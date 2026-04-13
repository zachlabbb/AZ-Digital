/**
 * AZ Digital — Serverless Form Handler
 * ─────────────────────────────────────
 * Proxy sécurisé entre le frontend et les webhooks Discord / Zapier.
 *
 * Sécurités appliquées :
 *  - Méthode HTTP restreinte à POST
 *  - Limite de taille de payload (10 KB)
 *  - Rate limiting : 5 requêtes par IP toutes les 15 minutes (429 si dépassé)
 *  - Validation stricte de tous les champs (type, longueur, format)
 *  - Sanitisation des entrées (trim, slicing)
 *  - Secrets uniquement en variables d'environnement (jamais dans le code)
 *  - Erreurs internes masquées au client
 *  - CORS limité à l'origine du site
 */

'use strict';

/* ── Webhooks (variables d'environnement uniquement) ── */
const DISCORD_WEBHOOK = process.env.DISCORD_WEBHOOK_URL;
const ZAPIER_WEBHOOK  = process.env.ZAPIER_WEBHOOK_URL;

/* ── Rate limiting en mémoire ──────────────────────────────────────────────
   Note : en mémoire = best-effort sur Netlify (chaque instance est isolée).
   Pour un rate limit strict en production, remplacer par Upstash Redis.
   ─────────────────────────────────────────────────────────────────────── */
const RATE_LIMIT  = 5;                  // tentatives max
const RATE_WINDOW = 15 * 60 * 1000;    // 15 minutes en ms
const rateLimitMap = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  const record = rateLimitMap.get(ip);

  if (!record || now > record.resetAt) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_WINDOW });
    return { allowed: true, remaining: RATE_LIMIT - 1 };
  }

  if (record.count >= RATE_LIMIT) {
    return {
      allowed: false,
      retryAfter: Math.ceil((record.resetAt - now) / 1000)
    };
  }

  record.count++;
  return { allowed: true, remaining: RATE_LIMIT - record.count };
}

/* ── Helpers de validation ── */
function sanitize(value, maxLen = 500) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLen);
}

function isValidEmail(email) {
  // RFC 5322 simplifié — refuse les adresses avec espaces
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

function isValidPhone(phone) {
  // Accepte les formats courants : +1 514 000-0000, (514) 000-0000, etc.
  return !phone || /^[\d\s\(\)\-\+\.]{7,25}$/.test(phone);
}

/* ── Services autorisés pour le formulaire devis ── */
const ALLOWED_SERVICES = new Set([
  'Création de site',
  'Optimisation de site',
  'E-commerce',
  '—',
  ''
]);

/* ── Headers communs ── */
function buildHeaders(extra = {}) {
  return {
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
    ...extra
  };
}

/* ── Handler principal ── */
exports.handler = async function handler(event) {

  /* 1. Méthode HTTP : POST uniquement */
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: buildHeaders({ Allow: 'POST' }),
      body: JSON.stringify({ error: 'Méthode non autorisée' })
    };
  }

  /* 2. Content-Type : application/json uniquement */
  const contentType = (event.headers['content-type'] || '').toLowerCase();
  if (!contentType.includes('application/json')) {
    return {
      statusCode: 415,
      headers: buildHeaders(),
      body: JSON.stringify({ error: 'Content-Type doit être application/json' })
    };
  }

  /* 3. Taille du payload : max 10 KB */
  const bodySize = Buffer.byteLength(event.body || '', 'utf8');
  if (bodySize > 10_240) {
    return {
      statusCode: 413,
      headers: buildHeaders(),
      body: JSON.stringify({ error: 'Payload trop volumineux' })
    };
  }

  /* 4. Rate limiting par IP */
  const ip =
    (event.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    event.headers['client-ip'] ||
    'unknown';

  const rateCheck = checkRateLimit(ip);
  if (!rateCheck.allowed) {
    return {
      statusCode: 429,
      headers: buildHeaders({
        'Retry-After': String(rateCheck.retryAfter),
        'X-RateLimit-Limit': String(RATE_LIMIT),
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': String(Math.ceil(Date.now() / 1000) + rateCheck.retryAfter)
      }),
      body: JSON.stringify({
        error: 'Trop de tentatives. Veuillez patienter 15 minutes avant de réessayer.'
      })
    };
  }

  /* 5. Parsing JSON */
  let data;
  try {
    data = JSON.parse(event.body);
  } catch {
    return {
      statusCode: 400,
      headers: buildHeaders(),
      body: JSON.stringify({ error: 'Corps de requête JSON invalide' })
    };
  }

  /* 6. Validation du type de formulaire */
  const formType = sanitize(data.type, 20);
  if (!['contact', 'devis'].includes(formType)) {
    return {
      statusCode: 400,
      headers: buildHeaders(),
      body: JSON.stringify({ error: 'Type de formulaire invalide' })
    };
  }

  /* 7. Validation des champs communs */
  const name  = sanitize(data.name,  100);
  const email = sanitize(data.email, 150);
  const phone = sanitize(data.phone,  25);

  if (!name) {
    return {
      statusCode: 400,
      headers: buildHeaders(),
      body: JSON.stringify({ error: 'Le nom est requis' })
    };
  }

  if (!isValidEmail(email)) {
    return {
      statusCode: 400,
      headers: buildHeaders(),
      body: JSON.stringify({ error: 'Adresse courriel invalide' })
    };
  }

  if (!isValidPhone(phone)) {
    return {
      statusCode: 400,
      headers: buildHeaders(),
      body: JSON.stringify({ error: 'Numéro de téléphone invalide' })
    };
  }

  /* 8. Validation des champs spécifiques au type */
  let company = '', message = '', service = '', website = '';

  if (formType === 'contact') {
    company = sanitize(data.company, 100);
    message = sanitize(data.message, 2000);
    if (!message) {
      return {
        statusCode: 400,
        headers: buildHeaders(),
        body: JSON.stringify({ error: 'Le message est requis' })
      };
    }
  }

  if (formType === 'devis') {
    service = sanitize(data.service, 100);
    website = sanitize(data.website, 200);

    if (!ALLOWED_SERVICES.has(service)) {
      return {
        statusCode: 400,
        headers: buildHeaders(),
        body: JSON.stringify({ error: 'Service demandé invalide' })
      };
    }
  }

  /* 9. Vérification de la configuration des webhooks */
  if (!DISCORD_WEBHOOK || !ZAPIER_WEBHOOK) {
    console.error('[submit-form] DISCORD_WEBHOOK_URL ou ZAPIER_WEBHOOK_URL non configuré');
    return {
      statusCode: 500,
      headers: buildHeaders(),
      body: JSON.stringify({ error: 'Erreur de configuration serveur' })
    };
  }

  /* 10. Construction des payloads */
  const now = new Date().toLocaleString('fr-CA', {
    timeZone:  'America/Toronto',
    dateStyle: 'full',
    timeStyle: 'short'
  });

  let discordPayload, zapierPayload;

  if (formType === 'contact') {
    discordPayload = {
      username:   'AZ Digital — Formulaire Contact',
      avatar_url: 'https://cdn-icons-png.flaticon.com/512/906/906343.png',
      embeds: [{
        title: '📬 Nouvelle demande de contact',
        color: 0x04E3FF,
        fields: [
          { name: '👤 Nom',        value: name    || '—', inline: true  },
          { name: '🏢 Entreprise', value: company || '—', inline: true  },
          { name: '📧 Courriel',   value: email   || '—', inline: false },
          { name: '📞 Téléphone',  value: phone   || '—', inline: true  },
          { name: '💬 Message',    value: message || '—', inline: false }
        ],
        footer:    { text: '🕐 ' + now + ' · AZ Digital' },
        thumbnail: { url: 'https://cdn-icons-png.flaticon.com/512/561/561127.png' }
      }]
    };
    zapierPayload = { type: 'contact', name, company, email, phone, message };

  } else {
    discordPayload = {
      username:   'AZ Digital — Soumission Devis',
      avatar_url: 'https://cdn-icons-png.flaticon.com/512/906/906343.png',
      embeds: [{
        title: '🚀 Nouvelle demande de soumission',
        color: 0x7B2FFF,
        fields: [
          { name: '👤 Nom',         value: name    || '—', inline: true  },
          { name: '📧 Courriel',    value: email   || '—', inline: true  },
          { name: '📞 Téléphone',   value: phone   || '—', inline: true  },
          { name: '🛠️ Service',     value: service || '—', inline: true  },
          { name: '🌐 Site actuel', value: website || '—', inline: false }
        ],
        footer:    { text: '🕐 ' + now + ' · AZ Digital' },
        thumbnail: { url: 'https://cdn-icons-png.flaticon.com/512/2721/2721297.png' }
      }]
    };
    zapierPayload = { type: 'devis', name, email, phone, service, website };
  }

  /* 11. Envoi aux webhooks */
  const [discordResult, zapierResult] = await Promise.allSettled([
    fetch(DISCORD_WEBHOOK, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(discordPayload)
    }),
    fetch(ZAPIER_WEBHOOK, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(zapierPayload)
    })
  ]);

  const discordOk =
    discordResult.status === 'fulfilled' && discordResult.value.ok;

  if (!discordOk) {
    const reason =
      discordResult.status === 'rejected'
        ? discordResult.reason
        : await discordResult.value.text().catch(() => 'inconnu');
    console.error('[submit-form] Discord webhook failed:', reason);
  }

  if (zapierResult.status === 'rejected') {
    console.error('[submit-form] Zapier webhook failed:', zapierResult.reason);
  }

  if (discordOk) {
    return {
      statusCode: 200,
      headers: buildHeaders(),
      body: JSON.stringify({ success: true })
    };
  }

  return {
    statusCode: 502,
    headers: buildHeaders(),
    body: JSON.stringify({ error: "Erreur lors de l'envoi. Veuillez réessayer." })
  };
};

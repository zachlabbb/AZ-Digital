/**
 * AZ Digital — Cloudflare Pages Function
 * Route : /api/submit-form
 *
 * Sécurités :
 *  - POST uniquement (405 sinon)
 *  - Payload max 10 KB (413 sinon)
 *  - Rate limiting : 5 tentatives par IP / 15 min (429 sinon)
 *  - Validation et sanitisation de tous les champs
 *  - Secrets en variables d'environnement Cloudflare (jamais dans le code)
 *  - Erreurs internes masquées au client
 */

/* ── Rate limiting en mémoire (best-effort) ── */
const RATE_LIMIT  = 5;
const RATE_WINDOW = 15 * 60 * 1000; // 15 min en ms
const rateMap     = new Map();

function checkRateLimit(ip) {
  const now    = Date.now();
  const record = rateMap.get(ip);

  if (!record || now > record.resetAt) {
    rateMap.set(ip, { count: 1, resetAt: now + RATE_WINDOW });
    return { allowed: true };
  }
  if (record.count >= RATE_LIMIT) {
    return { allowed: false, retryAfter: Math.ceil((record.resetAt - now) / 1000) };
  }
  record.count++;
  return { allowed: true };
}

/* ── Helpers ── */
function sanitize(value, maxLen) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLen);
}

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

function isValidPhone(phone) {
  return !phone || /^[\d\s()\-+.]{7,25}$/.test(phone);
}

const ALLOWED_SERVICES = new Set(['Création de site', 'Optimisation de site', 'E-commerce', '—', '']);

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'X-Content-Type-Options': 'nosniff',
      ...extraHeaders
    }
  });
}

/* ── Handler Cloudflare Pages ── */
export async function onRequestPost(context) {
  const { request, env } = context;

  /* 1. Content-Type */
  const ct = (request.headers.get('content-type') || '').toLowerCase();
  if (!ct.includes('application/json')) {
    return json({ error: 'Content-Type doit être application/json' }, 415);
  }

  /* 2. Taille du payload (max 10 KB) */
  const body = await request.text();
  if (body.length > 10_240) {
    return json({ error: 'Payload trop volumineux' }, 413);
  }

  /* 3. Rate limiting par IP */
  const ip = request.headers.get('cf-connecting-ip')
    || request.headers.get('x-forwarded-for')?.split(',')[0].trim()
    || 'unknown';

  const rate = checkRateLimit(ip);
  if (!rate.allowed) {
    return json(
      { error: 'Trop de tentatives. Veuillez patienter 15 minutes.' },
      429,
      { 'Retry-After': String(rate.retryAfter) }
    );
  }

  /* 4. Parse JSON */
  let data;
  try { data = JSON.parse(body); }
  catch { return json({ error: 'JSON invalide' }, 400); }

  /* 5. Type de formulaire */
  const formType = sanitize(data.type, 20);
  if (!['contact', 'devis'].includes(formType)) {
    return json({ error: 'Type de formulaire invalide' }, 400);
  }

  /* 6. Champs communs */
  const name  = sanitize(data.name,  100);
  const email = sanitize(data.email, 150);
  const phone = sanitize(data.phone,  25);

  if (!name)                 return json({ error: 'Le nom est requis' }, 400);
  if (!isValidEmail(email))  return json({ error: 'Adresse courriel invalide' }, 400);
  if (!isValidPhone(phone))  return json({ error: 'Numéro de téléphone invalide' }, 400);

  /* 7. Champs spécifiques */
  let company = '', message = '', service = '', website = '';

  if (formType === 'contact') {
    company = sanitize(data.company, 100);
    message = sanitize(data.message, 2000);
    if (!message) return json({ error: 'Le message est requis' }, 400);
  }

  if (formType === 'devis') {
    service = sanitize(data.service, 100);
    website = sanitize(data.website, 200);
    if (!ALLOWED_SERVICES.has(service)) return json({ error: 'Service invalide' }, 400);
  }

  /* 8. Vérification des secrets */
  const DISCORD_WEBHOOK = env.DISCORD_WEBHOOK_URL;
  const ZAPIER_WEBHOOK  = env.ZAPIER_WEBHOOK_URL;

  if (!DISCORD_WEBHOOK || !ZAPIER_WEBHOOK) {
    console.error('[submit-form] Variables d\'environnement manquantes');
    return json({ error: 'Erreur de configuration serveur' }, 500);
  }

  /* 9. Construction des payloads */
  const now = new Date().toLocaleString('fr-CA', {
    timeZone: 'America/Toronto', dateStyle: 'full', timeStyle: 'short'
  });

  let discordPayload, zapierPayload;

  if (formType === 'contact') {
    discordPayload = {
      username: 'AZ Digital — Formulaire Contact',
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
        footer: { text: '🕐 ' + now + ' · AZ Digital' },
        thumbnail: { url: 'https://cdn-icons-png.flaticon.com/512/561/561127.png' }
      }]
    };
    zapierPayload = { type: 'contact', name, company, email, phone, message };
  } else {
    discordPayload = {
      username: 'AZ Digital — Soumission Devis',
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
        footer: { text: '🕐 ' + now + ' · AZ Digital' },
        thumbnail: { url: 'https://cdn-icons-png.flaticon.com/512/2721/2721297.png' }
      }]
    };
    zapierPayload = { type: 'devis', name, email, phone, service, website };
  }

  /* 10. Envoi aux webhooks */
  const [discordRes, zapierRes] = await Promise.allSettled([
    fetch(DISCORD_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(discordPayload)
    }),
    fetch(ZAPIER_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(zapierPayload)
    })
  ]);

  const discordOk = discordRes.status === 'fulfilled' && discordRes.value.ok;

  if (!discordOk) {
    const reason = discordRes.status === 'rejected'
      ? discordRes.reason
      : await discordRes.value.text().catch(() => 'inconnu');
    console.error('[submit-form] Discord échoué :', reason);
  }

  if (zapierRes.status === 'rejected') {
    console.error('[submit-form] Zapier échoué :', zapierRes.reason);
  }

  if (discordOk) return json({ success: true });

  return json({ error: "Erreur lors de l'envoi. Veuillez réessayer." }, 502);
}

/* Toutes les autres méthodes → 405 */
export async function onRequest(context) {
  if (context.request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Allow': 'POST, OPTIONS',
        'Access-Control-Allow-Origin': 'https://azdigital.ca',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      }
    });
  }
  return new Response(JSON.stringify({ error: 'Méthode non autorisée' }), {
    status: 405,
    headers: { 'Allow': 'POST, OPTIONS', 'Content-Type': 'application/json' }
  });
}

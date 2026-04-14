/**
 * AZ Digital — Serverless Form Handler (Netlify)
 * ─────────────────────────────────────────────────────────────────────────────
 * Proxy sécurisé entre le frontend et Twilio SendGrid.
 * Aucune clé API n'est jamais exposée dans le frontend.
 *
 * Sécurités appliquées :
 *  ✓  Méthode HTTP restreinte à POST
 *  ✓  Content-Type : application/json obligatoire
 *  ✓  Taille du payload limitée à 10 KB (413 si dépassé)
 *  ✓  Rate limiting : 5 req / 15 min / IP (429 si dépassé)
 *  ✓  Validation stricte de tous les champs (type, longueur, format)
 *  ✓  Sanitisation des entrées (trim + slicing)
 *  ✓  Anti-spam léger (URLs excessives dans le message)
 *  ✓  Secrets en variables d'environnement uniquement
 *  ✓  Erreurs internes masquées au client
 */

'use strict';

/* ── Rate limiting en mémoire ──────────────────────────────────────────────
   Note : best-effort sur Netlify — chaque instance Lambda est isolée.
   Pour un rate limit strict multi-instance, utiliser Upstash Redis.
   ─────────────────────────────────────────────────────────────────────── */
const RATE_LIMIT   = 5;
const RATE_WINDOW  = 15 * 60 * 1000;  // 15 minutes en ms
const rateLimitMap = new Map();

function checkRateLimit(ip) {
  const now    = Date.now();
  const record = rateLimitMap.get(ip);

  if (!record || now > record.resetAt) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_WINDOW });
    return { allowed: true, remaining: RATE_LIMIT - 1 };
  }
  if (record.count >= RATE_LIMIT) {
    return { allowed: false, retryAfter: Math.ceil((record.resetAt - now) / 1000) };
  }
  record.count++;
  return { allowed: true, remaining: RATE_LIMIT - record.count };
}

/* ── Helpers de validation ─────────────────────────────────────────────── */
function sanitize(value, maxLen = 500) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLen);
}

function isValidEmail(email) {
  // RFC 5322 simplifié — refuse les adresses avec espaces ou sans domaine valide
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

function isValidPhone(phone) {
  // Formats acceptés : +1 514 000-0000, (514) 000-0000, etc.
  return !phone || /^[\d\s()\-+.]{7,25}$/.test(phone);
}

/* Anti-spam : refuse les messages contenant plus de 3 URLs */
function hasExcessiveUrls(text) {
  const matches = text.match(/https?:\/\/[^\s]+/gi);
  return matches !== null && matches.length > 3;
}

/* ── Services autorisés (liste blanche stricte) ─────────────────────────── */
const ALLOWED_SERVICES = new Set([
  'Création de site',
  'Optimisation de site',
  'E-commerce',
  '—',
  ''
]);

/* ── Headers de réponse communs ─────────────────────────────────────────── */
function buildHeaders(extra = {}) {
  return {
    'Content-Type':           'application/json',
    'X-Content-Type-Options': 'nosniff',
    ...extra
  };
}

/* ── Template email HTML (compatible tous clients mail) ──────────────────
   Utilise des tables et styles inline pour une compatibilité maximale
   avec Gmail, Outlook, Apple Mail, etc.
   ─────────────────────────────────────────────────────────────────────── */
function buildEmailHtml({ title, subtitle, badgeColor, rows, timestamp }) {
  const rowsHtml = rows
    .map(([label, value]) => `
      <tr>
        <td style="padding:0 0 10px 0;">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td style="background:#f9fafb;border-left:3px solid ${badgeColor};border-radius:0 6px 6px 0;padding:12px 16px;">
                <span style="display:block;font-size:11px;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:5px;">${escapeHtml(label)}</span>
                <span style="display:block;font-size:15px;color:#111827;line-height:1.5;word-break:break-word;">${value ? escapeHtml(value) : '<em style="color:#9ca3af;font-style:italic;">Non renseigné</em>'}</span>
              </td>
            </tr>
          </table>
        </td>
      </tr>`)
    .join('');

  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>${escapeHtml(title)}</title>
</head>
<body style="margin:0;padding:0;background-color:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
         style="background-color:#f3f4f6;padding:40px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="560" cellpadding="0" cellspacing="0"
               style="max-width:560px;width:100%;">

          <!-- En-tête dégradé AZ Digital -->
          <tr>
            <td style="background:linear-gradient(135deg,#7B2FFF 0%,#04E3FF 100%);
                       padding:30px 40px;border-radius:12px 12px 0 0;text-align:center;">
              <p style="margin:0;font-size:24px;font-weight:800;color:#ffffff;
                        letter-spacing:-0.5px;line-height:1;">AZ Digital</p>
              <p style="margin:8px 0 0;font-size:13px;color:rgba(255,255,255,0.82);
                        font-weight:400;">${escapeHtml(subtitle)}</p>
            </td>
          </tr>

          <!-- Corps du message -->
          <tr>
            <td style="background:#ffffff;padding:36px 40px;">

              <!-- Badge type formulaire -->
              <p style="display:inline-block;background:${badgeColor};color:#ffffff;
                        font-size:11px;font-weight:700;padding:4px 14px;
                        border-radius:20px;letter-spacing:0.05em;margin:0 0 20px;">
                ${escapeHtml(subtitle).toUpperCase()}
              </p>

              <!-- Titre -->
              <h1 style="margin:0 0 28px;font-size:19px;font-weight:700;
                         color:#111827;line-height:1.35;">${escapeHtml(title)}</h1>

              <!-- Champs du formulaire -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                ${rowsHtml}
              </table>

            </td>
          </tr>

          <!-- Pied de page -->
          <tr>
            <td style="background:#f9fafb;padding:18px 40px;
                       border-radius:0 0 12px 12px;border-top:1px solid #e5e7eb;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="font-size:12px;color:#9ca3af;">
                    Reçu le <strong style="color:#6b7280;">${escapeHtml(timestamp)}</strong>
                  </td>
                  <td align="right"
                      style="font-size:12px;color:#9ca3af;">azdigital.ca</td>
                </tr>
              </table>
            </td>
          </tr>

        </table>

        <!-- Note de confidentialité -->
        <p style="margin:16px 0 0;font-size:11px;color:#9ca3af;text-align:center;">
          Ce message est généré automatiquement — ne pas répondre directement.<br>
          Utilisez le bouton "Répondre" pour contacter le client.
        </p>

      </td>
    </tr>
  </table>
</body>
</html>`;
}

/* Échappe les caractères HTML pour éviter l'injection dans le template */
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#39;');
}

/* ── Template email texte brut (version de secours) ─────────────────────── */
function buildEmailText({ title, rows, timestamp }) {
  const divider = '─'.repeat(52);
  const fieldLines = rows.map(
    ([label, value]) => `${label.padEnd(18)}: ${value || '(non renseigné)'}`
  );
  return [
    'AZ DIGITAL — NOTIFICATION FORMULAIRE',
    divider,
    title,
    divider,
    '',
    ...fieldLines,
    '',
    divider,
    `Reçu le : ${timestamp}`,
    'Site     : azdigital.ca',
    divider
  ].join('\n');
}

/* ── Envoi via l'API Resend (REST natif, sans package npm) ──────────────
   Documentation : https://resend.com/docs/api-reference/emails/send-email
   ─────────────────────────────────────────────────────────────────────── */
async function sendViaResend({ apiKey, to, from, replyTo, subject, html, text }) {
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      from,                          // ex: "AZ Digital <notifications@azdigital.ca>"
      to:       to.split(',').map(e => e.trim()).filter(Boolean),  // supporte plusieurs destinataires
      reply_to: replyTo.email,       // répondre à l'email répond directement au client
      subject,
      html,
      text
    })
  });

  if (!response.ok) {
    // Ne jamais transmettre les détails de l'erreur Resend au client
    const errorBody = await response.text().catch(() => 'réponse illisible');
    throw new Error(`Resend HTTP ${response.status}: ${errorBody}`);
  }
}

/* ── Handler principal (Netlify Functions) ───────────────────────────────── */
exports.handler = async function handler(event) {

  /* 1. Méthode HTTP : POST uniquement */
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: buildHeaders({ Allow: 'POST' }),
      body: JSON.stringify({ error: 'Méthode non autorisée' })
    };
  }

  /* 2. Content-Type : application/json obligatoire */
  const contentType = (event.headers['content-type'] || '').toLowerCase();
  if (!contentType.includes('application/json')) {
    return {
      statusCode: 415,
      headers: buildHeaders(),
      body: JSON.stringify({ error: 'Content-Type doit être application/json' })
    };
  }

  /* 3. Taille du payload : maximum 10 KB */
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
        'Retry-After':           String(rateCheck.retryAfter),
        'X-RateLimit-Limit':     String(RATE_LIMIT),
        'X-RateLimit-Remaining': '0'
      }),
      body: JSON.stringify({
        error: 'Trop de tentatives. Veuillez patienter 15 minutes avant de réessayer.'
      })
    };
  }

  /* 5. Parsing du JSON */
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
    /* Anti-spam : trop d'URLs dans le message = probable spam */
    if (hasExcessiveUrls(message)) {
      return {
        statusCode: 400,
        headers: buildHeaders(),
        body: JSON.stringify({ error: 'Message non autorisé' })
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

  /* 9. Vérification de la configuration Resend */
  const RESEND_API_KEY = process.env.RESEND_API_KEY;
  const EMAIL_TO       = process.env.EMAIL_TO;
  const EMAIL_FROM     = process.env.EMAIL_FROM;

  if (!RESEND_API_KEY || !EMAIL_TO || !EMAIL_FROM) {
    console.error('[submit-form] Variables d\'environnement Resend manquantes (RESEND_API_KEY, EMAIL_TO, EMAIL_FROM)');
    return {
      statusCode: 500,
      headers: buildHeaders(),
      body: JSON.stringify({ error: 'Erreur de configuration serveur' })
    };
  }

  /* 10. Construction du contenu de l'email */
  const timestamp = new Date().toLocaleString('fr-CA', {
    timeZone:  'America/Toronto',
    dateStyle: 'full',
    timeStyle: 'short'
  });

  let emailSubject, emailRows, badgeColor, title, subtitle;

  if (formType === 'contact') {
    subtitle     = 'Formulaire de contact';
    title        = `Nouvelle demande de contact — ${name}`;
    badgeColor   = '#04E3FF';
    emailSubject = `Nouvelle demande de contact — ${name}`;
    emailRows    = [
      ['Nom',        name],
      ['Entreprise', company],
      ['Courriel',   email],
      ['Téléphone',  phone],
      ['Message',    message]
    ];
  } else {
    subtitle     = 'Soumission de devis';
    title        = `Nouvelle demande de devis — ${name}`;
    badgeColor   = '#7B2FFF';
    emailSubject = `Nouvelle demande de devis — ${name}`;
    emailRows    = [
      ['Nom',         name],
      ['Courriel',    email],
      ['Téléphone',   phone],
      ['Service',     service],
      ['Site actuel', website]
    ];
  }

  const htmlBody = buildEmailHtml({
    title, subtitle, badgeColor,
    rows: emailRows,
    timestamp
  });

  const textBody = buildEmailText({
    title,
    rows: emailRows,
    timestamp
  });

  /* 11. Envoi via Resend */
  try {
    await sendViaResend({
      apiKey:  RESEND_API_KEY,
      to:      EMAIL_TO,
      from:    EMAIL_FROM,        // doit être vérifié dans SendGrid (Sender Identity)
      replyTo: { email, name },   // répondre à l'email répondra directement au client
      subject: emailSubject,
      html:    htmlBody,
      text:    textBody
    });

    return {
      statusCode: 200,
      headers: buildHeaders(),
      body: JSON.stringify({ success: true })
    };

  } catch (err) {
    // Loguer l'erreur complète côté serveur, mais ne jamais l'exposer au client
    console.error('[submit-form] Erreur SendGrid :', err.message);
    return {
      statusCode: 502,
      headers: buildHeaders(),
      body: JSON.stringify({ error: "Erreur lors de l'envoi. Veuillez réessayer." })
    };
  }
};

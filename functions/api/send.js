export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const data = await request.json();
    const { type, name, email, phone } = data;

    const now = new Date().toLocaleString('fr-CA', {
      timeZone: 'America/Toronto',
      dateStyle: 'full',
      timeStyle: 'short'
    });

    let discordPayload;

    if (type === 'contact') {
      const { company, message } = data;
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
    } else if (type === 'devis') {
      const { service, website } = data;
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
    } else {
      return new Response(JSON.stringify({ ok: false, error: 'Type invalide' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const [discordRes] = await Promise.all([
      fetch(env.DISCORD_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(discordPayload)
      }),
      fetch(env.ZAPIER_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      })
    ]);

    return new Response(JSON.stringify({ ok: discordRes.ok }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch {
    return new Response(JSON.stringify({ ok: false }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

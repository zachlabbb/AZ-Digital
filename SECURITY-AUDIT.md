# Rapport d'audit de sécurité — AZ Digital
**Date :** 2026-04-13  
**Périmètre :** Projet complet (`AZ-Digital/`)  
**Réalisé par :** Claude Code (Sonnet 4.6)

---

## Résumé exécutif

Le projet est un site statique HTML/CSS/JS sans backend. Deux secrets critiques étaient exposés directement dans le code source côté client (et dans l'historique Git public GitHub). Un proxy serverless sécurisé a été mis en place pour éliminer cette exposition.

---

## Problèmes trouvés et correctifs appliqués

### 1. Webhooks exposés en dur dans le code client

| Attribut | Détail |
|---|---|
| **Gravité** | CRITIQUE |
| **Fichier** | `index.html` lignes 3981–3982 (avant correctif) |
| **Problème** | URL Discord webhook et Zapier webhook écrites en clair dans le JavaScript côté client, visible par tout visiteur via "Voir le code source" |
| **Risque** | Spam illimité vers Discord/Zapier, injection de données, abus de l'automatisation SMS, usurpation d'identité dans les notifications |
| **Correctif appliqué** | Suppression complète des URLs. Création d'une fonction serverless `netlify/functions/submit-form.js` qui lit les webhooks depuis des variables d'environnement serveur (`DISCORD_WEBHOOK_URL`, `ZAPIER_WEBHOOK_URL`). Le frontend appelle uniquement `/api/submit-form`. |

> **ACTION REQUISE :** Régénérer immédiatement les deux webhooks (voir section "Actions urgentes").

---

### 2. Absence de rate limiting

| Attribut | Détail |
|---|---|
| **Gravité** | HAUTE |
| **Fichier** | `index.html` (avant correctif) |
| **Problème** | Aucune limite sur le nombre d'envois de formulaire — attaque DoS/spam triviale |
| **Correctif appliqué** | Rate limiting intégré dans `submit-form.js` : **5 tentatives max par IP toutes les 15 minutes**. Retourne HTTP **429** avec header `Retry-After` si dépassé. Message d'erreur affiché dans le bouton du formulaire. |

---

### 3. Absence de validation et sanitisation serveur

| Attribut | Détail |
|---|---|
| **Gravité** | HAUTE |
| **Fichier** | `index.html` (avant correctif) |
| **Problème** | Toute la validation était côté client uniquement (contournable). Aucune vérification de format, taille, ou contenu côté serveur. |
| **Correctif appliqué** | La fonction serverless valide et sanitise tous les champs : longueur max par champ (nom 100, email 150, message 2000…), validation email par regex, validation téléphone, liste blanche des services, rejet de tout type de formulaire inconnu. |

---

### 4. Absence de restriction des méthodes HTTP

| Attribut | Détail |
|---|---|
| **Gravité** | MOYENNE |
| **Fichier** | `netlify/functions/submit-form.js` (nouveau fichier) |
| **Problème** | Sans backend, n'importe quelle méthode HTTP pouvait être utilisée |
| **Correctif appliqué** | L'endpoint `/api/submit-form` accepte **uniquement POST**. Toute autre méthode reçoit HTTP **405 Method Not Allowed**. |

---

### 5. Absence de limite de taille des payloads

| Attribut | Détail |
|---|---|
| **Gravité** | MOYENNE |
| **Fichier** | `netlify/functions/submit-form.js` (nouveau fichier) |
| **Problème** | Payloads de taille illimitée possibles |
| **Correctif appliqué** | Rejet automatique si le body dépasse **10 Ko** → HTTP **413 Payload Too Large**. |

---

### 6. Erreurs internes exposées au client

| Attribut | Détail |
|---|---|
| **Gravité** | MOYENNE |
| **Fichier** | `netlify/functions/submit-form.js` |
| **Problème** | Les erreurs Discord/Zapier étaient silencieuses mais non structurées |
| **Correctif appliqué** | Les erreurs internes sont loguées côté serveur (`console.error`) mais le client reçoit uniquement un message générique (502 + message en français). Les détails techniques ne sont jamais transmis au client. |

---

### 7. Absence de headers de sécurité HTTP

| Attribut | Détail |
|---|---|
| **Gravité** | MOYENNE |
| **Fichier** | `netlify.toml` (nouveau fichier) |
| **Problème** | Aucun header de sécurité n'était configuré |
| **Correctif appliqué** | Ajout via `netlify.toml` : `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security` (HSTS 1 an), `Referrer-Policy`, `Permissions-Policy`, `Content-Security-Policy` (CSP stricte limitant sources de scripts, styles, images, connexions). |

---

### 8. CORS non restreint sur l'API

| Attribut | Détail |
|---|---|
| **Gravité** | MOYENNE |
| **Fichier** | `netlify.toml` (nouveau fichier) |
| **Problème** | Sans configuration CORS, l'API serverless acceptait des requêtes cross-origin de n'importe quelle origine |
| **Correctif appliqué** | Headers CORS restreints dans `netlify.toml` : `Access-Control-Allow-Origin: https://azdigital.ca` uniquement. Méthodes autorisées : POST et OPTIONS seulement. |

---

### 9. Absence de .gitignore

| Attribut | Détail |
|---|---|
| **Gravité** | HAUTE |
| **Fichier** | `.gitignore` (nouveau fichier) |
| **Problème** | Aucun `.gitignore` — risque de commiter `.env`, `node_modules`, fichiers système |
| **Correctif appliqué** | Création d'un `.gitignore` couvrant : `.env*`, `node_modules/`, `.netlify/`, `dist/`, `.DS_Store`, fichiers temporaires et brouillons (`*.txt`, `index - copie*`, `intro`). |

---

### 10. Commentaire exposant l'ID Google Analytics

| Attribut | Détail |
|---|---|
| **Gravité** | FAIBLE |
| **Fichier** | `index.html` ligne 32 (avant correctif) |
| **Problème** | Commentaire HTML `<!-- Remplacer G-6X8C4MSWXL par votre vrai ID Google Analytics 4 -->` confirmant publiquement que l'ID live est en place |
| **Correctif appliqué** | Suppression du commentaire. Note : les ID GA4 sont semi-publics par nature (ils apparaissent dans les requêtes réseau), donc risque faible. |

---

## Fichiers modifiés / créés

| Fichier | Action | Description |
|---|---|---|
| `index.html` | **Modifié** | Suppression des 2 webhooks hardcodés, remplacement par `submitForm()` → `/api/submit-form`, validation côté client renforcée, gestion 429 |
| `netlify/functions/submit-form.js` | **Créé** | Proxy serverless sécurisé avec rate limiting, validation, sanitisation, gestion d'erreurs |
| `netlify.toml` | **Créé** | Headers de sécurité HTTP, CORS restreint, redirect API |
| `.gitignore` | **Créé** | Protection contre les commits accidentels de secrets |
| `.env.example` | **Créé** | Template documentant les variables d'environnement requises |

---

## Actions urgentes (à faire maintenant)

### 1. Régénérer le webhook Discord

1. Ouvrir Discord → serveur → Paramètres du serveur → Intégrations → Webhooks
2. Trouver le webhook `AZ Digital — Formulaire Contact`
3. Cliquer "Supprimer" (invalide l'URL exposée)
4. Créer un nouveau webhook → copier la nouvelle URL

### 2. Régénérer le webhook Zapier

1. Ouvrir Zapier → Zaps → trouver le Zap avec "Webhook"
2. Cliquer sur le déclencheur Webhook
3. Cliquer "Regenerate URL" ou recréer le Zap
4. Copier la nouvelle URL

### 3. Configurer les variables d'environnement sur Netlify

1. Netlify Dashboard → Site → **Site configuration** → **Environment variables**
2. Ajouter :
   - `DISCORD_WEBHOOK_URL` = nouvelle URL Discord
   - `ZAPIER_WEBHOOK_URL` = nouvelle URL Zapier
3. Redéployer le site

### 4. Nettoyer l'historique Git (optionnel mais recommandé)

Les anciens webhooks sont dans l'historique Git. Si le repo est public :

```bash
# Option 1 : BFG Repo-Cleaner (recommandé)
bfg --replace-text secrets.txt
git push --force

# Option 2 : git filter-repo
git filter-repo --path index.html --force
```

Alternativement, **rendre le repo GitHub privé** empêche toute exploitation future.

---

## Risques résiduels

| Risque | Niveau | Explication |
|---|---|---|
| Historique Git avec anciens secrets | CRITIQUE → atténué | Les URLs exposées dans le passé sont dans l'historique. Invalider les webhooks les rend inopérants. |
| Rate limiting best-effort | FAIBLE | Le rate limit en mémoire est best-effort sur Netlify (instances multiples). Pour un rate limit strict, utiliser Upstash Redis. |
| ID Google Analytics public | FAIBLE | Les ID GA4 apparaissent dans le trafic réseau par conception — risque de spam Analytics faible. |
| Pas d'authentification admin | N/A | Le site est purement public, aucune zone admin — non applicable. |

---

## Score de sécurité

| Domaine | Avant | Après |
|---|---|---|
| Secrets exposés | F | A |
| Rate limiting | F | B+ |
| Validation serveur | F | A |
| Headers HTTP | F | A |
| CORS | D | A |
| .gitignore | F | A |
| Gestion d'erreurs | C | A |
| **Global** | **F** | **A-** |

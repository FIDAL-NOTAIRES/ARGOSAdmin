// ============================================================
// ARGOSAdmin — api/admin.js — lots 1, 2 et 3 (31/10/2026)
// Fonction serveur UNIQUE à actions (limite Vercel Hobby : 12 fonctions).
// Appel : POST /api/admin  { action: "...", ...paramètres }
// En-tête : Authorization: Bearer <jeton>  (sauf action "connexion")
//
// Variables d'environnement Vercel attendues :
//   DATABASE_URL        chaîne Neon (rôle matrice_owner, projet neon-fuchsia-pillow)
//   ARGOSADMIN_MDP      mot de passe administrateur provisoire (JFD seul) — remplacé au lot 5
//   ARGOSADMIN_SECRET   (facultatif) secret de signature des jetons de session ;
//                       à défaut, dérivé du mot de passe
// Lot 2 — stockage des pièces sur Scaleway Object Storage (deux comptes) :
//   SCW_PRINCIPAL_CLE / SCW_PRINCIPAL_SECRET / SCW_PRINCIPAL_BUCKET
//   SCW_SAUVEGARDE_CLE / SCW_SAUVEGARDE_SECRET / SCW_SAUVEGARDE_BUCKET
//   SCW_REGION (défaut fr-par) ; l'hôte est <bucket>.s3.<région>.scw.cloud
// Le navigateur envoie le fichier DIRECTEMENT vers les deux buckets avec des
// adresses signées (limite Vercel de 4,5 Mo contournée) ; le serveur ne voit
// jamais le fichier, il ne fait que signer, enregistrer et supprimer.
// Lot 3 — utilisateurs, liens d'activation, création des sites clients sur Vercel :
//   VERCEL_JETON        clé d'accès Vercel (espace réservé à ARGOS)      VERCEL_EQUIPE (facultatif) identifiant de l'équipe Vercel
//   ARGOS_DEPOT         dépôt GitHub des sites clients, défaut FIDAL-NOTAIRES/ARGOS
//   ARGOS_LECTEUR_URL   chaîne Neon du rôle argos_lecteur (recopiée dans chaque site client)
//   SCW_LECTURE_CLE / SCW_LECTURE_SECRET   clé Scaleway LECTURE SEULE (recopiée dans chaque site client)
//   BREVO_CLE / BREVO_EXPEDITEUR / ADMIN_COURRIEL   facultatifs (courriels) ; sans Brevo, les liens sont affichés à l'écran
// 05/11/2026 — CARNET (annuaire commun des associés et collaborateurs) :
//   CARNET_URL  adresse de CARNET (https://carnet-ivory.vercel.app)   CARNET_CLE  clé de lecture donnée par CARNET à ARGOSAdmin
// ============================================================

const { neon } = require("@neondatabase/serverless");
const crypto = require("crypto");

const DUREE_SESSION_MS = 8 * 60 * 60 * 1000; // 8 heures
const DELAI_SONDAGE_MS = 5000;
const JOURS_ALERTE_ECHEANCE = 15;                     // LOT 4 : bandeau rouge et courriel à quinze jours de l'échéance

// ---------- utilitaires ----------
function sha256(texte) {
  return crypto.createHash("sha256").update(String(texte), "utf8").digest();
}
function secretSignature() {
  const base = process.env.ARGOSADMIN_SECRET || process.env.ARGOSADMIN_MDP || "";
  return sha256("argosadmin:" + base);
}
function egalSur(a, b) {
  const ha = sha256(a);
  const hb = sha256(b);
  return crypto.timingSafeEqual(ha, hb);
}
function signer(expiration) {
  return crypto.createHmac("sha256", secretSignature()).update(String(expiration)).digest("base64url");
}
function creerJeton() {
  const expiration = Date.now() + DUREE_SESSION_MS;
  return `${expiration}.${signer(expiration)}`;
}
function jetonValide(jeton) {
  if (!jeton || typeof jeton !== "string") return false;
  const [exp, sig] = jeton.split(".");
  if (!exp || !sig) return false;
  const expiration = Number(exp);
  if (!Number.isFinite(expiration) || expiration < Date.now()) return false;
  const attendu = signer(expiration);
  if (attendu.length !== sig.length) return false;
  return crypto.timingSafeEqual(Buffer.from(attendu), Buffer.from(sig));
}
function nouvelleCleLecture() {
  return "argos_" + crypto.randomBytes(24).toString("base64url");
}
function texte(v, max = 300) {
  return String(v == null ? "" : v).trim().slice(0, max);
}
function entier(v, defaut) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : defaut;
}
function lireCorps(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string" && req.body) {
    try { return JSON.parse(req.body); } catch { return {}; }
  }
  return {};
}

// ---------- sondage d'un site client (voyant vert / rouge) ----------
async function sonderUrl(url) {
  if (!url) return { ok: null, message: "Adresse du site non renseignée" };
  const controleur = new AbortController();
  const minuteur = setTimeout(() => controleur.abort(), DELAI_SONDAGE_MS);
  try {
    // Lot 2 : le site client exposera /api/sante qui vérifie la lecture de la base.
    // Lot 1 : on se contente de vérifier que le site répond.
    const cible = url.replace(/\/+$/, "") + "/api/sante";
    let rep = await fetch(cible, { method: "GET", signal: controleur.signal });
    if (rep.status === 404) {
      rep = await fetch(url, { method: "GET", signal: controleur.signal });
    }
    clearTimeout(minuteur);
    if (rep.ok) { let version = null; try { version = (await rep.json()).version || null; } catch {} return { ok: true, message: "", version }; }
    return { ok: false, message: `Réponse ${rep.status}` };
  } catch (e) {
    clearTimeout(minuteur);
    return { ok: false, message: e.name === "AbortError" ? "Pas de réponse en 5 secondes" : (e.message || "Erreur réseau") };
  }
}

// ---------- Scaleway Object Storage (signature AWS v4, sans bibliothèque) ----------
const RUBRIQUES = {
  1: "Désignation et plans", 2: "Origine de propriété", 3: "Exploitation",
  4: "Fiscalité", 5: "Diagnostics", 6: "Organisation de l'immeuble / de la zone",
  7: "Servitudes",   // ajoutée le 02/11 : s'affiche entre Titre et Exploitation (l'ordre d'affichage ne suit pas le numéro)
};
function compteScaleway(nom) {
  const p = nom === "sauvegarde" ? "SCW_SAUVEGARDE" : "SCW_PRINCIPAL";
  const cle = process.env[p + "_CLE"], secret = process.env[p + "_SECRET"], bucket = process.env[p + "_BUCKET"];
  if (!cle || !secret || !bucket) return null;
  const region = process.env.SCW_REGION || "fr-par";
  return { nom, cle, secret, bucket, region, hote: `${bucket}.s3.${region}.scw.cloud` };
}
function stockagePret() {
  return !!(compteScaleway("principal") && compteScaleway("sauvegarde"));
}
function hex(b) { return Buffer.from(b).toString("hex"); }
function hmac(cle, msg) { return crypto.createHmac("sha256", cle).update(msg, "utf8").digest(); }
function sha256hex(msg) { return crypto.createHash("sha256").update(msg, "utf8").digest("hex"); }
function encoderCle(cle) {
  return cle.split("/").map((seg) => encodeURIComponent(seg).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase())).join("/");
}
function dateAmz(d = new Date()) {
  const iso = d.toISOString().replace(/[:-]|\.\d{3}/g, "");
  return { amz: iso, jour: iso.slice(0, 8) };
}
function cleSignature(compte, jour) {
  const kDate = hmac("AWS4" + compte.secret, jour);
  const kRegion = hmac(kDate, compte.region);
  const kService = hmac(kRegion, "s3");
  return hmac(kService, "aws4_request");
}
// Adresse signée (valable `expire` secondes) pour un PUT ou un GET depuis le navigateur
function adresseSignee(compte, methode, cle, expire) {
  const { amz, jour } = dateAmz();
  const portee = `${jour}/${compte.region}/s3/aws4_request`;
  const uri = "/" + encoderCle(cle);
  const params = {
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
    "X-Amz-Credential": `${compte.cle}/${portee}`,
    "X-Amz-Date": amz,
    "X-Amz-Expires": String(expire),
    "X-Amz-SignedHeaders": "host",
  };
  const requete = Object.keys(params).sort().map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`).join("&");
  const canonique = [methode, uri, requete, `host:${compte.hote}\n`, "host", "UNSIGNED-PAYLOAD"].join("\n");
  const aSigner = ["AWS4-HMAC-SHA256", amz, portee, sha256hex(canonique)].join("\n");
  const signature = hex(hmac(cleSignature(compte, jour), aSigner));
  return `https://${compte.hote}${uri}?${requete}&X-Amz-Signature=${signature}`;
}
// Requête signée exécutée par le serveur (vérification, suppression, réglage du bucket)
// options : { requete: "cors", corps: "<xml>", type: "application/xml" }
async function requeteSignee(compte, methode, cle, options = {}) {
  const { amz, jour } = dateAmz();
  const portee = `${jour}/${compte.region}/s3/aws4_request`;
  const uri = "/" + encoderCle(cle || "");
  const requete = options.requete ? `${encodeURIComponent(options.requete)}=` : "";
  const entetes = { host: compte.hote, "x-amz-content-sha256": "UNSIGNED-PAYLOAD", "x-amz-date": amz };
  if (options.corps !== undefined) {
    entetes["content-md5"] = crypto.createHash("md5").update(options.corps, "utf8").digest("base64");
    entetes["content-type"] = options.type || "application/xml";
  }
  const noms = Object.keys(entetes).sort();
  const canonique = [methode, uri, requete, noms.map((n) => `${n}:${entetes[n]}\n`).join(""), noms.join(";"), "UNSIGNED-PAYLOAD"].join("\n");
  const aSigner = ["AWS4-HMAC-SHA256", amz, portee, sha256hex(canonique)].join("\n");
  const signature = hex(hmac(cleSignature(compte, jour), aSigner));
  const envoi = { "x-amz-content-sha256": "UNSIGNED-PAYLOAD", "x-amz-date": amz,
    Authorization: `AWS4-HMAC-SHA256 Credential=${compte.cle}/${portee}, SignedHeaders=${noms.join(";")}, Signature=${signature}` };
  if (entetes["content-md5"]) { envoi["Content-MD5"] = entetes["content-md5"]; envoi["Content-Type"] = entetes["content-type"]; }
  return fetch(`https://${compte.hote}${uri}${requete ? "?" + requete.replace(/=$/, "") : ""}`, {
    method: methode, headers: envoi, body: options.corps,
  });
}
// Intitulé lisible proposé à partir du nom de fichier : sans extension, soulignés et tirets en espaces, majuscule initiale
function intituleDepuisNom(nom) {
  let s = String(nom || "").replace(/\.[A-Za-z0-9]{1,5}$/, "").replace(/[_\-]+/g, " ").replace(/\s+/g, " ").trim();
  if (!s) s = "Pièce";
  return (s.charAt(0).toUpperCase() + s.slice(1)).slice(0, 200);
}
function nomFichierPropre(nom) {
  return String(nom || "piece").normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 120) || "piece";
}


// ---------- LOT 3 : liens d'activation, courriels, géocodage, Vercel ----------
const DUREE_LIEN_MS = 48 * 60 * 60 * 1000; // 48 heures
async function lienActivation(sql, utilisateurId, objet, req) {
  const u = await sql`SELECT u.id, u.courriel, u.civilite, u.nom, u.prenom, c.nom AS client_nom, c.url_site, c.id AS client_id FROM argos_utilisateur u JOIN argos_client c ON c.id = u.client_id WHERE u.id = ${utilisateurId}`;
  if (!u.length) throw new Error("Utilisateur introuvable.");
  const jeton = crypto.randomBytes(24).toString("base64url");
  await sql`UPDATE argos_utilisateur SET activation_hachage = ${crypto.createHash("sha256").update(jeton).digest("hex")}, activation_expire = ${new Date(Date.now() + DUREE_LIEN_MS)}, activation_objet = ${objet}, maj_le = NOW() WHERE id = ${utilisateurId}`;
  const base = (u[0].url_site || "").replace(/\/+$/, "");
  if (!base) throw new Error("L'adresse du site client n'est pas renseignée : créez d'abord le site (bouton « Déployer le site »).");
  const route = objet === "activation" ? "activation" : objet;
  const url = `${base}/#${route}/${jeton}`;
  const objetMail = objet === "activation" ? "Votre accès au portail du patrimoine foncier FIDAL Notaires" : objet === "code" ? "Portail FIDAL Notaires : nouveau code secret" : "Portail FIDAL Notaires : nouveau mot de passe";
  // 05/11 : texte validé phrase par phrase le 04/11 (civilité, élision « d' » devant une voyelle)
  const appel = u[0].civilite === "Madame" ? "Chère Madame," : u[0].civilite === "Monsieur" ? "Cher Monsieur," : "Madame, Monsieur,";
  const deClient = (/^[aeiouyàâäéèêëîïôöùûü]/i.test(String(u[0].client_nom || "").trim()) ? "d'" : "de ") + u[0].client_nom;
  const corps = objet === "activation"
    ? `${appel}\n\nVous êtes invité${u[0].civilite === "Madame" ? "e" : ""} par FIDAL NOTAIRES à accéder au portail du patrimoine foncier ${deClient}.\n\nPour activer votre accès, merci de cliquer sur le lien ci-dessous. Ce lien restera valable pour une durée de quarante-huit heures et il est à usage unique. Il vous permettra de paramétrer votre compte en choisissant un mot de passe et un code secret à six chiffres, pour valider votre identité avec votre téléphone.\n\n${url}\n\nSi ce lien a expiré ou ne fonctionne plus, n'hésitez pas à revenir vers nous pour que nous vous adressions un nouveau lien d'accès.\n\nNous restons à votre disposition pour toute demande,\n\nVotre bien dévoué,\n\nFIDAL Notaires`
    : `Bonjour ${u[0].prenom} ${u[0].nom},\n\nÀ votre demande, FIDAL Notaires vous invite à choisir ${objet === "code" ? "un nouveau code secret" : "un nouveau mot de passe"} pour le portail du patrimoine foncier de votre société.\n\nLe lien ci-dessous est valable quarante-huit heures et ne sert qu'une fois :\n${url}\n\nFIDAL Notaires`;
  const envoye = await envoyerCourriel(sql, u[0].client_id, [u[0].courriel], objetMail, corps);
  return { url, envoye };
}
async function envoyerCourriel(sql, clientId, destinataires, objet, corps) {
  const cle = process.env.BREVO_CLE, exp = process.env.BREVO_EXPEDITEUR;
  if (!cle || !exp) return false;
  try {
    const r = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST", headers: { "api-key": cle, "Content-Type": "application/json" },
      body: JSON.stringify({ sender: { email: exp, name: "FIDAL Notaires" }, to: destinataires.map((e) => ({ email: e })), subject: objet, textContent: corps }),
    });
    return r.ok;
  } catch (e) { console.error("[brevo]", e.message); return false; }
}
// Coordonnées d'un site par la Base Adresse Nationale (gratuite) ; silencieux en cas d'échec
async function geocoder(adresse, code_postal, commune) {
  const q = [adresse, code_postal, commune].filter(Boolean).join(" ");
  if (!q.trim()) return null;
  try {
    const r = await fetch(`https://api-adresse.data.gouv.fr/search/?limit=1&q=${encodeURIComponent(q)}${code_postal ? "&postcode=" + encodeURIComponent(code_postal) : ""}`);
    const g = await r.json();
    const f = g.features && g.features[0];
    return f ? { lat: f.geometry.coordinates[1], lng: f.geometry.coordinates[0] } : null;
  } catch { return null; }
}
// Vercel : crée le projet du client, branché sur le dépôt ARGOS, avec ses variables, puis lance le déploiement
async function vercelApi(chemin, methode, corps) {
  const jeton = process.env.VERCEL_JETON;
  if (!jeton) throw new Error("Variable VERCEL_JETON absente sur ARGOSAdmin.");
  const equipe = process.env.VERCEL_EQUIPE ? (chemin.includes("?") ? "&" : "?") + "teamId=" + encodeURIComponent(process.env.VERCEL_EQUIPE) : "";
  const r = await fetch("https://api.vercel.com" + chemin + equipe, { method: methode || "GET", headers: { Authorization: "Bearer " + jeton, "Content-Type": "application/json" }, body: corps ? JSON.stringify(corps) : undefined });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error("Vercel : " + ((d.error && (d.error.message || d.error.code)) || r.status));
  return d;
}
async function deployerSiteClient(client, code) {
  for (const v of ["ARGOS_LECTEUR_URL", "SCW_LECTURE_CLE", "SCW_LECTURE_SECRET"]) if (!process.env[v]) throw new Error(`Variable ${v} absente sur ARGOSAdmin (nécessaire pour créer un site client).`);
  const depot = process.env.ARGOS_DEPOT || "FIDAL-NOTAIRES/ARGOS";
  const nomProjet = `argos-${code}`;
  const variables = {
    ARGOS_DATABASE_URL: process.env.ARGOS_LECTEUR_URL,
    ARGOS_CLE_LECTURE: client.cle_lecture,
    ARGOS_SECRET: crypto.randomBytes(32).toString("base64url"),
    SCW_LECTURE_CLE: process.env.SCW_LECTURE_CLE,
    SCW_LECTURE_SECRET: process.env.SCW_LECTURE_SECRET,
    SCW_REGION: process.env.SCW_REGION || "fr-par",
  };
  if (process.env.BREVO_CLE) variables.BREVO_CLE = process.env.BREVO_CLE;
  if (process.env.BREVO_EXPEDITEUR) variables.BREVO_EXPEDITEUR = process.env.BREVO_EXPEDITEUR;
  if (process.env.ADMIN_COURRIEL) variables.ADMIN_COURRIEL = process.env.ADMIN_COURRIEL;
  const env = Object.entries(variables).map(([key, value]) => ({ key, value, target: ["production", "preview"], type: "encrypted" }));
  let projet;
  if (client.vercel_projet) {
    projet = await vercelApi(`/v9/projects/${encodeURIComponent(client.vercel_projet)}`);
    for (const e of env) await vercelApi(`/v10/projects/${projet.id}/env?upsert=true`, "POST", e);
  } else {
    projet = await vercelApi("/v10/projects", "POST", { name: nomProjet, framework: null, gitRepository: { type: "github", repo: depot }, environmentVariables: env });
  }
  const repoId = projet.link && projet.link.repoId;
  const deploiement = await vercelApi("/v13/deployments", "POST", { name: projet.name, project: projet.id, target: "production",
    gitSource: repoId ? { type: "github", repoId, ref: "main" } : { type: "github", org: depot.split("/")[0], repo: depot.split("/")[1], ref: "main" } });
  return { projet: projet.id, nom: projet.name, url: `https://${projet.name}.vercel.app`, deploiement: deploiement.id, etat: deploiement.readyState || deploiement.status };
}

// ---------- LOT 4 — RONDE DE NUIT (tâche planifiée Vercel, api/ronde.js) ----------
// Pour chaque client : le portail répond (/api/sante lit la base avec le rôle lecteur), la base répond ici aussi,
// et la pièce la plus récente du client est ouverte (HEAD) dans les DEUX stockages. Échec → voyant rouge avec motif,
// événement, courriel du matin à l'étude. Rien si tout passe. Puis rappel des échéances techniques à quinze jours.
async function ronde(sql, options = {}) {
  const debut = Date.now();
  const clients = await sql`SELECT c.id, c.nom, c.url_site FROM argos_client c WHERE c.actif = TRUE ORDER BY c.nom`;
  const principal = compteScaleway("principal"), sauvegarde = compteScaleway("sauvegarde");
  const rapport = [];
  for (const c of clients) {
    const defauts = [];
    const s = await sonderUrl(c.url_site);
    if (s.ok === false) defauts.push(`portail injoignable (${s.message})`);
    else if (s.ok === null) defauts.push("adresse du portail non renseignée");
    let piece = null;
    try {
      const r = await sql`SELECT p.id, p.cle_objet, p.copie_principale, p.copie_sauvegarde, COALESCE(NULLIF(p.intitule,''), p.nom_fichier) AS intitule
                          FROM argos_piece p JOIN argos_site s ON s.id = p.site_id WHERE s.client_id = ${c.id} ORDER BY p.depose_le DESC LIMIT 1`;
      piece = r[0] || null;
    } catch (e) { defauts.push(`base de données : ${e.message}`); }
    if (piece) {
      if (!principal) defauts.push("stockage principal non configuré");
      else { try { const r = await requeteSignee(principal, "HEAD", piece.cle_objet); if (!r.ok) defauts.push(`pièce test absente du stockage principal (réponse ${r.status})`); } catch (e) { defauts.push(`stockage principal : ${e.message}`); } }
      if (!sauvegarde) defauts.push("stockage de sauvegarde non configuré");
      else if (piece.copie_sauvegarde) { try { const r = await requeteSignee(sauvegarde, "HEAD", piece.cle_objet); if (!r.ok) defauts.push(`pièce test absente du stockage de sauvegarde (réponse ${r.status})`); } catch (e) { defauts.push(`stockage de sauvegarde : ${e.message}`); } }
    }
    const ok = defauts.length === 0;
    const detail = ok ? "" : defauts.join(" ; ");
    if (ok) {
      await sql`INSERT INTO argos_sondage (client_id, dernier_ok, message, version, ronde_le, ronde_ok, ronde_detail) VALUES (${c.id}, NOW(), '', ${s.version || null}, NOW(), TRUE, '')
                ON CONFLICT (client_id) DO UPDATE SET dernier_ok = NOW(), message = '', version = COALESCE(${s.version || null}, argos_sondage.version), ronde_le = NOW(), ronde_ok = TRUE, ronde_detail = ''`;
    } else {
      await sql`INSERT INTO argos_sondage (client_id, dernier_echec, message, ronde_le, ronde_ok, ronde_detail) VALUES (${c.id}, NOW(), ${"Ronde de nuit : " + detail}, NOW(), FALSE, ${detail})
                ON CONFLICT (client_id) DO UPDATE SET dernier_echec = NOW(), message = ${"Ronde de nuit : " + detail}, ronde_le = NOW(), ronde_ok = FALSE, ronde_detail = ${detail}`;
      await sql`INSERT INTO argos_evenement (client_id, nature, detail) VALUES (${c.id}, 'ronde_echec', ${detail})`;
    }
    rapport.push({ id: c.id, nom: c.nom, ok, detail, piece: piece ? piece.intitule : null });
  }
  const echecs = rapport.filter((x) => !x.ok);
  if (echecs.length && process.env.ADMIN_COURRIEL) {
    await envoyerCourriel(sql, null, [process.env.ADMIN_COURRIEL], `[ARGOSAdmin] Ronde de nuit : ${echecs.length} vérification${echecs.length > 1 ? "s" : ""} en échec`,
      `Bonjour,\n\nLa ronde de nuit d'ARGOS a relevé ${echecs.length} défaut${echecs.length > 1 ? "s" : ""} :\n\n` +
      echecs.map((x) => `— ${x.nom} : ${x.detail}`).join("\n") + `\n\nLes voyants correspondants sont passés au rouge dans ARGOSAdmin.\n\nFIDAL Notaires — ARGOSAdmin`);
  }
  // échéances techniques : rappel unique à quinze jours
  const aRappeler = await sql`SELECT id, libelle, echeance, note FROM argos_echeance WHERE fait_le IS NULL AND rappel_envoye_le IS NULL AND echeance <= CURRENT_DATE + ${JOURS_ALERTE_ECHEANCE}::int ORDER BY echeance`;
  let rappels = 0;
  if (aRappeler.length && process.env.ADMIN_COURRIEL) {
    const envoye = await envoyerCourriel(sql, null, [process.env.ADMIN_COURRIEL], `[ARGOSAdmin] Échéance technique dans quinze jours ou moins`,
      `Bonjour,\n\nÉchéance${aRappeler.length > 1 ? "s" : ""} technique${aRappeler.length > 1 ? "s" : ""} à traiter :\n\n` +
      aRappeler.map((x) => `— ${x.libelle} : ${new Date(x.echeance).toLocaleDateString("fr-FR")}${x.note ? " (" + x.note + ")" : ""}`).join("\n") +
      `\n\nLe bandeau rouge d'ARGOSAdmin les signale jusqu'à ce qu'elles soient marquées faites.\n\nFIDAL Notaires — ARGOSAdmin`);
    if (envoye) { for (const x of aRappeler) await sql`UPDATE argos_echeance SET rappel_envoye_le = NOW() WHERE id = ${x.id}`; rappels = aRappeler.length; }
  }
  return { ok: echecs.length === 0, clients: rapport, echeances_rappelees: rappels, duree_ms: Date.now() - debut, manuel: !!options.manuel };
}

// ---------- CARNET : lecture des associés et collaborateurs actifs (serveur à serveur, clé propre à ARGOSAdmin) ----------
let carnetCache = null, carnetCacheLe = 0;
async function lireCarnet() {
  if (carnetCache && Date.now() - carnetCacheLe < 60000) return carnetCache;
  const url = String(process.env.CARNET_URL || "").replace(/\/+$/, ""), cle = process.env.CARNET_CLE || "";
  if (!url || !cle) throw new Error("CARNET n'est pas branché : variables CARNET_URL et CARNET_CLE absentes sur ARGOSAdmin.");
  const r = await fetch(url + "/api/carnet?action=lecture", { headers: { "X-Carnet-Cle": cle } });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error("CARNET répond : " + (d.erreur || r.status));
  carnetCache = d.personnes || []; carnetCacheLe = Date.now();
  return carnetCache;
}
function listeIds(v) {
  const t = Array.isArray(v) ? v : [];
  return [...new Set(t.map((x) => parseInt(x, 10)).filter((x) => Number.isFinite(x) && x > 0))];
}

// ---------- actions ----------
const actions = {
  // 05/11 : personnes de CARNET proposées dans la fiche client (actifs seulement)
  async carnet_personnes() {
    const liste = await lireCarnet();
    const court = (p) => ({ id: p.id, civilite: p.civilite, prenom: p.prenom, nom: p.nom, courriel: p.courriel, fonction: p.fonction, service: p.service,
      telephone: p.telephone, portable: p.portable, site: p.site ? p.site.nom : "", site_cp: p.site ? p.site.code_postal : "", site_adresse: p.site ? p.site.adresse : "",
      sans_signature: !!p.sans_signature });
    return { associes: liste.filter((p) => p.categorie === "associe").map(court), collaborateurs: liste.filter((p) => p.categorie === "collaborateur").map(court) };
  },

  async clients(sql) {
    const lignes = await sql`
      SELECT c.id, c.nom, c.actif, c.url_site, c.seuil_jour, c.seuil_vitesse, c.seuil_heure_alerte, c.seuil_heure_pause, c.cree_le,
             (SELECT COUNT(*)::int FROM argos_site s WHERE s.client_id = c.id) AS nb_sites,
             (SELECT COUNT(*)::int FROM argos_utilisateur u WHERE u.client_id = c.id) AS nb_utilisateurs,
             (SELECT MAX(p.depose_le) FROM argos_piece p JOIN argos_site s ON s.id = p.site_id WHERE s.client_id = c.id) AS dernier_depot,
             c.code, c.vercel_projet, so.dernier_ok, so.dernier_echec, so.message AS sondage_message, so.version,
             (SELECT COUNT(*)::int FROM argos_evenement e WHERE e.client_id = c.id AND e.traite = FALSE) AS nb_evenements,
             (SELECT COUNT(*)::int FROM argos_site s WHERE s.client_id = c.id AND s.cadastre_alerte_le IS NOT NULL) AS nb_sites_alerte,
             c.associes, c.collaborateurs
      FROM argos_client c
      LEFT JOIN argos_sondage so ON so.client_id = c.id
      ORDER BY c.nom`;
    const alertes = await sql`SELECT COUNT(*)::int AS n FROM argos_evenement WHERE traite = FALSE`;
    // LOT 4 — échéances techniques à quinze jours ou moins (bandeau rouge)
    const echeances = await sql`SELECT id, libelle, echeance FROM argos_echeance WHERE fait_le IS NULL AND echeance <= CURRENT_DATE + ${JOURS_ALERTE_ECHEANCE}::int ORDER BY echeance`;
    return { clients: lignes, alertes: alertes[0].n, echeances };
  },

  // 05/11 : sondage d'un seul client (après création ou déploiement de son site)
  async client_sonder(sql, p) {
    const id = entier(p.id, 0);
    const c = await sql`SELECT id, url_site FROM argos_client WHERE id = ${id}`;
    if (!c.length) throw new Error("Client introuvable.");
    const r = await sonderUrl(c[0].url_site);
    if (r.ok === true) await sql`INSERT INTO argos_sondage (client_id, dernier_ok, message, version) VALUES (${id}, NOW(), '', ${r.version || null})
                                 ON CONFLICT (client_id) DO UPDATE SET dernier_ok = NOW(), message = '', version = ${r.version || null}`;
    else if (r.ok === false) await sql`INSERT INTO argos_sondage (client_id, dernier_echec, message) VALUES (${id}, NOW(), ${r.message})
                                       ON CONFLICT (client_id) DO UPDATE SET dernier_echec = NOW(), message = ${r.message}`;
    return { ok: r.ok, message: r.message };
  },

  async sonder(sql) {
    const clients = await sql`SELECT id, url_site FROM argos_client ORDER BY id`;
    const resultats = await Promise.all(clients.map(async (c) => {
      const r = await sonderUrl(c.url_site);
      if (r.ok === true) {
        await sql`INSERT INTO argos_sondage (client_id, dernier_ok, message, version) VALUES (${c.id}, NOW(), '', ${r.version || null})
                  ON CONFLICT (client_id) DO UPDATE SET dernier_ok = NOW(), message = '', version = ${r.version || null}`;
      } else if (r.ok === false) {
        await sql`INSERT INTO argos_sondage (client_id, dernier_echec, message) VALUES (${c.id}, NOW(), ${r.message})
                  ON CONFLICT (client_id) DO UPDATE SET dernier_echec = NOW(), message = ${r.message}`;
      }
      return { id: c.id, ok: r.ok, message: r.message };
    }));
    return { sondages: resultats };
  },

  async client_creer(sql, p) {
    const nom = texte(p.nom, 120);
    if (!nom) throw new Error("Le nom du client est obligatoire.");
    const url_site = texte(p.url_site, 300);
    const code = texte(p.code, 40).toLowerCase().replace(/[^a-z0-9-]/g, "") || null;
    const cle = nouvelleCleLecture();
    const ins = await sql`
      INSERT INTO argos_client (nom, cle_lecture, url_site, code)
      VALUES (${nom}, ${cle}, ${url_site}, ${code})
      RETURNING id`;
    const id = ins[0].id;
    await sql`INSERT INTO argos_sondage (client_id) VALUES (${id}) ON CONFLICT DO NOTHING`;
    let deploiement = null;
    if (p.deployer && code) {
      try { deploiement = await deployerSiteClient({ id, nom, code, cle_lecture: cle, url_site: "" }, code);
            await sql`UPDATE argos_client SET url_site = ${deploiement.url}, vercel_projet = ${deploiement.projet} WHERE id = ${id}`; }
      catch (e) { deploiement = { erreur: e.message }; }
    }
    return { id, cle_lecture: cle, deploiement };
  },

  async client(sql, p) {
    const id = entier(p.id, 0);
    const c = await sql`
      SELECT c.*, so.dernier_ok, so.dernier_echec, so.message AS sondage_message,
             (SELECT x.motif FROM argos_suspension x WHERE x.client_id = c.id AND x.utilisateur_id IS NULL AND x.action = 'suspension' ORDER BY x.cree_le DESC LIMIT 1) AS suspension_motif
      FROM argos_client c LEFT JOIN argos_sondage so ON so.client_id = c.id
      WHERE c.id = ${id}`;
    if (!c.length) throw new Error("Client introuvable.");
    const sites = await sql`
      SELECT s.id, s.nom, s.adresse, s.commune, s.code_postal, s.cree_le, s.maj_le,
             (SELECT COUNT(*)::int FROM argos_piece p WHERE p.site_id = s.id) AS nb_pieces,
             (SELECT MAX(p.depose_le) FROM argos_piece p WHERE p.site_id = s.id) AS dernier_depot
      FROM argos_site s WHERE s.client_id = ${id}
      ORDER BY s.commune, s.nom, s.id`;
    const utilisateurs = await sql`
      SELECT u.id, u.courriel, u.civilite, u.nom, u.prenom, u.role, u.active, u.bloque_jusqua, u.cree_le, u.active_le, u.conditions_le, u.suspendu_le,
             u.coupe_par_responsable, u.pause_volume,
             (SELECT x.motif FROM argos_suspension x WHERE x.utilisateur_id = u.id AND x.action = 'suspension' ORDER BY x.cree_le DESC LIMIT 1) AS suspension_motif, u.derniere_connexion, u.activation_expire, u.activation_objet,
             (SELECT COALESCE(json_agg(json_build_object('id', a.id, 'libelle', a.libelle, 'type', a.type, 'vu_le', a.vu_le) ORDER BY a.vu_le DESC), '[]'::json) FROM argos_appareil a WHERE a.utilisateur_id = u.id) AS appareils,
             (SELECT COALESCE(json_agg(e.site_id), '[]'::json) FROM argos_site_exclu e WHERE e.utilisateur_id = u.id) AS sites_exclus
      FROM argos_utilisateur u WHERE u.client_id = ${id} ORDER BY u.nom, u.prenom`;
    const evenements = await sql`SELECT id, nature, detail, cree_le FROM argos_evenement WHERE client_id = ${id} AND traite = FALSE ORDER BY cree_le DESC LIMIT 50`;
    const connexions = await sql`
      SELECT cx.id, cx.horodatage, cx.resultat, cx.detail, cx.courriel AS courriel_saisi, cx.adresse_ip,
             u.nom AS utilisateur_nom, u.prenom AS utilisateur_prenom, u.courriel AS utilisateur_courriel,
             a.libelle AS appareil,
             (SELECT COUNT(*)::int FROM argos_telechargement t
               WHERE t.utilisateur_id = cx.utilisateur_id
                 AND t.horodatage >= cx.horodatage
                 AND t.horodatage < cx.horodatage + INTERVAL '12 hours') AS telechargements
      FROM argos_connexion cx
      LEFT JOIN argos_utilisateur u ON u.id = cx.utilisateur_id
      LEFT JOIN argos_appareil a ON a.id = cx.appareil_id
      WHERE cx.client_id = ${id}
      ORDER BY cx.horodatage DESC LIMIT 100`;
    return { client: c[0], sites, utilisateurs, connexions, evenements, vercel_pret: !!(process.env.VERCEL_JETON && process.env.ARGOS_LECTEUR_URL) };
  },

  async client_modifier(sql, p) {
    const id = entier(p.id, 0);
    const nom = texte(p.nom, 120);
    if (!nom) throw new Error("Le nom du client est obligatoire.");
    const url_site = texte(p.url_site, 300);
    const seuil_heure_alerte = Math.max(1, entier(p.seuil_heure_alerte, 20));
    const seuil_heure_pause = Math.max(seuil_heure_alerte + 1, entier(p.seuil_heure_pause, 50));
    const seuil_jour = Math.max(seuil_heure_pause, entier(p.seuil_jour, 100));
    const code = texte(p.code, 40).toLowerCase().replace(/[^a-z0-9-]/g, "") || null;
    // 05/11 : au moins un associé rattaché (il est alerté en cas de difficulté) ; collaborateurs facultatifs ; identifiants CARNET
    const associes = listeIds(p.associes), collaborateurs = listeIds(p.collaborateurs);
    if (!associes.length) throw new Error("Rattachez au moins un associé au client : c'est lui qui sera alerté en cas de difficulté.");
    await sql`
      UPDATE argos_client
      SET nom = ${nom}, url_site = ${url_site}, code = ${code}, seuil_heure_alerte = ${seuil_heure_alerte}, seuil_heure_pause = ${seuil_heure_pause}, seuil_jour = ${seuil_jour},
          associes = ${JSON.stringify(associes)}::jsonb, collaborateurs = ${JSON.stringify(collaborateurs)}::jsonb, maj_le = NOW()
      WHERE id = ${id}`;
    // 05/11 : coordonnées du premier associé, lues dans CARNET, recopiées pour le portail (boutons « Demander un rappel » et « remise en service »)
    try {
      const a = (await lireCarnet()).find((x) => x.id === associes[0]);
      if (a && a.courriel) await sql`UPDATE argos_client SET contact_associe = ${JSON.stringify({ prenom: a.prenom || "", nom: a.nom || "", courriel: a.courriel })}::jsonb WHERE id = ${id}`;
    } catch (e) { console.error("[carnet] contact associé", e.message); }
    return { ok: true };
  },

  async client_suspendre(sql, p) {
    const id = entier(p.id, 0);
    const actif = !!p.actif;
    // 05/11 : motif OBLIGATOIRE à la suspension, conservé dans argos_suspension (table non lue par les sites clients)
    const motif = texte(p.motif, 500);
    if (!actif && !motif) throw new Error("Le motif de la suspension est obligatoire.");
    await sql`INSERT INTO argos_suspension (client_id, action, motif) VALUES (${id}, ${actif ? "retablissement" : "suspension"}, ${actif ? null : motif})`;
    await sql`
      UPDATE argos_client
      SET actif = ${actif}, suspendu_le = ${actif ? null : new Date()}, maj_le = NOW()
      WHERE id = ${id}`;
    return { ok: true, actif };
  },

  async client_cle_regenerer(sql, p) {
    const id = entier(p.id, 0);
    const cle = nouvelleCleLecture();
    await sql`UPDATE argos_client SET cle_lecture = ${cle}, maj_le = NOW() WHERE id = ${id}`;
    return { cle_lecture: cle };
  },

  async site_creer(sql, p) {
    const client_id = entier(p.client_id, 0);
    const nom = texte(p.nom, 160);
    const adresse = texte(p.adresse, 300);
    const commune = texte(p.commune, 120);
    const code_postal = texte(p.code_postal, 10);
    const geo = await geocoder(adresse, code_postal, commune);
    const ins = await sql`
      INSERT INTO argos_site (client_id, nom, adresse, commune, code_postal, lat, lng)
      VALUES (${client_id}, ${nom}, ${adresse}, ${commune}, ${code_postal}, ${geo ? geo.lat : null}, ${geo ? geo.lng : null})
      RETURNING id`;
    return { id: ins[0].id, geolocalise: !!geo };
  },

  async site_supprimer(sql, p) {
    const id = entier(p.id, 0);
    const n = await sql`SELECT COUNT(*)::int AS n FROM argos_piece WHERE site_id = ${id}`;
    if (n[0].n > 0) throw new Error("Ce site contient des pièces : supprimez-les d'abord (lot 2).");
    await sql`DELETE FROM argos_site WHERE id = ${id}`;
    return { ok: true };
  },
  // ===== LOT 2 — fiche site et pièces =====
  async site(sql, p) {
    const id = entier(p.id, 0);
    const s = await sql`
      SELECT s.*, c.nom AS client_nom, c.id AS client_id
      FROM argos_site s JOIN argos_client c ON c.id = s.client_id WHERE s.id = ${id}`;
    if (!s.length) throw new Error("Site introuvable.");
    const pieces = await sql`
      SELECT id, rubrique, nom_fichier, COALESCE(NULLIF(intitule, ''), nom_fichier) AS intitule, type_mime, taille, empreinte, copie_principale, copie_sauvegarde, sauvegarde_le, depose_le, est_plan
      FROM argos_piece WHERE site_id = ${id} ORDER BY rubrique, depose_le DESC`;
    return { site: s[0], pieces, rubriques: RUBRIQUES, stockage_pret: stockagePret() };
  },

  // Rubrique « Organisation de l'immeuble / de la zone » : case à cocher par site pour l'afficher au client même sans document
  async site_organisation(sql, p) {
    const id = entier(p.id, 0);
    await sql`UPDATE argos_site SET organisation_visible = ${!!p.visible}, maj_le = NOW() WHERE id = ${id}`;
    return { ok: true };
  },

  async site_modifier(sql, p) {
    const id = entier(p.id, 0);
    const references_ = {
      cadastre: texte(p.cadastre, 4000),
      surface: texte(p.surface, 60),
      titre: texte(p.titre, 300),
      // acte du titre de propriété : date et notaire, facultatifs
      acte_date: /^\d{4}-\d{2}-\d{2}$/.test(String(p.acte_date || "")) ? String(p.acte_date) : "",
      notaire: texte(p.notaire, 120),
      // date d'entrée dans le patrimoine (AAAA-MM-JJ), reprise dans les caractéristiques de la fiche de synthèse
      entree: /^\d{4}-\d{2}-\d{2}$/.test(String(p.entree || "")) ? String(p.entree) : "",
    };
    const fiche = { designation: texte(p.designation, 4000), nature: texte(p.nature, 80) };
    const geo = await geocoder(texte(p.adresse, 300), texte(p.code_postal, 10), texte(p.commune, 120));
    const avant = await sql`SELECT references_, commune, code_postal FROM argos_site WHERE id = ${id}`;
    const refsChangees = !avant.length || (avant[0].references_ || {}).cadastre !== references_.cadastre
      || avant[0].commune !== texte(p.commune, 120) || avant[0].code_postal !== texte(p.code_postal, 10);
    await sql`
      UPDATE argos_site
      SET nom = ${texte(p.nom, 160)}, adresse = ${texte(p.adresse, 300)},
          code_postal = ${texte(p.code_postal, 10)}, commune = ${texte(p.commune, 120)},
          references_ = ${JSON.stringify(references_)}::jsonb, fiche = ${JSON.stringify(fiche)}::jsonb,
          lat = COALESCE(${geo ? geo.lat : null}, lat), lng = COALESCE(${geo ? geo.lng : null}, lng),
          maj_le = NOW()
      WHERE id = ${id}`;
    // Références cadastrales ou commune modifiées : l'alerte cadastrale tombe (le prochain contrôle repartira de zéro) et le code INSEE sera relu
    if (refsChangees) await sql`UPDATE argos_site SET cadastre_alerte_le = NULL, cadastre_alerte_detail = NULL, insee = NULL WHERE id = ${id}`;
    return { ok: true, geolocalise: !!geo, alerte_levee: refsChangees };
  },

  // Lever l'alerte cadastrale à la main (après vérification), sans toucher aux références
  async cadastre_lever_alerte(sql, p) {
    const id = entier(p.id, 0);
    await sql`UPDATE argos_site SET cadastre_alerte_le = NULL, cadastre_alerte_detail = NULL WHERE id = ${id}`;
    return { ok: true };
  },

  // Étape 1 du dépôt : le serveur réserve la clé et signe deux adresses d'envoi (principal + sauvegarde)
  async piece_preparer(sql, p) {
    if (!stockagePret()) throw new Error("Stockage Scaleway non configuré (variables SCW_* absentes sur Vercel).");
    const site_id = entier(p.site_id, 0);
    const rubrique = entier(p.rubrique, 0);
    if (!RUBRIQUES[rubrique]) throw new Error("Rubrique inconnue.");
    const s = await sql`SELECT id, client_id FROM argos_site WHERE id = ${site_id}`;
    if (!s.length) throw new Error("Site introuvable.");
    // Doublon : même empreinte SHA-256 déjà déposée pour ce site (toutes rubriques), sauf si l'écran force le dépôt
    const empreinte = texte(p.empreinte, 64);
    if (empreinte && !p.forcer) {
      const d = await sql`
        SELECT id, rubrique, nom_fichier, COALESCE(NULLIF(intitule, ''), nom_fichier) AS intitule, depose_le
        FROM argos_piece WHERE site_id = ${site_id} AND empreinte = ${empreinte} ORDER BY depose_le DESC LIMIT 1`;
      if (d.length) return { doublon: { id: d[0].id, rubrique: d[0].rubrique, libelle_rubrique: RUBRIQUES[d[0].rubrique], intitule: d[0].intitule, depose_le: d[0].depose_le } };
    }
    const nom = nomFichierPropre(p.nom_fichier);
    const cle = `client-${s[0].client_id}/site-${site_id}/rubrique-${rubrique}/${Date.now()}-${nom}`;
    const principal = compteScaleway("principal"), sauvegarde = compteScaleway("sauvegarde");
    return {
      cle_objet: cle,
      envoi_principal: adresseSignee(principal, "PUT", cle, 900),
      envoi_sauvegarde: adresseSignee(sauvegarde, "PUT", cle, 900),
      bucket_principal: principal.bucket,
      bucket_sauvegarde: sauvegarde.bucket,
    };
  },

  // Étape 2 : le navigateur a envoyé le fichier ; on vérifie la présence dans les deux comptes et on enregistre
  async piece_enregistrer(sql, p) {
    // Plan du site (produit dans PAINT par l'étude) : un seul par site, l'ancien est retiré des deux stockages
    if (p.est_plan) {
      const anciens = await sql`SELECT id, cle_objet FROM argos_piece WHERE site_id = ${entier(p.site_id, 0)} AND est_plan = TRUE`;
      const principal = compteScaleway("principal"), sauvegarde = compteScaleway("sauvegarde");
      for (const a of anciens) {
        await Promise.allSettled([principal ? requeteSignee(principal, "DELETE", a.cle_objet) : null, sauvegarde ? requeteSignee(sauvegarde, "DELETE", a.cle_objet) : null]);
        await sql`DELETE FROM argos_piece WHERE id = ${a.id}`;
      }
    }
    const site_id = entier(p.site_id, 0);
    const rubrique = entier(p.rubrique, 0);
    const cle = texte(p.cle_objet, 600);
    if (!cle.startsWith(`client-`) || !cle.includes(`/site-${site_id}/rubrique-${rubrique}/`)) throw new Error("Clé d'objet incohérente.");
    const principal = compteScaleway("principal"), sauvegarde = compteScaleway("sauvegarde");
    const [rp, rs] = await Promise.all([requeteSignee(principal, "HEAD", cle), requeteSignee(sauvegarde, "HEAD", cle)]);
    const okP = rp.ok, okS = rs.ok;
    if (!okP) throw new Error("Le fichier n'est pas arrivé dans le compte principal (réponse " + rp.status + ").");
    const ins = await sql`
      INSERT INTO argos_piece (site_id, rubrique, nom_fichier, intitule, type_mime, taille, empreinte, cle_objet,
                               bucket_principal, bucket_sauvegarde, copie_principale, copie_sauvegarde, sauvegarde_le, est_plan)
      VALUES (${site_id}, ${rubrique}, ${texte(p.nom_fichier, 255)}, ${texte(p.intitule, 200) || (p.est_plan ? "Plan du site" : intituleDepuisNom(p.nom_fichier))}, ${texte(p.type_mime, 120) || "application/pdf"},
              ${entier(p.taille, 0)}, ${texte(p.empreinte, 64)}, ${cle},
              ${principal.bucket}, ${sauvegarde.bucket}, ${okP}, ${okS}, ${okS ? new Date() : null}, ${!!p.est_plan})
      RETURNING id`;
    await sql`UPDATE argos_site SET maj_le = NOW() WHERE id = ${site_id}`;
    if (!okS) {
      const site = await sql`SELECT client_id FROM argos_site WHERE id = ${site_id}`;
      await sql`INSERT INTO argos_evenement (client_id, nature, detail)
                VALUES (${site[0].client_id}, 'sauvegarde_echec', ${"Copie de sauvegarde absente pour " + cle})`;
    }
    return { id: ins[0].id, copie_sauvegarde: okS };
  },

  // Modification de l'intitulé affiché au client (le nom de fichier d'origine est conservé)
  async piece_intituler(sql, p) {
    const id = entier(p.id, 0);
    const r = await sql`SELECT site_id, nom_fichier FROM argos_piece WHERE id = ${id}`;
    if (!r.length) throw new Error("Pièce introuvable.");
    const intitule = texte(p.intitule, 200) || intituleDepuisNom(r[0].nom_fichier);
    await sql`UPDATE argos_piece SET intitule = ${intitule} WHERE id = ${id}`;
    await sql`UPDATE argos_site SET maj_le = NOW() WHERE id = ${r[0].site_id}`;
    return { ok: true, intitule };
  },

  // Adresse de lecture signée (5 minutes) pour ouvrir une pièce depuis ARGOSAdmin
  async piece_lien(sql, p) {
    const id = entier(p.id, 0);
    const r = await sql`SELECT cle_objet, copie_principale, copie_sauvegarde, nom_fichier FROM argos_piece WHERE id = ${id}`;
    if (!r.length) throw new Error("Pièce introuvable.");
    const compte = r[0].copie_principale ? compteScaleway("principal") : compteScaleway("sauvegarde");
    if (!compte) throw new Error("Stockage non configuré.");
    return { url: adresseSignee(compte, "GET", r[0].cle_objet, 300), nom_fichier: r[0].nom_fichier };
  },

  // Suppression dans les deux comptes puis en base
  async piece_supprimer(sql, p) {
    const id = entier(p.id, 0);
    const r = await sql`SELECT cle_objet, site_id FROM argos_piece WHERE id = ${id}`;
    if (!r.length) throw new Error("Pièce introuvable.");
    const principal = compteScaleway("principal"), sauvegarde = compteScaleway("sauvegarde");
    const resultats = await Promise.allSettled([
      principal ? requeteSignee(principal, "DELETE", r[0].cle_objet) : Promise.reject(new Error("principal absent")),
      sauvegarde ? requeteSignee(sauvegarde, "DELETE", r[0].cle_objet) : Promise.reject(new Error("sauvegarde absente")),
    ]);
    const echecs = resultats.filter((x) => x.status === "rejected" || (x.value && !x.value.ok && x.value.status !== 404));
    if (echecs.length) throw new Error("Suppression incomplète côté stockage ; la pièce reste enregistrée. Réessayez.");
    await sql`DELETE FROM argos_piece WHERE id = ${id}`;
    await sql`UPDATE argos_site SET maj_le = NOW() WHERE id = ${r[0].site_id}`;
    return { ok: true };
  },

  // Pose la règle CORS sur les deux buckets pour autoriser l'envoi direct depuis ARGOSAdmin
  async stockage_configurer(sql, p, req) {
    if (!stockagePret()) throw new Error("Variables SCW_* absentes sur Vercel.");
    const origine = texte(p.origine, 200) || `https://${req.headers["x-forwarded-host"] || req.headers.host}`;
    const xml = `<?xml version="1.0" encoding="UTF-8"?><CORSConfiguration><CORSRule>` +
      `<AllowedOrigin>${origine}</AllowedOrigin><AllowedMethod>PUT</AllowedMethod><AllowedMethod>GET</AllowedMethod>` +
      `<AllowedMethod>HEAD</AllowedMethod><AllowedHeader>*</AllowedHeader><ExposeHeader>ETag</ExposeHeader><MaxAgeSeconds>3000</MaxAgeSeconds>` +
      `</CORSRule></CORSConfiguration>`;
    const resultats = {};
    for (const nom of ["principal", "sauvegarde"]) {
      const compte = compteScaleway(nom);
      const r = await requeteSignee(compte, "PUT", "", { requete: "cors", corps: xml });
      resultats[nom] = r.ok ? "ok" : `${r.status} ${(await r.text()).slice(0, 200)}`;
      resultats[nom + "_bucket"] = compte.bucket;
    }
    return { origine, resultats };
  },

  // Statut de l'autorisation de dépôt (règle CORS présente pour cette adresse, sur chacun des deux comptes) : alimente l'interrupteur vert / rouge
  async stockage_statut(sql, p, req) {
    if (!stockagePret()) return { pret: false, ok: false, comptes: {} };
    const origine = texte(p.origine, 200) || `https://${req.headers["x-forwarded-host"] || req.headers.host}`;
    const comptes = {};
    for (const nom of ["principal", "sauvegarde"]) {
      const compte = compteScaleway(nom);
      try {
        const r = await requeteSignee(compte, "GET", "", { requete: "cors" });
        const x = r.ok ? await r.text() : "";
        comptes[nom] = { ok: r.ok && x.includes(`<AllowedOrigin>${origine}</AllowedOrigin>`), statut: r.status };
      } catch (e) { comptes[nom] = { ok: false, statut: 0, detail: e.message }; }
    }
    return { pret: true, origine, comptes, ok: Object.values(comptes).every((c) => c.ok) };
  },

  // Contrôle de l'état du stockage pour l'écran (sans exposer les clés)
  async stockage_etat() {
    const principal = compteScaleway("principal"), sauvegarde = compteScaleway("sauvegarde");
    return {
      principal: principal ? { bucket: principal.bucket, region: principal.region } : null,
      sauvegarde: sauvegarde ? { bucket: sauvegarde.bucket, region: sauvegarde.region } : null,
    };
  },

  // ===== LOT 3 — utilisateurs, activation, appareils, droits, journal, création de client (31/10/2026) =====
  async utilisateur_creer(sql, p, req) {
    const client_id = entier(p.client_id, 0);
    const nom = texte(p.nom, 80), prenom = texte(p.prenom, 80), courriel = texte(p.courriel, 200).toLowerCase();
    if (!nom || !prenom || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(courriel)) throw new Error("Nom, prénom et courriel valide sont obligatoires.");
    const role = p.responsable ? "responsable" : "lecture";
    const civilite = ["Monsieur", "Madame"].includes(p.civilite) ? p.civilite : null;
    const ins = await sql`INSERT INTO argos_utilisateur (client_id, courriel, civilite, nom, prenom, role, active)
                          VALUES (${client_id}, ${courriel}, ${civilite}, ${nom}, ${prenom}, ${role}, FALSE) RETURNING id`;
    const id = ins[0].id;
    const exclus = Array.isArray(p.sites_exclus) ? p.sites_exclus.map((x) => entier(x, 0)).filter(Boolean) : [];
    for (const site_id of exclus) await sql`INSERT INTO argos_site_exclu (utilisateur_id, site_id) VALUES (${id}, ${site_id}) ON CONFLICT DO NOTHING`;
    const lien = await lienActivation(sql, id, "activation", req);
    return { id, lien: lien.url, envoye: lien.envoye };
  },

  async utilisateur_modifier(sql, p) {
    const id = entier(p.id, 0);
    const nom = texte(p.nom, 80), prenom = texte(p.prenom, 80);
    const role = p.responsable ? "responsable" : "lecture";
    const civilite = ["Monsieur", "Madame"].includes(p.civilite) ? p.civilite : null;
    await sql`UPDATE argos_utilisateur SET civilite = ${civilite}, nom = ${nom}, prenom = ${prenom}, role = ${role}, maj_le = NOW() WHERE id = ${id}`;
    await sql`DELETE FROM argos_site_exclu WHERE utilisateur_id = ${id}`;
    const exclus = Array.isArray(p.sites_exclus) ? p.sites_exclus.map((x) => entier(x, 0)).filter(Boolean) : [];
    for (const site_id of exclus) await sql`INSERT INTO argos_site_exclu (utilisateur_id, site_id) VALUES (${id}, ${site_id}) ON CONFLICT DO NOTHING`;
    return { ok: true };
  },

  // Renvoie un lien (activation | code | mdp) et l'envoie par courriel si Brevo est configuré
  async utilisateur_lien(sql, p, req) {
    const id = entier(p.id, 0);
    const objet = ["activation", "code", "mdp"].includes(p.objet) ? p.objet : "activation";
    const lien = await lienActivation(sql, id, objet, req);
    return { lien: lien.url, envoye: lien.envoye, objet };
  },

  async utilisateur_suspendre(sql, p) {
    const id = entier(p.id, 0);
    const suspendre = !!p.suspendre;
    const motif = texte(p.motif, 500);
    if (suspendre && !motif) throw new Error("Le motif de la suspension est obligatoire.");
    const cl = await sql`SELECT client_id FROM argos_utilisateur WHERE id = ${id}`;
    if (cl.length) await sql`INSERT INTO argos_suspension (client_id, utilisateur_id, action, motif) VALUES (${cl[0].client_id}, ${id}, ${suspendre ? "suspension" : "retablissement"}, ${suspendre ? motif : null})`;
    if (suspendre) {
      await sql`UPDATE argos_utilisateur SET suspendu_le = NOW(), maj_le = NOW() WHERE id = ${id}`;
      await sql`UPDATE argos_session SET revoque_le = NOW() WHERE utilisateur_id = ${id} AND revoque_le IS NULL`;
    } else {
      // rétablissement : lève la suspension manuelle, la coupure du responsable et le blocage 48 h
      await sql`UPDATE argos_utilisateur SET suspendu_le = NULL, coupe_par_responsable = NULL, bloque_jusqua = NULL, pause_volume = NULL, alerte_volume_le = NULL, echecs_mdp = 0, echecs_code = 0, maj_le = NOW() WHERE id = ${id}`;
    }
    const u = await sql`SELECT client_id FROM argos_utilisateur WHERE id = ${id}`;
    if (u.length) await sql`INSERT INTO argos_connexion (client_id, utilisateur_id, resultat, detail) VALUES (${u[0].client_id}, ${id}, ${suspendre ? "suspension" : "reinitialisation"}, ${suspendre ? "Suspendu par FIDAL Notaires" : "Accès rétabli par FIDAL Notaires"})`;
    return { ok: true };
  },

  async utilisateur_supprimer(sql, p) {
    const id = entier(p.id, 0);
    const n = await sql`SELECT COUNT(*)::int AS n FROM argos_connexion WHERE utilisateur_id = ${id}`;
    if (n[0].n > 0) throw new Error("Cette personne a un historique de connexions : suspendez-la plutôt que de la supprimer (le journal doit rester complet).");
    await sql`DELETE FROM argos_utilisateur WHERE id = ${id}`;
    return { ok: true };
  },

  async appareil_retirer(sql, p) {
    const id = entier(p.id, 0);
    await sql`UPDATE argos_session SET revoque_le = NOW() WHERE appareil_id = ${id} AND revoque_le IS NULL`;
    await sql`DELETE FROM argos_appareil WHERE id = ${id}`;
    return { ok: true };
  },

  // Journal filtré (personne, période, type) pour l'onglet Connexions et l'export PDF
  async journal(sql, p) {
    const client_id = entier(p.client_id, 0);
    const utilisateur_id = entier(p.utilisateur_id, 0) || null;
    const type = texte(p.type, 30) || null;
    const depuis = p.depuis ? new Date(p.depuis) : null, jusqua = p.jusqua ? new Date(p.jusqua + "T23:59:59") : null;
    const lignes = await sql`
      SELECT cx.id, cx.horodatage, cx.resultat, cx.detail, cx.courriel AS courriel_saisi, cx.adresse_ip,
             u.nom AS utilisateur_nom, u.prenom AS utilisateur_prenom, u.courriel AS utilisateur_courriel, a.libelle AS appareil
      FROM argos_connexion cx
      LEFT JOIN argos_utilisateur u ON u.id = cx.utilisateur_id
      LEFT JOIN argos_appareil a ON a.id = cx.appareil_id
      WHERE cx.client_id = ${client_id}
        AND (${utilisateur_id}::int IS NULL OR cx.utilisateur_id = ${utilisateur_id})
        AND (${type}::text IS NULL OR cx.resultat = ${type})
        AND (${depuis}::timestamptz IS NULL OR cx.horodatage >= ${depuis})
        AND (${jusqua}::timestamptz IS NULL OR cx.horodatage <= ${jusqua})
      ORDER BY cx.horodatage DESC LIMIT 500`;
    const telechargements = await sql`
      SELECT t.id, t.horodatage, u.nom AS utilisateur_nom, u.prenom AS utilisateur_prenom, COALESCE(NULLIF(p.intitule, ''), p.nom_fichier) AS nom_fichier, s.nom AS site, s.commune
      FROM argos_telechargement t JOIN argos_utilisateur u ON u.id = t.utilisateur_id
      JOIN argos_piece p ON p.id = t.piece_id JOIN argos_site s ON s.id = p.site_id
      WHERE u.client_id = ${client_id}
        AND (${utilisateur_id}::int IS NULL OR t.utilisateur_id = ${utilisateur_id})
        AND (${depuis}::timestamptz IS NULL OR t.horodatage >= ${depuis})
        AND (${jusqua}::timestamptz IS NULL OR t.horodatage <= ${jusqua})
      ORDER BY t.horodatage DESC LIMIT 500`;
    return { connexions: lignes, telechargements };
  },

  // ===== LOT 4 (02/11/2026) — échéances techniques =====
  async echeances(sql) {
    const lignes = await sql`SELECT id, libelle, echeance, note, fait_le, rappel_envoye_le, cree_le FROM argos_echeance ORDER BY fait_le NULLS FIRST, echeance`;
    return { echeances: lignes, jours_alerte: JOURS_ALERTE_ECHEANCE };
  },
  async echeance_creer(sql, p) {
    const libelle = texte(p.libelle, 160), echeance = texte(p.echeance, 10), note = texte(p.note, 1000);
    if (!libelle || !/^\d{4}-\d{2}-\d{2}$/.test(echeance)) throw new Error("Libellé et date (AAAA-MM-JJ) obligatoires.");
    const r = await sql`INSERT INTO argos_echeance (libelle, echeance, note) VALUES (${libelle}, ${echeance}, ${note || null}) RETURNING id`;
    return { id: r[0].id };
  },
  async echeance_modifier(sql, p) {
    const id = entier(p.id, 0), libelle = texte(p.libelle, 160), echeance = texte(p.echeance, 10), note = texte(p.note, 1000);
    if (!libelle || !/^\d{4}-\d{2}-\d{2}$/.test(echeance)) throw new Error("Libellé et date (AAAA-MM-JJ) obligatoires.");
    // une date repoussée réarme le rappel
    await sql`UPDATE argos_echeance SET libelle = ${libelle}, echeance = ${echeance}, note = ${note || null},
              rappel_envoye_le = CASE WHEN echeance <> ${echeance}::date THEN NULL ELSE rappel_envoye_le END WHERE id = ${id}`;
    return { ok: true };
  },
  async echeance_fait(sql, p) {
    const id = entier(p.id, 0);
    await sql`UPDATE argos_echeance SET fait_le = ${p.fait ? new Date() : null} WHERE id = ${id}`;
    return { ok: true };
  },
  async echeance_supprimer(sql, p) {
    await sql`DELETE FROM argos_echeance WHERE id = ${entier(p.id, 0)}`;
    return { ok: true };
  },
  // Lancement manuel de la ronde de nuit depuis l'écran (même code que la tâche planifiée)
  async ronde_lancer(sql) {
    return ronde(sql, { manuel: true });
  },

  // Événements (bande rouge) : liste et marquage
  async evenements(sql, p) {
    const client_id = entier(p.client_id, 0) || null;
    const lignes = await sql`SELECT e.id, e.client_id, c.nom AS client_nom, e.nature, e.detail, e.traite, e.cree_le
                             FROM argos_evenement e LEFT JOIN argos_client c ON c.id = e.client_id
                             WHERE (${client_id}::int IS NULL OR e.client_id = ${client_id}) AND (e.traite = FALSE OR e.cree_le > NOW() - INTERVAL '30 days')
                             ORDER BY e.traite, e.cree_le DESC LIMIT 200`;
    return { evenements: lignes };
  },
  async evenement_traiter(sql, p) {
    const id = entier(p.id, 0);
    if (p.tous && p.client_id) await sql`UPDATE argos_evenement SET traite = TRUE WHERE client_id = ${entier(p.client_id, 0)}`;
    else await sql`UPDATE argos_evenement SET traite = TRUE WHERE id = ${id}`;
    return { ok: true };
  },
  async client_vu(sql, p) {
    await sql`UPDATE argos_client SET vu_le = NOW() WHERE id = ${entier(p.id, 0)}`;
    return { ok: true };
  },

  // ---- création du site client sur Vercel (un déploiement par client, même dépôt GitHub ARGOS) ----
  async vercel_etat() {
    return { pret: !!(process.env.VERCEL_JETON && process.env.ARGOS_LECTEUR_URL && process.env.SCW_LECTURE_CLE && process.env.SCW_LECTURE_SECRET), depot: process.env.ARGOS_DEPOT || "FIDAL-NOTAIRES/ARGOS",
      manque: ["VERCEL_JETON", "ARGOS_LECTEUR_URL", "SCW_LECTURE_CLE", "SCW_LECTURE_SECRET"].filter((v) => !process.env[v]) };
  },
  async client_deployer(sql, p) {
    const id = entier(p.id, 0);
    const c = await sql`SELECT id, nom, code, cle_lecture, url_site, vercel_projet FROM argos_client WHERE id = ${id}`;
    if (!c.length) throw new Error("Client introuvable.");
    const client = c[0];
    const code = texte(p.code, 40).toLowerCase().replace(/[^a-z0-9-]/g, "") || client.code;
    if (!code) throw new Error("Nom court obligatoire (lettres, chiffres, tirets).");
    const r = await deployerSiteClient(client, code);
    await sql`UPDATE argos_client SET code = ${code}, url_site = ${r.url}, vercel_projet = ${r.projet}, maj_le = NOW() WHERE id = ${id}`;
    return r;
  },
};

// ---------- point d'entrée ----------
module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json; charset=utf-8");

  if (req.method !== "POST") {
    res.statusCode = 405;
    return res.end(JSON.stringify({ erreur: "Méthode non autorisée" }));
  }
  const corps = lireCorps(req);
  const action = texte(corps.action, 40);

  if (!process.env.ARGOSADMIN_MDP) {
    res.statusCode = 500;
    return res.end(JSON.stringify({ erreur: "Variable ARGOSADMIN_MDP absente sur Vercel." }));
  }
  if (!process.env.DATABASE_URL) {
    res.statusCode = 500;
    return res.end(JSON.stringify({ erreur: "Variable DATABASE_URL absente sur Vercel." }));
  }

  // Connexion de l'administrateur
  if (action === "connexion") {
    const mdp = String(corps.mdp || "");
    if (!mdp || !egalSur(mdp, process.env.ARGOSADMIN_MDP)) {
      await new Promise((r) => setTimeout(r, 800)); // freine les essais
      res.statusCode = 401;
      return res.end(JSON.stringify({ erreur: "Mot de passe incorrect." }));
    }
    return res.end(JSON.stringify({ jeton: creerJeton(), expire_dans: DUREE_SESSION_MS }));
  }

  // Toute autre action exige un jeton valide
  const auth = String(req.headers["authorization"] || "");
  const jeton = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!jetonValide(jeton)) {
    res.statusCode = 401;
    return res.end(JSON.stringify({ erreur: "Session expirée, reconnectez-vous." }));
  }

  const fn = actions[action];
  if (!fn) {
    res.statusCode = 400;
    return res.end(JSON.stringify({ erreur: `Action inconnue : ${action}` }));
  }

  try {
    const sql = neon(process.env.DATABASE_URL);
    const resultat = await fn(sql, corps, req);
    return res.end(JSON.stringify(resultat));
  } catch (e) {
    console.error("[argosadmin]", action, e);
    res.statusCode = 500;
    return res.end(JSON.stringify({ erreur: e.message || "Erreur serveur" }));
  }
};
module.exports.ronde = ronde;

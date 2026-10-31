// ============================================================
// ARGOSAdmin — api/admin.js — lots 1 et 2 (31/10/2026)
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
// ============================================================

const { neon } = require("@neondatabase/serverless");
const crypto = require("crypto");

const DUREE_SESSION_MS = 8 * 60 * 60 * 1000; // 8 heures
const DELAI_SONDAGE_MS = 5000;

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
    if (rep.ok) return { ok: true, message: "" };
    return { ok: false, message: `Réponse ${rep.status}` };
  } catch (e) {
    clearTimeout(minuteur);
    return { ok: false, message: e.name === "AbortError" ? "Pas de réponse en 5 secondes" : (e.message || "Erreur réseau") };
  }
}

// ---------- Scaleway Object Storage (signature AWS v4, sans bibliothèque) ----------
const RUBRIQUES = {
  1: "Désignation et plans", 2: "Titre", 3: "Exploitation",
  4: "Fiscalité", 5: "Diagnostics", 6: "Organisation de l'immeuble / de la zone",
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
function nomFichierPropre(nom) {
  return String(nom || "piece").normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 120) || "piece";
}

// ---------- actions ----------
const actions = {
  async clients(sql) {
    const lignes = await sql`
      SELECT c.id, c.nom, c.actif, c.url_site, c.seuil_jour, c.seuil_vitesse, c.cree_le,
             (SELECT COUNT(*)::int FROM argos_site s WHERE s.client_id = c.id) AS nb_sites,
             (SELECT COUNT(*)::int FROM argos_utilisateur u WHERE u.client_id = c.id) AS nb_utilisateurs,
             (SELECT MAX(p.depose_le) FROM argos_piece p JOIN argos_site s ON s.id = p.site_id WHERE s.client_id = c.id) AS dernier_depot,
             so.dernier_ok, so.dernier_echec, so.message AS sondage_message
      FROM argos_client c
      LEFT JOIN argos_sondage so ON so.client_id = c.id
      ORDER BY c.nom`;
    const alertes = await sql`SELECT COUNT(*)::int AS n FROM argos_evenement WHERE traite = FALSE`;
    return { clients: lignes, alertes: alertes[0].n };
  },

  async sonder(sql) {
    const clients = await sql`SELECT id, url_site FROM argos_client ORDER BY id`;
    const resultats = await Promise.all(clients.map(async (c) => {
      const r = await sonderUrl(c.url_site);
      if (r.ok === true) {
        await sql`INSERT INTO argos_sondage (client_id, dernier_ok, message) VALUES (${c.id}, NOW(), '')
                  ON CONFLICT (client_id) DO UPDATE SET dernier_ok = NOW(), message = ''`;
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
    const cle = nouvelleCleLecture();
    const ins = await sql`
      INSERT INTO argos_client (nom, cle_lecture, url_site)
      VALUES (${nom}, ${cle}, ${url_site})
      RETURNING id`;
    const id = ins[0].id;
    await sql`INSERT INTO argos_sondage (client_id) VALUES (${id}) ON CONFLICT DO NOTHING`;
    return { id, cle_lecture: cle };
  },

  async client(sql, p) {
    const id = entier(p.id, 0);
    const c = await sql`
      SELECT c.*, so.dernier_ok, so.dernier_echec, so.message AS sondage_message
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
      SELECT id, courriel, nom, role, active, bloque_jusqua, cree_le
      FROM argos_utilisateur WHERE client_id = ${id} ORDER BY role DESC, courriel`;
    const connexions = await sql`
      SELECT cx.id, cx.horodatage, cx.resultat, cx.courriel AS courriel_saisi, cx.adresse_ip,
             u.nom AS utilisateur_nom, u.courriel AS utilisateur_courriel,
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
    return { client: c[0], sites, utilisateurs, connexions };
  },

  async client_modifier(sql, p) {
    const id = entier(p.id, 0);
    const nom = texte(p.nom, 120);
    if (!nom) throw new Error("Le nom du client est obligatoire.");
    const url_site = texte(p.url_site, 300);
    const seuil_jour = Math.max(1, entier(p.seuil_jour, 30));
    const seuil_vitesse = Math.max(1, entier(p.seuil_vitesse, 10));
    await sql`
      UPDATE argos_client
      SET nom = ${nom}, url_site = ${url_site}, seuil_jour = ${seuil_jour}, seuil_vitesse = ${seuil_vitesse}, maj_le = NOW()
      WHERE id = ${id}`;
    return { ok: true };
  },

  async client_suspendre(sql, p) {
    const id = entier(p.id, 0);
    const actif = !!p.actif;
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
    const ins = await sql`
      INSERT INTO argos_site (client_id, nom, adresse, commune, code_postal)
      VALUES (${client_id}, ${nom}, ${adresse}, ${commune}, ${code_postal})
      RETURNING id`;
    return { id: ins[0].id };
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
      SELECT id, rubrique, nom_fichier, type_mime, taille, empreinte, copie_principale, copie_sauvegarde, sauvegarde_le, depose_le
      FROM argos_piece WHERE site_id = ${id} ORDER BY rubrique, depose_le DESC`;
    return { site: s[0], pieces, rubriques: RUBRIQUES, stockage_pret: stockagePret() };
  },

  async site_modifier(sql, p) {
    const id = entier(p.id, 0);
    const references_ = {
      cadastre: texte(p.cadastre, 600),
      surface: texte(p.surface, 60),
      titre: texte(p.titre, 300),
    };
    const fiche = { designation: texte(p.designation, 4000) };
    await sql`
      UPDATE argos_site
      SET nom = ${texte(p.nom, 160)}, adresse = ${texte(p.adresse, 300)},
          code_postal = ${texte(p.code_postal, 10)}, commune = ${texte(p.commune, 120)},
          references_ = ${JSON.stringify(references_)}::jsonb, fiche = ${JSON.stringify(fiche)}::jsonb,
          maj_le = NOW()
      WHERE id = ${id}`;
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
    const site_id = entier(p.site_id, 0);
    const rubrique = entier(p.rubrique, 0);
    const cle = texte(p.cle_objet, 600);
    if (!cle.startsWith(`client-`) || !cle.includes(`/site-${site_id}/rubrique-${rubrique}/`)) throw new Error("Clé d'objet incohérente.");
    const principal = compteScaleway("principal"), sauvegarde = compteScaleway("sauvegarde");
    const [rp, rs] = await Promise.all([requeteSignee(principal, "HEAD", cle), requeteSignee(sauvegarde, "HEAD", cle)]);
    const okP = rp.ok, okS = rs.ok;
    if (!okP) throw new Error("Le fichier n'est pas arrivé dans le compte principal (réponse " + rp.status + ").");
    const ins = await sql`
      INSERT INTO argos_piece (site_id, rubrique, nom_fichier, type_mime, taille, empreinte, cle_objet,
                               bucket_principal, bucket_sauvegarde, copie_principale, copie_sauvegarde, sauvegarde_le)
      VALUES (${site_id}, ${rubrique}, ${texte(p.nom_fichier, 255)}, ${texte(p.type_mime, 120) || "application/pdf"},
              ${entier(p.taille, 0)}, ${texte(p.empreinte, 64)}, ${cle},
              ${principal.bucket}, ${sauvegarde.bucket}, ${okP}, ${okS}, ${okS ? new Date() : null})
      RETURNING id`;
    await sql`UPDATE argos_site SET maj_le = NOW() WHERE id = ${site_id}`;
    if (!okS) {
      const site = await sql`SELECT client_id FROM argos_site WHERE id = ${site_id}`;
      await sql`INSERT INTO argos_evenement (client_id, nature, detail)
                VALUES (${site[0].client_id}, 'sauvegarde_echec', ${"Copie de sauvegarde absente pour " + cle})`;
    }
    return { id: ins[0].id, copie_sauvegarde: okS };
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
    }
    return { origine, resultats };
  },

  // Contrôle de l'état du stockage pour l'écran (sans exposer les clés)
  async stockage_etat() {
    const principal = compteScaleway("principal"), sauvegarde = compteScaleway("sauvegarde");
    return {
      principal: principal ? { bucket: principal.bucket, region: principal.region } : null,
      sauvegarde: sauvegarde ? { bucket: sauvegarde.bucket, region: sauvegarde.region } : null,
    };
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

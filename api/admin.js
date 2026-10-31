// ============================================================
// ARGOSAdmin — api/admin.js — lot 1 (30/10/2026)
// Fonction serveur UNIQUE à actions (limite Vercel Hobby : 12 fonctions).
// Appel : POST /api/admin  { action: "...", ...paramètres }
// En-tête : Authorization: Bearer <jeton>  (sauf action "connexion")
//
// Variables d'environnement Vercel attendues :
//   DATABASE_URL        chaîne Neon (rôle matrice_owner, projet neon-fuchsia-pillow)
//   ARGOSADMIN_MDP      mot de passe administrateur provisoire (JFD seul) — remplacé au lot 5
//   ARGOSADMIN_SECRET   (facultatif) secret de signature des jetons de session ;
//                       à défaut, dérivé du mot de passe
// Lot 2 (pour mémoire, non lues ici) :
//   SCW_PRINCIPAL_CLE / SCW_PRINCIPAL_SECRET / SCW_PRINCIPAL_BUCKET
//   SCW_SAUVEGARDE_CLE / SCW_SAUVEGARDE_SECRET / SCW_SAUVEGARDE_BUCKET
//   SCW_REGION (fr-par) / SCW_ENDPOINT (https://s3.fr-par.scw.cloud)
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
    const resultat = await fn(sql, corps);
    return res.end(JSON.stringify(resultat));
  } catch (e) {
    console.error("[argosadmin]", action, e);
    res.statusCode = 500;
    return res.end(JSON.stringify({ erreur: e.message || "Erreur serveur" }));
  }
};

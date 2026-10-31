# ARGOSAdmin — administration isolée du portail patrimoine ARGOS

Site réservé au cabinet (FIDAL Notaires). Il alimente le site client ARGOS, qui ne fait que lire.
Aucune adresse d'ARGOSAdmin ne doit apparaître dans le code du site client.

## Lot 1 (30/10/2026) — socle
- `index.html` : connexion administrateur, liste des clients (voyant vert/rouge), fiche client (sites, utilisateurs, journal).
- `api/admin.js` : fonction serveur unique à actions (Neon).
- `argosadmin_lot1.sql` : tables `argos_*` + rôle lecture seule `argos_lecteur` (à exécuter dans Neon, projet gentle-firefly-91584148).

## Variables d'environnement Vercel (lot 1)
| Variable | Rôle |
|---|---|
| `DATABASE_URL` | chaîne Neon, rôle `matrice_owner` |
| `ARGOSADMIN_MDP` | mot de passe administrateur provisoire (remplacé au lot 5) |
| `ARGOSADMIN_SECRET` | facultatif : secret de signature des sessions |

## Lots suivants
2. Fiche site : dépôt des pièces vers Scaleway (compte principal + copie sauvegarde), pont lecture seule vers le site client, `/api/sante` côté client.
3. Utilisateurs : création par courriel, lien d'activation, code secret, droits, suspension.
4. Journal, seuils (30/jour, 10 en 5 min), alertes courriel, contrôle de nuit, bande rouge.
5. Connexion modèle Caisse des dépôts (notification, biométrie, code) + appli téléphone ARGOS.

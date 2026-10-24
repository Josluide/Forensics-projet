# Réponse à incident & forensics  Projet D

Rapport d'investigation forensique d'un endpoint Debian compromis, réalisé dans le cadre d'un TP pédagogique (analyse hors ligne, en lecture seule, sur image disque et dump mémoire fournis).

Contexte strictement pédagogique. Les IOC présents (ex. `203.0.113.50`, bloc **TEST-NET-3** réservé à la documentation RFC 5737) ne doivent **jamais** être contactés. L'implant n'a jamais été exécuté pendant l'analyse.

## Résumé de l'incident

L'analyse de l'hôte **`cnd-endpoint01`** (Debian, noyau 6.1.0-54-amd64) confirme une **compromission avec exécution de code et persistance au niveau root**.

- **Persistance** : unité systemd malveillante `systemd-sysupdate.service` (`Restart=always`, activée via `multi-user.target.wants/`) lançant un binaire caché `/usr/lib/systemd/.cache/sysupdate` (ELF 64 bits statique).
- **Exécution** : l'implant démarre à chaque amorçage sous **UID 0** (processus `sysupdate`, PID 315 en mémoire).
- **Point d'entrée probable** : leurre documentaire visant `jdupont` (`facture_fournisseur.pdf.exe` → renommé `.pdf` → ouvert via `xdg-open`).
- **Impact démontré** : atteinte à l'intégrité du système + exécution arbitraire sous privilèges root. **Aucune exfiltration ni connexion C2 réussie n'est démontrée.**

## Méthode

Analyse **hors ligne**, **en lecture seule** (montage `ro,noload`, lectures directes via The Sleuth Kit), sans exécuter l'implant ni contacter les IOC. Chaîne de possession vérifiée par `sha256sum -c`.

Outils utilisés :
- **The Sleuth Kit** (`mmls`, `fsstat`, `fls`, `icat`, `istat`, `mactime`) analyse disque et timeline
- **Volatility 3** (profil ISF `debian-6.1.0-54-amd64`) analyse mémoire
- `file`, `readelf`, `strings`, `objdump` analyse statique du binaire
- `dpkg -V`, analyse de `audit.log`, PAM, wtmp/lastlog contrôles complémentaires
- **YARA** règle de détection de l'implant

## Contenu du dépôt

| Fichier | Description |
|---------|-------------|
| [`rapport_incident.md`](rapport_incident.md) | Rapport d'investigation complet (résumé, intégrité, analyse disque, chronologie UTC, point d'entrée, IOC, analyse mémoire, impact, recommandations, limites) |
| [`Rapport_ProjetD_forensics.docx`](Rapport_ProjetD_forensics.docx) | Version mise en forme du rapport (livrable) |

## Chronologie (résumé)

Amorçage du système compromis → premier lancement du service → activation de la persistance → redémarrages successifs avec lancement automatique de l'implant sous root → acquisition de la preuve → image disque figée. Chronologie détaillée à la milliseconde (sources `audit.log`, `wtmp`, mémoire) dans le rapport.

## Recommandations (synthèse)

Isolation de l'hôte, éradication de l'unité et du binaire cachés, durcissement SSH, revue des comptes à privilèges, et surveillance de l'IOC réseau. Détail de l'éradication, de la remise en état et de la vérification post-correction dans le rapport.

---

*Projet pédagogique de réponse à incident Groupe D.*

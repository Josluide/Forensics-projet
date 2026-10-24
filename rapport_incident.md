# Rapport de réponse à incident et forensics — Groupe D

**Hôte analysé :** cnd-endpoint01
**Périmètre :** image disque et dump mémoire fournis pour le Groupe D uniquement
**Méthode :** analyse hors ligne, lecture seule, sans exécution de l'implant et sans connexion aux IOC
**Date de rédaction :** 22 octobre 2026

> État de rédaction : brouillon en cours. Chaque section se remplit avec les sorties réelles capturées par Daren. Les valeurs attendues (d'après les consignes du prof) servent de repère de vérification.

---

## 1. Résumé exécutif

L'analyse hors ligne de l'image disque et du dump mémoire de l'hôte **`cnd-endpoint01`** confirme une **compromission avec exécution de code et persistance au niveau root**.

Le mécanisme de persistance est une **unité systemd `systemd-sysupdate.service`**, dont le nom imite un composant légitime de mise à jour. Elle lance **`/usr/lib/systemd/.cache/sysupdate`**, un exécutable **ELF 64 bits statiquement lié** placé dans un répertoire **caché** sous l'arborescence systemd. Le service est activé au démarrage (`multi-user.target.wants/`) et relancé automatiquement (`Restart=always`). L'audit et la mémoire prouvent que l'implant **démarre à chaque amorçage** et s'exécute sous **UID 0** (processus `sysupdate`, PID 315).

Le **point d'entrée le plus vraisemblable** est un **leurre documentaire** visant l'utilisateur **`jdupont`** : l'historique shell montre le renommage de `facture_fournisseur.pdf.exe` en `facture_fournisseur.pdf` puis son ouverture via `xdg-open`. Le `.exe` original n'est plus présent dans l'image (seul subsiste un PDF leurre de 131 octets) : la **séquence utilisateur est prouvée** (confiance élevée), mais l'exécution directe du fichier original ne peut pas être démontrée par les seules preuves disponibles.

Le binaire contient l'**IOC réseau `203.0.113.50`** (bloc TEST-NET-3, à **ne jamais contacter**). L'impact minimal démontré est l'**atteinte à l'intégrité du système** et l'**exécution arbitraire sous privilèges root**. **Aucune exfiltration ni connexion C2 réussie n'est démontrée** par les preuves disponibles.

## 2. Intégrité et chaîne de possession

_Preuves analysées sans modifier l'original. Volume monté `ro,noload`. Implant jamais exécuté._

Trois preuves fournies dans `TP/GROUPE D/`. Vérification d'intégrité `sha256sum -c forensic-artifacts.sha256` → **les deux correspondent (Réussi)**, preuves non altérées (capture 4).

| Preuve | Fichier | Taille | SHA-256 | Vérif |
|--------|---------|--------|---------|-------|
| Image disque | `endpoint-b-disk.raw` | 3,0 Gio | `8cd19344d416131565b9a619818a247b4706aa952a50f010141957b83c9b3efe` | ✅ OK |
| Dump mémoire | `endpoint-b-memory.raw` | 1,0 Gio | `eda04fe594d74a00b6fc5921fd2e29682d3df39a9d6b854f7616d2327d71f6ea` | ✅ OK |
| Fichier d'empreintes | `forensic-artifacts.sha256` | 174 o | — | — |

Fourni en plus : `debian-6.1.0-54-amd64.json` + dossier `symbols/` = profil de symboles ISF pour Volatility 3.

**Montage en lecture seule** (capture 7) : `endpoint-b-disk.raw on ~/forensics/mount type ext4 (ro,relatime,norecovery)` → l'option **`ro`** garantit qu'aucune écriture n'a modifié la preuve. L'implant n'a jamais été exécuté.

## 3. Identification du disque

Table de partitions **GPT (EFI)**, secteurs de 512 octets (`mmls`, capture 5) :

| Slot | Début | Fin | Longueur | Description |
|------|-------|-----|----------|-------------|
| 004 (013) | 2048 | 8191 | 6144 | partition de démarrage |
| 005 (014) | 8192 | 262143 | 253952 | partition |
| 006 (000) | 262144 | 6289407 | 6027264 | **volume Linux principal (ext4)** |

Partition Linux : secteur de départ **262144** → offset **262144 × 512 = 134217728 octets**.
Montage lecture seule : `sudo mount -o ro,noload,loop,offset=134217728 endpoint-b-disk.raw mount/` (capture 7).

`fsstat -o 262144` (capture 6) :
- Type : **Ext4**, Source OS : Linux
- Volume ID : **`bd976b90b0de4b94714218713ab689ac`**
- Dernier montage (« Last Mounted ») : 2026-10-21 **08:59:58 UTC** (09:59:58 affiché en WAT = UTC+1)
- Dernière écriture (« Last Written ») : 2026-10-21 **08:38:53 UTC** (09:38:53 WAT)
- Dernier point de montage : `/`
- Block size 4096, inodes 1–188417

> ⏱️ **Note fuseau horaire** : la Kali affiche l'heure en **WAT (UTC+1)**. Toutes les heures du rapport sont en **UTC** → on retranche 1 h aux sorties, ou on force `export TZ=UTC` dans le terminal.

## 4. Chronologie reconstruite — UTC

_Toutes les heures en UTC (la Kali d'analyse affiche WAT = UTC+1 ; sorties forcées en UTC via `TZ=UTC`)._

| Heure (UTC) | Événement | Source | Confiance |
|-------------|-----------|--------|-----------|
| 2026-10-21 08:30:02 | mtime du binaire `sysupdate` (date de préparation/copie) | MACB disque (stat, cap. 11) | élevée |
| 2026-10-21 08:32:15.668 | Création du dossier caché `.cache` + naissance du binaire `sysupdate` | MACB disque (stat, cap. 11) | élevée |
| 2026-10-21 08:32:15.684 | Naissance du fichier `systemd-sysupdate.service` | MACB disque (stat, cap. 10) | élevée |
| 2026-10-21 08:32:15.796 | Naissance de l'artefact leurre `facture_fournisseur.pdf` | MACB disque (stat, cap. 15) | élevée |
| (avant la session root) | jdupont renomme `facture_fournisseur.pdf.exe` → `.pdf` puis l'ouvre (`xdg-open`) | .bash_history (cap. 15) | élevée (séquence) |
| 2026-10-21 08:51:33 | Connexion **root** locale sur `/dev/ttyS0` (hôte `cnd-endpoint01`) | audit.log (cap. 17) | élevée |
| 2026-10-21 08:54:19–08:54:20 | Nouvelle connexion root sur `/dev/ttyS0` | audit.log (cap. 17) | élevée |
| 2026-10-21 08:54:21 | root ouvre brièvement une session `su` vers jdupont (≈160 ms) | audit.log (cap. 17) | élevée |
| 2026-10-21 08:54:37 | **Premier démarrage** du service `systemd-sysupdate` (par PID 1) | audit.log SERVICE_START (cap. 17) | élevée |
| 2026-10-21 08:55:00.376 | Modification finale de l'unité systemd | MACB disque (stat, cap. 10) | élevée |
| 2026-10-21 08:55:08 | Création du lien `multi-user.target.wants/systemd-sysupdate.service` | ls -la (cap. 8) | élevée |
| 2026-10-21 08:55:33 | Arrêt du service (redémarrage de la machine) | audit.log SERVICE_STOP (cap. 17) | élevée |
| 2026-10-21 08:56:25 | **Redémarrage automatique** du service au boot suivant (preuve de persistance) | audit.log SERVICE_START (cap. 17) | élevée |
| 2026-10-21 09:00:09 | Nouveau démarrage du service par PID 1 (boot suivant) | audit.log SERVICE_START (cap. 17) | élevée |
| 2026-10-21 ~09:01 | Session root : vérification service actif + `BOOTED_AND_IMPLANT_OK` | /root/.bash_history (cap. 16) | élevée |
| 2026-10-21 09:01:28 | Arrêt final du service + extinction propre de la VM (`sync; poweroff`) | audit.log SERVICE_STOP + bash_history (cap. 16-17) | élevée |

**Lecture de la chrono** : le service `systemd-sysupdate` **démarre à chaque amorçage** (08:54:37, 08:56:25, 09:00:09), ce qui **prouve la persistance** (activation au boot + `Restart=always`). La séquence `su` root→jdupont (08:54:21) et les connexions root sur la console série `/dev/ttyS0` situent l'activité de vérification de l'implant par l'administrateur/attaquant, juste avant l'extinction (09:01:28).

## 5. Point d'entrée et chaîne d'attaque

### 5.1 Point d'entrée probable

Le seul compte utilisateur présent est **`jdupont`** (`/home/` ne contient que `jdupont`), ce qui confirme que l'**UID 1000** propriétaire des fichiers implant correspond bien à cet utilisateur.

**Historique shell de jdupont** (`/home/jdupont/.bash_history`, capture 15) :
```
ls -la
cd Documents
cat rapport_mensuel.txt
firefox &
cd ~/Downloads
ls
mv facture_fournisseur.pdf.exe facture_fournisseur.pdf
xdg-open facture_fournisseur.pdf
history
exit
```

**Lecture de la séquence** : l'utilisateur ouvre Firefox, va dans `~/Downloads`, puis **renomme `facture_fournisseur.pdf.exe` en `facture_fournisseur.pdf`** (il masque l'extension exécutable derrière une fausse extension PDF), et **l'ouvre avec `xdg-open`**. C'est le schéma classique du **leurre à double extension** par ingénierie sociale documentaire.

**Le fichier restant** `~/Downloads/facture_fournisseur.pdf` (capture 15) est un **leurre de 131 octets** :
```
%PDF-1.4 (document leurre, non ouvrable - sert uniquement d'artefact pour le TP CND)
Facture Delmas SARL - reference DLM-2026-0914
```
SHA-256 : `e4c172fc0be02986a5deae88ccb4317724919027a86aab55e1195c8a4f772161`. Horodatages (`stat`) : mtime 2026-10-19 08:32:16, naissance 2026-10-21 08:32:15.796 UTC, UID 1000.

⚠️ **Nuance (honnêteté des preuves)** : le fichier `.exe` original **n'est plus présent** dans l'image. On a donc une **preuve forte de la séquence utilisateur** (renommage + ouverture, confiance élevée), mais **pas de preuve directe** que l'exécutable original a bien lancé l'implant. On qualifie ce vecteur de **point d'entrée probable**.

### 5.2 Exécution et persistance

**Démarche — comment on a repéré l'intrus (capture 8).**
On a listé `/etc/systemd/system/` et son dossier `multi-user.target.wants/` (les unités lancées au démarrage). Dans une installation Debian saine, les fichiers de ce dossier sont presque tous des **liens symboliques** pointant vers `/lib/systemd/system/`, appartenant à **root**, et datés de l'installation (18 oct.). Une entrée tranche nettement :

```
-rw-rw-r-- 1 kali kali  195 21 oct. 08:55 systemd-sysupdate.service
```

Quatre signaux d'alerte convergents :
1. **C'est un vrai fichier, pas un lien** symbolique comme les unités légitimes voisines.
2. Il appartient à **UID 1000** (un utilisateur normal, pas root) — anormal pour une unité système (à confirmer : UID 1000 = `jdupont`, cf. capture 18).
3. Sa **date (21 oct. 08:55)** est très postérieure à l'installation (18 oct.) → ajouté après coup.
4. Son **nom imite** un composant légitime (« systemd-sysupdate »), mais aucun service de ce nom n'est fourni ainsi par Debian.

Le lien d'activation confirme la persistance :
```
multi-user.target.wants/systemd-sysupdate.service → /etc/systemd/system/systemd-sysupdate.service
```
→ le service démarre **automatiquement à chaque boot** (niveau multi-utilisateur).

**Contenu de l'unité (capture 9) :**
```ini
[Unit]
Description=System Update Helper
After=network.target
[Service]
Type=simple
ExecStart=/usr/lib/systemd/.cache/sysupdate
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
```
Lecture : lancé après le réseau, **exécute `/usr/lib/systemd/.cache/sysupdate`** (binaire dans un dossier **caché** `.cache` sous `/usr/lib/systemd`, emplacement qui ne contient normalement pas de `.cache`), et **`Restart=always`** le relance s'il est tué → résilience.

**Horodatages de l'unité (`stat`, capture 10) :**
- Naissance (Créé) : **2026-10-21 08:32:15.684 UTC**
- Dernière modification : **2026-10-21 08:55:00.376 UTC**
- Droits `0664`, propriétaire **UID 1000 / GID 1000**

### 5.3 Objectif final et communication

**Le binaire implant `/usr/lib/systemd/.cache/sysupdate`** (analyse **statique uniquement**, jamais exécuté).

`stat` (capture 11) : dossier caché `.cache` et binaire nés le **2026-10-21 08:32:15.668 UTC**, mtime **08:30:02 UTC**, dernier accès **08:54:21.228 UTC** (coïncide avec la session root, cf. chrono). Droits `0755`, propriétaire UID 1000.

`file` + `readelf` (captures 12-13) :
- **ELF 64 bits LSB, x86-64, statiquement lié, *not stripped*** (symboles conservés), point d'entrée `0x401760`.
- **BuildID (SHA-1)** : `177631402830b4f31e37beb32713cc0fec8256ec`.
- Empreintes : **SHA-256** `6e451414a4ac3dbaa3529d9a867d0cfa8b503cf4eae85d0c16afec45e037d1fa` · **MD5** `189b6b4f2ceda78dd83406951d7616fb`.
- Notes `.note.stapsdt` (sondes SystemTap `lll_lock_*`, `memory_*`) = artefacts normaux d'une **glibc liée statiquement**, pas un indicateur en soi.

Chaînes codées en dur (`strings`, capture 14) — trois éléments décisifs émergent du bruit (le reste = chaînes internes de la glibc statique, liées aux verrous/`lock`) :
- Chemin du **verrou (mutex d'instance unique)** : **`/tmp/.X11-unix/.sysupd_lock`** — caché dans un dossier d'apparence légitime (`.X11-unix`).
- **Marqueur de build** : **`SBX-IMPLANT-BUILD-2026.10-edu`** (confirme un binaire compilé sur mesure ; le suffixe `-edu` = artefact pédagogique du TP).
- **IOC réseau** : **`203.0.113.50`** (capacité réseau compilée ; **ne jamais contacter**).
- Nom de fichier source résiduel : **`sysupdate.c`** (binaire *not stripped*).

**Vérification par root (capture 16).** `/root/.bash_history` (mtime **2026-10-21 09:01 UTC**) contient :
```
systemctl is-active systemd-sysupdate.service; ps aux|grep sysupdate|grep -v grep
echo BOOTED_AND_IMPLANT_OK
sync; poweroff
```
Lecture : une session **root** confirme que le service est **actif** et que le processus `sysupdate` tourne, imprime le marqueur **`BOOTED_AND_IMPLANT_OK`**, puis **éteint proprement la VM** (`sync; poweroff`) — ce qui correspond à l'instant où l'image/le dump ont été figés.

**Objectif démontré** : maintien d'un **exécuteur root persistant** après redémarrage (service `Restart=always`, activé au boot, exécution confirmée sous UID 0). Une capacité réseau est compilée (IOC codé en dur), mais **aucune connexion sortante réussie ni exfiltration n'est prouvée** par les preuves disponibles.

### 5.4 Schéma de la chaîne d'attaque (capture 20)

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │  1. POINT D'ENTRÉE (probable)                                          │
 │  Leurre documentaire « facture_fournisseur.pdf.exe » dans ~/Downloads │
 │  jdupont :  mv  *.pdf.exe → *.pdf   puis   xdg-open   (ingénierie      │
 │  sociale, double extension)                    [confiance : séquence]  │
 └───────────────────────────────┬──────────────────────────────────────┘
                                  │  (exécution du .exe non prouvée —
                                  │   fichier original absent de l'image)
                                  ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  2. DÉPÔT DE L'IMPLANT                                                 │
 │  Binaire  /usr/lib/systemd/.cache/sysupdate  (ELF64 statique, root)   │
 │  + unité  /etc/systemd/system/systemd-sysupdate.service               │
 └───────────────────────────────┬──────────────────────────────────────┘
                                  ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  3. PERSISTANCE                                                        │
 │  Lien multi-user.target.wants/  →  démarrage auto à chaque boot       │
 │  Restart=always                 →  relance si tué                     │
 └───────────────────────────────┬──────────────────────────────────────┘
                                  ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  4. EXÉCUTION ROOT (confirmée disque + mémoire)                        │
 │  Démarrages répétés : 08:54:37, 08:56:25, 09:00:09                     │
 │  Processus  sysupdate  PID 315,  UID 0,  parent systemd (PID 1)       │
 └───────────────────────────────┬──────────────────────────────────────┘
                                  ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  5. OBJECTIF / COMMUNICATION                                           │
 │  Vérification admin : BOOTED_AND_IMPLANT_OK                            │
 │  Capacité réseau compilée → IOC 203.0.113.50 (NON contacté)           │
 │  Exfiltration / C2 réussi : NON prouvés                                │
 │  09:01:28 : arrêt du service + extinction (figement des preuves)      │
 └──────────────────────────────────────────────────────────────────────┘
```

## 6. Indicateurs de compromission

**Fichiers et chemins :**
- `/etc/systemd/system/systemd-sysupdate.service` (unité de persistance)
- `/etc/systemd/system/multi-user.target.wants/systemd-sysupdate.service` (lien d'activation au boot)
- `/usr/lib/systemd/.cache/sysupdate` (binaire implant, dossier caché)
- `/tmp/.X11-unix/.sysupd_lock` (verrou d'instance unique, confirmé par strings)
- `/home/jdupont/Downloads/facture_fournisseur.pdf` (leurre, 131 o, SHA-256 `e4c172fc…772161`)

**Empreintes :**
- Implant SHA-256 : `6e451414a4ac3dbaa3529d9a867d0cfa8b503cf4eae85d0c16afec45e037d1fa`
- Implant MD5 : `189b6b4f2ceda78dd83406951d7616fb`
- BuildID : `177631402830b4f31e37beb32713cc0fec8256ec`

**Réseau :**
- `203.0.113.50` — IOC codé en dur dans le binaire ; appartient au bloc TEST-NET-3 (documentation, non routable) ; **ne jamais contacter**.
- Marqueur de build : `SBX-IMPLANT-BUILD-2026.10-edu`

**Tableau de synthèse des IOC avec niveaux de confiance (capture 20) :**

| IOC | Type | Niveau de confiance |
|-----|------|---------------------|
| `systemd-sysupdate.service` (+ lien `multi-user.target.wants/`) | Persistance / service | Élevé |
| `/usr/lib/systemd/.cache/sysupdate` | Fichier / binaire implant | Élevé |
| SHA-256 `6e451414…37d1fa` · MD5 `189b6b4f…7616fb` | Empreinte binaire | Élevé |
| BuildID `177631…8256ec` | Empreinte binaire | Élevé |
| `/tmp/.X11-unix/.sysupd_lock` | Fichier / verrou | Élevé |
| `SBX-IMPLANT-BUILD-2026.10-edu` | Chaîne / marqueur | Élevé |
| Processus `sysupdate` PID 315 (UID 0) | Exécution en mémoire | Élevé |
| `203.0.113.50` | IOC réseau (capacité, non contactée) | Moyen (pas de connexion prouvée) |
| `facture_fournisseur.pdf` (leurre, SHA-256 `e4c172fc…772161`) | Point d'entrée | Moyen (séquence forte, exécution du `.exe` non prouvée) |

**Processus, services et comptes :**
- Service : `systemd-sysupdate.service` — Processus : `sysupdate`
- Compte d'exécution : **root / UID 0** · Hôte : `cnd-endpoint01` (confirmé via audit.log et `/etc/hostname`)
- Propriétaire des fichiers implant : **UID 1000 = `jdupont`** (confirmé cap. 18 : `jdupont:x:1000:1000::/home/jdupont:/bin/bash`)
- **`jdupont` est membre du groupe `sudo`** (`sudo:x:27:jdupont`) → l'utilisateur ciblé dispose de droits d'élévation.
- Accès root observé : **local, sur la console série `/dev/ttyS0`** (`addr=?` dans l'audit → pas une connexion SSH distante).

## 7. Analyse mémoire

**Corroboration par chaînes du dump `endpoint-b-memory.raw`** (hors ligne, capture 19). Les artefacts du disque se retrouvent **résidents en mémoire** au moment du figement :
- Le **processus de l'implant est vivant** (sortie `ps` capturée en RAM) :
  ```
  root  315  0.6  0.0  976  4 ?  Ss  09:00  0:00 /usr/lib/systemd/.cache/sysupdate
  ```
  → **PID 315**, exécuté sous **root (UID 0)**, démarré à **09:00**, chemin = le binaire implant.
- Marqueur de vérification admin : **`BOOTED_AND_IMPLANT_OK`** (plusieurs occurrences).
- Unité et chemins : `/etc/systemd/system/systemd-sysupdate.service`, `ExecStart=/usr/lib/systemd/.cache/sysupdate`, `/system.slice/systemd-sysupdate.service`, message journald « Started systemd-sysupdate.service - System Update Helper ».
- Verrou : `/tmp/.X11-unix/.sysupd_lock` · Marqueur de build : `SBX-IMPLANT-BUILD-2026.10-edu` · IOC : `203.0.113.50` · Source : `sysupdate.c`.
- Entrée d'audit `SERVICE_START unit=systemd-sysupdate` également présente en mémoire.

→ La mémoire est **cohérente avec le disque** et prouve l'**exécution effective sous root** au moment de la capture.

**Analyse Volatility 3** (framework 2.28.2, profil ISF `debian-6.1.0-54-amd64.json` fourni, capture 19) :
- `linux.pstree.PsTree` : le processus **`sysupdate` (PID 315)** a pour **parent `systemd` (PID 1)** :
  ```
  0x...  1    1    0  systemd
  * 0x8cd408ca1840  315  315  1  sysupdate
  ```
  → confirmation **indépendante des strings** que l'implant a été **lancé par le service systemd au démarrage** (et non exécuté manuellement).
- `systemd` (PID 1) a pour heure de création **2026-10-21 08:59:41 UTC** = heure du dernier amorçage ; l'implant démarre juste après (SERVICE_START 09:00:09, cf. audit), cohérent avec le figement de la mémoire.
- `linux.pslist.PsList` : `sysupdate` listé en **PID 315, PPID 1, UID 0 / GID 0 (root)**, heure de création **2026-10-21 09:00:08.685703 UTC** :
  ```
  OFFSET (V)      PID  TID  PPID COMM       UID GID EUID EGID CREATION TIME
  0x8cd408ca1840  315  315  1    sysupdate  0   0   0    0    2026-10-21 09:00:08.685703 UTC
  ```
  → cette heure coïncide avec le `SERVICE_START` de l'audit (09:00:09) : le binaire est **démarré par le service sous root** au boot, et **toujours résident** au moment du figement.

## 8. Impact

Impact **confirmé** par les preuves :
- **Perte d'intégrité de l'hôte** : ajout d'un service et d'un binaire non standard sur le système.
- **Exécution de code sous UID 0** (processus `sysupdate`, confirmé disque + mémoire).
- **Persistance** après démarrage (`WantedBy=multi-user.target`) et **relance automatique** (`Restart=always`).
- **Capacité réseau** compilée dans le binaire + IOC codé en dur → exposition potentielle.
- **Exposition potentielle** des secrets locaux, comptes et fichiers accessibles à root.

Non démontré par les preuves (à traiter comme **risques**, pas comme faits) : l'exfiltration de données, le vol de mots de passe et une connexion C2 réussie.

## 9. Recommandations

_(à finaliser — éléments déjà collectés)_
- **Éradication** : supprimer l'unité `systemd-sysupdate.service` et son lien `multi-user.target.wants/`, le binaire `/usr/lib/systemd/.cache/sysupdate` et le verrou `/tmp/.X11-unix/.sysupd_lock` ; `systemctl daemon-reload` ; reconstruire le poste depuis une image saine (compromission root → confiance perdue).
- **Durcissement SSH** (capture 18 : config faible) : passer `PermitRootLogin no` et désactiver `PasswordAuthentication` (clés uniquement).
- **Moindre privilège** : réévaluer l'appartenance de `jdupont` au groupe `sudo`.
- **Sensibilisation / anti-phishing** : le vecteur est un leurre à double extension (`.pdf.exe`) ouvert par l'utilisateur → formation + filtrage des pièces jointes exécutables, masquage des extensions désactivé.
- **Détection** : surveiller la création d'unités systemd hors paquet (fichiers non-liens, propriétaire non-root dans `/etc/systemd/system`), les binaires dans des dossiers cachés sous `/usr/lib`, et les `SERVICE_START` d'unités inconnues.

## 10. Limites et niveau de confiance

- **Point d'entrée** : confiance élevée sur la *séquence* utilisateur (renommage + `xdg-open`), mais le `.exe` original absent empêche de prouver directement l'exécution → vecteur qualifié de **probable**.
- **IOC réseau `203.0.113.50`** : la présence de symboles socket/réseau prouve une *capacité*, pas une *connexion réussie* ni une exfiltration.
- **Dates MACB** du binaire/unité : partiellement artificielles (préparées tôt dans la séquence) ; elles ne fixent pas à elles seules l'heure d'exécution initiale, d'où la corrélation avec audit + mémoire.
- **Volatility** : le profil ISF fourni a permis `pslist`/`pstree` ; la corrélation disque + audit + mémoire fournit des preuves **convergentes et cohérentes**.
- Analyse menée **en lecture seule** (montage `ro,noload`), implant **jamais exécuté**, aucun IOC contacté.

## 11. Annexe — les 20 captures d'écran

_Suivi des captures fournies au prof. Sous chaque capture : n° de preuve, commande exécutée, source, empreinte, interprétation. Ne JAMAIS afficher /etc/shadow, clé privée SSH, mot de passe ou secret._

| # | Capture attendue | Statut |
|---|------------------|--------|
| 1 | Page Transfer.it montrant GROUPE D | ⚠️ à refaire/justifier (téléchargement déjà effectué) |
| 2 | Liste des trois preuves du groupe | ✅ |
| 3 | `ls -lh` des preuves | ✅ |
| 4 | `sha256sum -c` disque + mémoire = Réussi | ✅ |
| 5 | `mmls endpoint-b-disk.raw` | ✅ |
| 6 | `fsstat -o 262144 endpoint-b-disk.raw` | ✅ |
| 7 | Montage `ro,noload` + preuve lecture seule | ✅ |
| 8 | Arborescence `/etc/systemd/system` | ✅ |
| 9 | Contenu complet de `systemd-sysupdate.service` | ✅ |
| 10 | `stat` du service (naissance, modif, perms, propriétaire) | ✅ |
| 11 | `stat` du binaire caché | ✅ |
| 12 | SHA-256 et MD5 du binaire | ✅ |
| 13 | `file`, `readelf -h/-n`, BuildID | ✅ |
| 14 | `strings` : verrou, marqueur de build, IOC réseau | ✅ |
| 15 | Historique jdupont : renommage `.pdf.exe` + `xdg-open` | ✅ |
| 16 | Historique root : `BOOTED_AND_IMPLANT_OK` | ✅ |
| 17 | Journaux : `audit.log` (session root ttyS0 + SERVICE_START/STOP) — *pas d'auth.log (journald)* | ✅ |
| 18 | `/etc/passwd`, groupe sudo, SSH (secrets masqués) | ✅ |
| 19 | Volatility `pslist`/`pstree` : `sysupdate` PID 315 UID 0, parent systemd + corroboration strings | ✅ |
| 20 | Schéma chaîne d'attaque + tableau IOC avec niveaux de confiance | ✅ (dans le rapport, §5.4 + §6) |

> Note : garde tes 20 captures d'écran numérotées. Sous chacune, ajoute : **n° de preuve, commande exécutée, source, empreinte concernée, interprétation**. Ne **jamais** afficher `/etc/shadow`, une clé privée SSH, un mot de passe ou un secret.

## 12. Conclusion

L'hôte `cnd-endpoint01` a été **compromis au niveau root** via un implant persistant déguisé en service de mise à jour système (`systemd-sysupdate.service` → `/usr/lib/systemd/.cache/sysupdate`). La chaîne a été reconstituée **preuve par preuve** : point d'entrée probable par leurre à double extension visant `jdupont`, dépôt de l'implant, persistance par unité systemd activée au boot, exécution répétée sous UID 0 (confirmée par l'audit et par Volatility, PID 315), puis extinction de la machine. Les preuves ont été exploitées **en lecture seule**, sans jamais exécuter l'implant ni contacter l'IOC. L'impact confirmé est l'atteinte à l'intégrité et l'exécution root ; l'exfiltration de données n'est **pas** démontrée et reste un risque à traiter.

## 13. Vérification externe de l'IOC 203.0.113.50

Conformément au cadre du TP, **aucune requête réseau n'a été effectuée** vers l'IOC. Vérification documentaire hors ligne : `203.0.113.50` appartient au bloc **`203.0.113.0/24` = TEST-NET-3**, réservé par l'IANA à la **documentation** (RFC 5737). Ce bloc n'est **ni routable publiquement ni destiné à du trafic réel** : il s'agit d'une adresse d'exemple codée en dur dans le binaire (cohérent avec le marqueur de build `-edu` du TP), et non d'une infrastructure C2 réelle contactable.

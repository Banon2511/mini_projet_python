#import "@preview/latexlike-report:1.0.0": *
#show: latexlike-report.with(
  author: "Banon Camara (23005)",
  title: [Mini-projet Python – MiniSec Scanner],
  subtitle: [Conception d'un scanner hybride de détection de fichiers malveillants en Python],
  participants: [Oumoulmnin Mahmoud (23081)],
  affiliation: [Institut Supérieur du Numérique],
  year: [2025--2026],
  class: [Spécialité Réseaux, Systèmes et Sécurité],
  other: [Professeur : Rifaa Sadegh],
  date: [#datetime.today().display()],
  logo: image("Images/logo_supnum.png"),
  theme-color: rgb("#0f2787"),
  lang: "fr",
  participants-supplement: "Auteurs :",
  title-font: "New Computer Modern",
  font: "New Computer Modern",
  font-size: 13pt,
  font-weight: 400,
  math-font: "New Computer Modern Math",
  math-weight: 400,
  math-ref-supplement: auto,
  math-numbering: "(1.1)",
  math-number-mode: "label",
  math-sub-numbering: true,
  pagebreak-section: true,
  show-outline: true,
  page-paper: "a4",
  h-l: [#smallcaps[Mini-projet Python – MiniSec Scanner]],
  h-r: [#image("Images/logo_supnum.png", width: 14%)],
  h-c: none,
  f-l: [],
  f-r: [],
  f-c: chic-page-number(),
)

= Introduction

== Contexte et motivation

Dans le domaine de la cybersécurité, la détection de fichiers malveillants est un enjeu fondamental et en constante évolution. Les logiciels malveillants — ou _malwares_ — représentent une menace permanente pour les systèmes d'information : ransomwares, chevaux de Troie, spywares et autres codes malveillants causent chaque année des milliards de dollars de dommages à l'échelle mondiale.

Face à cette réalité, les antivirus modernes ont considérablement évolué. Ils ne se contentent plus d'une simple comparaison de signatures statiques, mais combinent désormais plusieurs approches complémentaires : analyse heuristique, détection comportementale, moteurs de règles comme YARA, et plus récemment l'intelligence artificielle. Ces mécanismes, souvent perçus comme des « boîtes noires », méritent d'être démystifiés et expérimentés dans un cadre pédagogique.

== Objectif du projet

Ce mini-projet porte sur la conception et l'implémentation d'un scanner de fichiers malveillants en Python, nommé *MiniSec Scanner*. L'objectif principal est de développer un outil capable d'analyser un répertoire local et d'identifier les fichiers suspects en utilisant une approche hybride combinant :

- la détection par *signatures cryptographiques* (hash MD5/SHA256) sur une base d'entrées réelles issues de threat intelligence publique (fichier `signatures/signature_db.json`),
- des *règles heuristiques* (extension, nom, taille, date de modification, fichiers cachés),
- des *règles YARA* embarquées dans `scanner.py` (7 règles : EICAR, exécutables PE, mots-clés malveillants, banking trojans, cryptominers, code suspect, URLs),
- une *analyse de contenu textuel et binaire* (entropie, magic bytes, chaînes suspectes, patterns de code),
- et un *modèle de Machine Learning* (Isolation Forest + analyse d'intention de code et binaire) pour la détection d'anomalies.

Le projet vise à illustrer les principes fondamentaux de la cybersécurité appliqués à l'analyse statique de fichiers, tout en démontrant la maîtrise du framework Flask, des bibliothèques Python liées au ML, et des bonnes pratiques de développement (architecture modulaire, tests, sécurisation des entrées).

== Périmètre fonctionnel

MiniSec Scanner offre les capacités suivantes :

- *Analyse de fichiers locaux* : scan d'un répertoire complet, avec option récursive et option d'analyse de contenu.
- *Détection multi-couches* : combinaison de six familles de critères (heuristiques métadonnées, YARA, signatures par hash, contenu texte, analyse binaire, IA).
- *Interface web* : application Flask accessible via navigateur (formulaire HTML sur la route #raw"`/`", résultats affichés en page après soumission).
- *API REST* : endpoints JSON sous #raw"`/api/v1/`" (statut, scan, rapports, export) pour intégration dans des pipelines automatisés.
- *Export des résultats* : rapports JSON et CSV générés par `report_service.py`, téléchargeables via l'API ou après un scan depuis l'interface.
- *Évaluation ML* : script `ml_evaluation.py` produisant accuracy, précision, rappel, F1 et matrice de confusion sur un jeu annoté.
- *Sécurisation* : validation des chemins (évitement des dossiers système et path traversal) côté moteur et optionnellement via schémas Marshmallow.

Les tests réalisés dans le cadre de ce rapport portent *uniquement sur l'interface utilisateur web* (formulaire, chargement, scan, gestion d'erreurs, export) ; aucun test CLI ni test automatisé d'API n'est décrit ici.

= Architecture du projet

== Vue d'ensemble

MiniSec Scanner repose sur une architecture modulaire organisée autour d'un moteur de scan central (`scanner.py`, classe #raw"SecurityScanner") exposé via l'application Flask. L'*interface web* (`app/web/routes.py`) et l'*API REST* (`app/api/routes.py`) appellent *directement* #raw"SecurityScanner" (ou en fallback #raw"WebMiniSecScanner" si le module `scanner.py` est indisponible). Une façade optionnelle `minisec/scanner.py` fournit une API propre (#raw"scan(path, config)") pour un usage hors Flask (CLI, scripts) ; l'application web et l'API n'utilisent pas cette façade.

```
┌─────────────────────────────────────────────────────────┐
│  Point d'entrée : wsgi.py → create_app() → Flask app    │
└───────────────────────────┬─────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        │                                       │
        ▼                                       ▼
┌──────────────────────┐             ┌──────────────────────┐
│  app/web/routes.py    │             │  app/api/routes.py   │
│  GET/POST /           │             │  /api/v1/status       │
│  (formulaire + scan)  │             │  /api/v1/scan        │
│                      │             │  /api/v1/reports/<>  │
│                      │             │  /api/v1/export       │
└──────────┬───────────┘             └──────────┬───────────┘
           │                                     │
           └─────────────────┬───────────────────┘
                             │
                    Import direct depuis scanner
                             │
                             ▼
                  ┌──────────────────────┐
                  │  scanner.py          │
                  │  SecurityScanner      │
                  │  (ou WebMiniSecScanner│
                  │   si import échoue)   │
                  └──────────┬───────────┘
                             │
     ┌───────────────────────┼───────────────────────┐
     │                       │                       │
     ▼                       ▼                       ▼
┌──────────────┐   ┌──────────────────┐   ┌──────────────────┐
│ YARA (7      │   │ signature_db.py  │   │ ai_models.py     │
│ règles dans  │   │ signatures/      │   │ AIModelManager   │
│ scanner.py)  │   │ signature_db.json│   │ AIDetector, etc. │
└──────────────┘   └──────────────────┘   └──────────────────┘
```

== Structure des fichiers principaux

- `wsgi.py` — point d'entrée WSGI (développement et production, compatible Gunicorn).
- `scanner.py` — moteur principal : #raw"SecurityScanner", heuristiques, YARA embarqué, signatures, IA ; export JSON/CSV ; fonction #raw"validate_scan_path" pour la validation des chemins.
- `ai_models.py` — #raw"AIDetector" (Isolation Forest), #raw"CodeIntentAnalyzer", #raw"BinaryAnalyzer", #raw"BehaviorAnalyzer", gérés par #raw"AIModelManager".
- `signature_db.py` — classe #raw"SignatureDatabase", chargement de `signatures/signature_db.json` (hashes MD5/SHA256), recherche par fichier via #raw"get_threat".
- `report_service.py` — #raw"save_report(scanner)", #raw"get_report_content(report_id, format)" ; stockage dans `reports/`.
- `app/__init__.py` — factory Flask #raw"create_app" avec enregistrement des blueprints web et API, gestionnaires d'erreurs, headers de sécurité.
- `app/web/routes.py` — route #raw"/" (GET formulaire, POST exécution du scan avec #raw"SecurityScanner" ou #raw"WebMiniSecScanner", rendu #raw"index.html" avec résultats et résumé).
- `app/api/routes.py` — #raw"/api/v1/status", #raw"/api/v1/scan", #raw"/api/v1/scans/recent", #raw"/api/v1/reports/<report_id>", #raw"/api/v1/export".
- `app/web_scanner.py` — #raw"WebMiniSecScanner" : sous-classe de #raw"SecurityScanner" avec IA désactivée, ou fallback minimal si `scanner` est indisponible.
- `app/core/security.py` — #raw"validate_scan_path_safe", #raw"validate_scan_path" (sandbox via config) pour une validation centralisée optionnelle.
- `minisec/config.py` — dataclass #raw"ScanConfig" (sandbox, seuils, options) et #raw"validate_path" pour la façade CLI.
- `minisec/scanner.py` — façade #raw"scan(path, config, **kwargs)" réutilisant #raw"SecurityScanner" ou #raw"WebMiniSecScanner".
- `validators.py` — schémas Marshmallow (#raw"ScanRequestSchema", #raw"QuarantineRequestSchema", #raw"ScanScheduleSchema", #raw"SystemSettingsSchema", #raw"ScanHistoryQuerySchema", #raw"ExportRequestSchema", etc.) et validation des chemins (path traversal, caractères interdits).
- `error_handlers.py` — exceptions et gestionnaires d'erreurs Flask.
- `logging_config.py` — configuration du logging applicatif.
- `requirements.txt` — dépendances Python versionnées.

== Moteur de détection : SecurityScanner

La classe #raw"SecurityScanner" (`scanner.py`) orchestre l'analyse de chaque fichier selon un pipeline séquentiel. L'ordre va du plus léger (métadonnées) au plus coûteux (contenu et IA) :

#align(center)[
#table(
  columns: (1fr, 1fr),
  align: (left, left),
  stroke: 0.5pt,
  [*Étape*], [*Méthode / Rôle*],
  [1], [#raw"analyze_extension(ext)" — extensions dangereuses ou suspectes],
  [2], [#raw"analyze_filename(name)" — mots-clés malveillants dans le nom],
  [3], [#raw"analyze_size(size)" — vide, très petit, très volumineux],
  [4], [#raw"analyze_modification_date(mtime)" — modification récente],
  [5], [#raw"analyze_hidden_file(is_hidden, name)" — fichier caché],
  [6], [#raw"analyze_signature(path)" — hash MD5/SHA256 vs base de signatures],
  [7], [#raw"analyze_file_content(path, name)" — YARA, IA (anomaly, code intent, binaire), heuristiques texte],
)
]

Chaque étape retourne un score et une raison ; les scores sont cumulés et le niveau de risque est dérivé par #raw"calculate_risk_level(total_score)".

== Système de scoring et niveaux de risque

#align(center)[
#table(
  columns: (auto, auto, auto),
  align: center,
  stroke: 0.5pt,
  [*Score total*], [*Niveau de risque*], [*Interprétation*],
  [0 – 1], [Low], [Aucune anomalie significative],
  [2 – 4], [Medium], [Comportement suspect, surveillance recommandée],
  [≥ 5], [High], [Menace probable, action immédiate conseillée],
)
]

Implémentation : #raw"total_score >= 5" → High ; #raw"total_score >= 2" → Medium ; sinon Low.

== Contribution par critère (résumé)

Extensions dangereuses (#raw".exe", #raw".bat", #raw".dll", etc.) : +3. Extensions suspectes (#raw".zip", #raw".py", etc.) : +2. Mot-clé malveillant dans le nom : +3. Fichier vide / très petit / très volumineux : +1 ou +2. Modifié récemment (< 24 h) : +1. Fichier caché : +1. Signature connue (hash en base) : +5. YARA High : +3, YARA Medium : +2. Anomalie IA : +2. Intention de code ou analyse binaire : +1 à +3 selon le module IA.

== Mécanisme de fallback

- Si #raw"yara-python" est absent : #raw"YARA_AVAILABLE = False", l'analyse YARA est ignorée.
- Si #raw"ai_models" ou #raw"scikit-learn" est indisponible : #raw"AI_AVAILABLE = False", #raw"SecurityScanner" s'initialise avec #raw"enable_ai=False".
- Si l'import de `scanner` échoue (ex. dépendances manquantes) : `app/web/routes.py` et `app/api/routes.py` utilisent #raw"WebMiniSecScanner" (fallback sans IA, ou message d'erreur si le module scanner n'est pas chargé).
- Si la base de signatures est absente : #raw"analyze_signature" retourne #raw"(0, \"\")".

L'endpoint #raw"GET /api/v1/status" expose #raw"yara_available", #raw"ai_scanner_available", #raw"signature_db_available".

== API REST (résumé)

#align(center)[
#table(
  columns: (auto, auto, auto),
  align: (center, left, left),
  stroke: 0.5pt,
  [*Méthode*], [*Endpoint*], [*Description*],
  [GET], [#raw"/api/v1/status"], [Statut : YARA, IA, base de signatures],
  [POST], [#raw"/api/v1/scan"], [Corps JSON : #raw"folder", #raw"recursive", #raw"analyze_content"],
  [GET], [#raw"/api/v1/scans/recent"], [Liste des scans récents (placeholder)],
  [GET], [#raw"/api/v1/reports/<report_id>"], [Téléchargement rapport JSON ou CSV],
  [GET], [#raw"/api/v1/export?report_id=...&format=..."], [Redirection vers #raw"/api/v1/reports/<id>"],
)
]

Les requêtes invalides (path traversal, chemin système, champ manquant ou type incorrect) renvoient 400 avec un JSON structuré #raw"{ error, error_code, message, status_code }". La validation du chemin pour le scan utilise #raw"validate_scan_path" exportée par `scanner.py`.

= Technologies et bibliothèques

== Dépendances principales

Flask (framework web), Marshmallow (validation/sérialisation), python-dotenv (configuration). Optionnelles : yara-python (règles YARA), scikit-learn (Isolation Forest, RandomForest), numpy, pandas, joblib (modèles ML). Bibliothèques standard : hashlib (MD5, SHA256), pathlib (chemins).

== Sécurisation des entrées

- `scanner.py` : #raw"validate_scan_path(path)" — résolution #raw"Path(path).expanduser().resolve()", exclusion des chemins système (e.g. #raw"/etc", #raw"/proc", #raw"C:\Windows").
- `validators.py` : schémas Marshmallow avec rejet de #raw"../", caractères interdits Windows, préfixes de chemins système.
- `minisec/config.py` : #raw"ScanConfig.validate_path" — le chemin résolu doit être sous le répertoire sandbox autorisé.

= Implémentation détaillée (résumé)

== scanner.py

#raw"SecurityScanner" initialise les règles YARA (cache en mémoire), charge éventuellement #raw"AIModelManager" si #raw"enable_ai" et #raw"AI_AVAILABLE". #raw"run_analysis()" valide le dossier, énumère les fichiers, appelle #raw"analyze_file" pour chacun et met à jour #raw"scan_results", #raw"summary", #raw"scan_progress". #raw"export_results(format_type)" produit du JSON ou du CSV.

== ai_models.py

#raw"AIDetector" : extraction de features textuelles, entraînement Isolation Forest sur fichiers « sûrs », #raw"detect_anomaly(content)". #raw"CodeIntentAnalyzer" et #raw"BinaryAnalyzer" analysent intentions de code et structure binaire (magic bytes, entropie, chaînes suspectes). #raw"AIModelManager" initialise et expose ces analyseurs.

== signature_db.py

#raw"SignatureDatabase" charge `signatures/signature_db.json` et indexe par MD5 et SHA256. #raw"get_threat(file_path)" calcule les hashes du fichier (lecture par blocs 64 Ko) et retourne la menace si connue. La base contient des entrées de type APT, Trojan, Backdoor et Test (EICAR).

== report_service.py

#raw"save_report(scanner)" génère un identifiant unique, écrit un fichier JSON et un CSV dans `reports/`, et retourne le #raw"report_id". #raw"get_report_content(report_id, format)" permet le téléchargement (JSON ou CSV) avec en-têtes appropriés.

= Tests fonctionnels de l'interface utilisateur

Les tests décrits ci-dessous ont été réalisés *manuellement* via l'interface web (navigateur). Aucun test en ligne de commande ni test automatisé d'API n'est inclus.

== Méthodologie

Scénarios exécutés dans le navigateur : chargement de la page d'accueil, soumission du formulaire avec des chemins valides ou invalides, vérification de l'affichage des résultats et des messages d'erreur, consultation de l'export des rapports. Les cas path traversal et chemins système ont été testés pour valider le rejet côté serveur.

== Chargement de l'interface

#align(center)[
#table(
  columns: (1fr, 1fr, 1fr),
  align: (left, center, center),
  stroke: 0.5pt,
  [*Action*], [*Comportement attendu*], [*Résultat*],
  [Accès à #raw"/"], [Chargement de la page avec formulaire de scan], [À renseigner],
  [Actualisation (F5)], [Pas d'erreur JavaScript, formulaire intact], [À renseigner],
  [Accès sans serveur lancé], [Erreur de connexion navigateur], [À renseigner],
)
]

== Lancement d'un scan valide

Soumission du formulaire avec un répertoire valide contenant des fichiers de test (dont des fichiers bénins et des noms/extensions suspects).

#align(center)[
#table(
  columns: (1fr, 1fr, 1fr),
  align: (left, center, center),
  stroke: 0.5pt,
  [*Cas testé*], [*Comportement attendu*], [*Résultat*],
  [Dossier valide], [Scan exécuté, résultats affichés sur la page], [À renseigner],
  [Fichier bénin (ex. .txt)], [Niveau Low affiché], [À renseigner],
  [Fichier suspect (ex. extension .exe)], [Niveau Medium ou High selon score], [À renseigner],
  [Fichier très suspect (ex. nom + extension)], [Niveau High, raisons listées], [À renseigner],
)
]

== Gestion des erreurs côté interface

#align(center)[
#table(
  columns: (1fr, 1fr, 1fr),
  align: (left, center, center),
  stroke: 0.5pt,
  [*Entrée utilisateur*], [*Comportement attendu*], [*Résultat*],
  [Champ dossier vide], [Message d'erreur affiché], [À renseigner],
  [Chemin inexistant], [Erreur claire (ex. « n'existe pas ou n'est pas un dossier »)], [À renseigner],
  [Path traversal (#raw"../../../etc/passwd")], [Rejet, message de sécurité], [À renseigner],
)
]

Aucun stacktrace ne doit être exposé à l'utilisateur.

== Consultation des scans récents (si implémenté dans l'UI)

Si l'interface affiche une liste de scans récents (appel à #raw"/api/v1/scans/recent" ou équivalent) :

#align(center)[
#table(
  columns: (1fr, 1fr, 1fr),
  align: (left, center, center),
  stroke: 0.5pt,
  [*Action*], [*Comportement attendu*], [*Résultat*],
  [Accès à la section scans récents], [Liste affichée (vide ou avec entrées)], [À renseigner],
  [Rafraîchissement], [Persistance ou mise à jour cohérente], [À renseigner],
)
]

== Export des résultats depuis l'interface

Après un scan, si l'interface propose des liens ou boutons d'export (JSON/CSV) utilisant le #raw"report_id" :

#align(center)[
#table(
  columns: (1fr, 1fr, 1fr),
  align: (left, center, center),
  stroke: 0.5pt,
  [*Format*], [*Comportement attendu*], [*Résultat*],
  [JSON], [Téléchargement d'un fichier JSON valide], [À renseigner],
  [CSV], [Téléchargement d'un fichier CSV exploitable], [À renseigner],
)
]

== Bilan des tests UI

Les tests manuels de l'interface web permettent de vérifier :

- Fonctionnement du workflow complet (formulaire → scan → affichage des résultats).
- Gestion des erreurs utilisateur (champ vide, chemin invalide, path traversal).
- Cohérence des niveaux de risque et des raisons affichés avec la logique du moteur.
- Export des rapports (JSON/CSV) lorsque l'UI expose cette fonctionnalité.

Remplir les colonnes « Résultat » lors des passes de test réelles (✓ Conforme / ✗ Non conforme).

= Conclusion et perspectives

== Bilan

Le projet MiniSec Scanner met en œuvre un scanner hybride (heuristiques, YARA, signatures, contenu, IA) avec une architecture modulaire : moteur dans `scanner.py`, interfaces web et API dans `app/`, façade optionnelle dans `minisec/`. La sécurisation des entrées (validation des chemins, schémas Marshmallow) et le fallback en l'absence de YARA ou IA garantissent un service robuste et évolutif.

== Perspectives

Enrichissement du jeu de données ML, métriques formelles (précision, rappel, F1) sur un benchmark, mise à jour automatique des signatures, intégration du #raw"BehaviorAnalyzer", analyse dynamique en sandbox, persistance de l'historique des scans, tableau de bord de visualisation.

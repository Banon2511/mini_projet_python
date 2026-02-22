# Rapport de Projet — MiniSec Scanner

**Analyseur de sécurité de fichiers — Rapport professionnel académique**

---

## Table des matières

0. [Contexte et problématique](#0-contexte-et-problématique)
1. [Introduction](#1-introduction)
2. [Architecture technique](#2-architecture-technique)
3. [Flux de données](#3-flux-de-données)
4. [Modules et dépendances](#4-modules-et-dépendances)
5. [Classes et API internes](#5-classes-et-api-internes)
6. [API REST — Contrat](#6-api-rest--contrat)
7. [Configuration et variables d'environnement](#7-configuration-et-variables-denvironnement)
8. [Algorithmes clés](#8-algorithmes-clés)
9. [Formats de fichiers](#9-formats-de-fichiers)
10. [Points d'extension pour développeurs](#10-points-dextension-pour-développeurs)
11. [Tests et exécution](#11-tests-et-exécution)
12. [Annexes](#12-annexes)
13. [Analyse critique](#13-analyse-critique)
14. [Perspectives d'amélioration](#14-perspectives-damélioration)
15. [Conclusion](#15-conclusion)

---

## 0. Contexte et problématique

La prolifération des logiciels malveillants (malware) constitue un enjeu majeur en cybersécurité. Les approches traditionnelles de détection reposent principalement sur :

- des **signatures statiques** (hashes connus),
- des **règles heuristiques**,
- des **moteurs de pattern-matching** (ex. YARA).

Cependant, ces méthodes présentent des limites face aux menaces modernes, notamment :

- **polymorphisme**,
- **obfuscation**,
- **malware inconnu** (zero-day).

L'objectif de MiniSec Scanner est d'explorer une approche **hybride**, combinant :

- Détection statique par signatures
- Analyse heuristique
- Détection comportementale simplifiée
- Modèles de Machine Learning (Isolation Forest)

Ce projet vise à démontrer la **faisabilité** d'un moteur d'analyse de sécurité modulaire, extensible et déployable en environnement web ou CLI.

---

## 1. Introduction

### 1.1 Vue d'ensemble

MiniSec Scanner est un outil Python de détection de menaces combinant :
- **Heuristiques** (extension, nom, taille, date)
- **YARA** (règles pattern-matching embarquées)
- **Base de signatures** (hashes MD5/SHA256)
- **Machine Learning** (scikit-learn : IsolationForest, TfidfVectorizer)

### 1.2 Modes d'exécution

| Mode | Point d'entrée | Usage |
|------|----------------|-------|
| Web | `python wsgi.py` ou `gunicorn wsgi:app` | Interface Flask (formulaire + API) |
| CLI | `python minisec_cli.py scan <path> [--recursive] [--ai]` | Scan direct en ligne de commande |

### 1.3 Positionnement par rapport aux solutions existantes

MiniSec Scanner ne prétend pas remplacer des solutions industrielles telles que :

- **ClamAV**
- **Windows Defender**
- **VirusTotal**

Ces solutions disposent :

- de bases de signatures massives,
- d'équipes de recherche dédiées,
- d'infrastructures distribuées.

MiniSec se positionne comme :

- un **moteur pédagogique**,
- un **démonstrateur d'architecture hybride**,
- une **base expérimentale** pour l'analyse statique et semi-comportementale.

---

## 2. Architecture technique

### 2.1 Vue globale

```
                    ┌──────────────────────────────────────────┐
                    │              Point d'entrée               │
                    │  wsgi.py  →  create_app()  →  app        │
                    └────────────────────┬─────────────────────┘
                                         │
         ┌───────────────────────────────┼───────────────────────────────┐
         │                               │                               │
         ▼                               ▼                               ▼
┌─────────────────┐           ┌─────────────────┐           ┌─────────────────┐
│   app/web/      │           │   app/api/      │           │   minisec_cli   │
│   routes.py     │           │   routes.py     │           │   (CLI)         │
│   (formulaire)  │           │   (REST v1)     │           │                 │
└────────┬────────┘           └────────┬────────┘           └────────┬────────┘
         │                             │                             │
         └─────────────────────────────┼─────────────────────────────┘
                                       │
                                       ▼
              ┌────────────────────────────────────────┐
              │     Choix du moteur de scan            │
              │  • scanner.SecurityScanner (IA+),      │
              │  • app.web_scanner.WebMiniSecScanner   │
              │    (fallback sans IA)                  │
              └────────────────────┬───────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         │                         │                         │
         ▼                         ▼                         ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ YARA (embarqué) │     │ signature_db.py │     │ ai_models.py    │
│ yara.compile()  │     │ SignatureDatabase│     │ AIModelManager  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### 2.2 Arborescence détaillée

```
mini_projet_python/
├── wsgi.py                    # Point d'entrée WSGI
├── config.py                  # Config Flask (Dev/Test/Prod)
├── app/
│   ├── __init__.py            # create_app() — factory Flask
│   ├── api/
│   │   ├── __init__.py        # register_routes() → Blueprint /api/v1
│   │   └── routes.py          # POST /scan, GET /status, GET /scans/recent
│   ├── web/
│   │   ├── __init__.py
│   │   └── routes.py          # GET/POST / (formulaire)
│   ├── web_scanner.py         # WebMiniSecScanner (fallback sans IA)
│   ├── core/
│   │   ├── config.py          # Réexport config
│   │   └── security.py        # validate_scan_path, validate_scan_path_safe
│   └── models/                # Réexport models (SQLAlchemy)
├── scanner.py                 # SecurityScanner (IA + YARA + signatures)
├── ai_models.py               # AIDetector, CodeIntentAnalyzer, BinaryAnalyzer
├── signature_db.py            # SignatureDatabase, get_signature_database()
├── models.py                  # ScanHistory, QuarantinedFile (SQLAlchemy)
├── minisec/
│   ├── __init__.py            # scan(), ScanConfig, SecurityScanner
│   ├── scanner.py             # Façade scan() appelant scanner.SecurityScanner
│   └── config.py              # ScanConfig (dataclass)
├── signatures/
│   └── signature_db.json      # Hashes MD5/SHA256 des menaces connues
├── templates/
│   └── index.html             # Formulaire + affichage résultats
└── tests/
    ├── conftest.py            # Fixtures pytest (client, sample_files_dir)
    ├── test_flask.py          # Tests API, validation, sécurité
    ├── test_scanner.py        # Tests SecurityScanner, validate_scan_path
    └── test_ai_models.py      # Tests modèles IA
```

---

## 3. Flux de données

### 3.1 Requête API → Réponse

```
Client                    app/api/routes           scanner.SecurityScanner
  │                              │                            │
  │  POST /api/v1/scan           │                            │
  │  {folder, recursive,         │                            │
  │   analyze_content}           │                            │
  ├─────────────────────────────>│                            │
  │                              │  validate_scan_path()      │
  │                              │  Path().resolve()          │
  │                              ├─────────┐                  │
  │                              │         │ OK               │
  │                              │<────────┘                  │
  │                              │  SecurityScanner(          │
  │                              │    path, recursive,        │
  │                              │    analyze_content,        │
  │                              │    enable_ai=True          │
  │                              │  )                         │
  │                              ├───────────────────────────>│
  │                              │                            │ run_analysis()
  │                              │                            │   validate_folder()
  │                              │                            │   scan_files()
  │                              │                            │   for f: analyze_file(f)
  │                              │                            │     → YARA, signatures, IA
  │                              │<───────────────────────────│
  │                              │  scan_results, summary     │
  │  JSON {success, results,     │                            │
  │        summary}              │                            │
  │<─────────────────────────────┤                            │
```

### 3.2 Analyse d'un fichier (SecurityScanner.analyze_file)

```
analyze_file(file_info)
    │
    ├── analyze_extension(ext)        → (score, reason)
    ├── analyze_filename(name)       → (score, reason)
    ├── analyze_size(size)           → (score, reason)
    ├── analyze_modification_date()  → (score, reason)
    ├── analyze_hidden_file()        → (score, reason)
    ├── analyze_signature(path)      → db.get_threat() → (5, reason) si match
    └── analyze_file_content()       →
            ├── YARA rules.match(path)  si analyze_content
            ├── AI: ai_manager.ai_detector.detect_anomaly()
            ├── AI: ai_manager.code_analyzer.analyze_code_intent()
            ├── AI: ai_manager.binary_analyzer.analyze_binary()
            └── Heuristiques (patterns eval, exec, system…)
    │
    └── total_score → calculate_risk_level()
            Low  : 0–1
            Medium: 2–4
            High : 5+
```

---

## 4. Modules et dépendances

### 4.1 Graphe d'import (simplifié)

```
wsgi.py
  └── app.create_app

app/__init__.py
  ├── app.core.config (get_config)
  ├── app.web.routes (register_web_routes)
  ├── app.api (register_routes)
  ├── error_handlers (setup_error_handlers)
  └── [optionnel] logging_config

app/api/routes.py
  ├── scanner (SecurityScanner, validate_scan_path)
  ├── signature_db (get_signature_database)
  ├── app.web_scanner (WebMiniSecScanner)  — fallback
  └── app.core.security (validate_scan_path_safe) — si scanner absent

app/web/routes.py
  ├── scanner (SecurityScanner)
  └── app.web_scanner (WebMiniSecScanner)

scanner.py
  ├── ai_models (AIModelManager)
  ├── signature_db (get_signature_database)
  └── yara

minisec/scanner.py
  ├── minisec.config (ScanConfig)
  └── scanner (SecurityScanner) ou app.web_scanner (fallback)
```

### 4.2 Fallbacks

- Si `scanner` n'est pas importable → `app.web_scanner.WebMiniSecScanner` (sans IA)
- Si `validate_scan_path` absent (scanner non chargé) → `app.core.security.validate_scan_path_safe`
- Si `ai_models` absent → `SecurityScanner.enable_ai = False`, pas d'appel aux modèles IA

---

## 5. Classes et API internes

### 5.1 SecurityScanner (`scanner.py`)

```python
class SecurityScanner:
    def __init__(self, folder_path: str, recursive: bool = True,
                 analyze_content: bool = True, enable_ai: bool = True):
        # Initialise AIModelManager si enable_ai et ai_models disponible

    def validate_folder(self) -> Tuple[bool, str]:
        # Vérifie existence, type dossier, droits lecture

    def scan_files(self) -> List[Dict]:
        # os.walk ou os.listdir → liste de {name, path, size, extension, mtime, is_hidden}

    def analyze_file(self, file_info: Dict) -> Dict:
        # Agrège extension, nom, taille, date, hidden, signature, contenu (YARA + IA)
        # Retourne {name, path, size, risk_level, score, reasons, ...}

    def run_analysis(self) -> Tuple[bool, str]:
        # validate_folder → scan_files → analyze_file pour chaque fichier
        # Remplit scan_results, summary, total_files
```

**Constantes importantes :**

- `HIGH_RISK_EXTENSIONS`: `.exe`, `.bat`, `.dll`, `.ps1`, etc.
- `MEDIUM_RISK_EXTENSIONS`: `.zip`, `.py`, `.sh`, etc.
- `SUSPICIOUS_KEYWORDS`: crack, virus, malware, trojan, etc.
- `VERY_LARGE_SIZE`: 50 Mo

### 5.2 WebMiniSecScanner (`app/web_scanner.py`)

- Sous-ensemble de `SecurityScanner` sans IA.
- Même interface : `run_analysis()`, `scan_results`, `summary`, `total_files`.
- Utilisé quand `scanner.SecurityScanner` n'est pas disponible.

### 5.3 SignatureDatabase (`signature_db.py`)

```python
class SignatureDatabase:
    def __init__(self, db_path: Optional[Path] = None):
        # Charge signatures/signature_db.json

    def load(self) -> bool:
        # Parse JSON, indexe par MD5 et SHA256

    def get_threat(self, file_path: str) -> Optional[dict]:
        # Calcule MD5 + SHA256 du fichier, cherche dans les index
        # Retourne {name, type, description} ou None
```

### 5.4 AIModelManager (`ai_models.py`)

- `AIDetector`: IsolationForest + TfidfVectorizer pour détection d'anomalies
- `CodeIntentAnalyzer`: analyse d'intention de code (script)
- `BinaryAnalyzer`: analyse de binaires
- `BehaviorAnalyzer`: comportement
- `AIModelManager.initialize_models()`: charge les modèles depuis `models/`

### 5.5 validate_scan_path (`scanner.py`)

```python
def validate_scan_path(path: str) -> bool:
    # 1. Résout le chemin (Path(path).expanduser().resolve())
    # 2. Vérifie qu'il ne démarre pas par un chemin dangereux :
    #    /etc, /boot, /dev, C:\Windows, C:\Program Files, etc.
    # 3. Retourne False si chemin sensible, True sinon
```

---

## 6. API REST — Contrat

### 6.1 GET /api/v1/status

**Réponse 200 :**

```json
{
  "yara_available": true,
  "ai_scanner_available": true,
  "signature_db_available": true,
  "version": "1.0",
  "status": "ready"
}
```

### 6.2 POST /api/v1/scan

**Requête :**

```json
{
  "folder": "C:\\Users\\Documents\\test",   // requis
  "recursive": true,                         // défaut: false
  "analyze_content": true                    // défaut: false
}
```

**Réponse 200 (succès) :**

```json
{
  "success": true,
  "message": "Analyse terminée avec succès",
  "results": [
    {
      "name": "fichier.exe",
      "path": "C:\\Users\\...\\fichier.exe",
      "size": 1024,
      "risk_level": "High",
      "reasons": ["Extension dangereuse: .exe", "Motif malveillant détecté: virus"],
      "score": 6,
      "extension": ".exe"
    }
  ],
  "summary": {
    "total_files": 10,
    "analyzed_files": 10,
    "high": 2,
    "medium": 3,
    "low": 5,
    "folder": "C:\\Users\\Documents\\test",
    "recursive": true,
    "analyze_content": true,
    "yara_available": true,
    "ai_available": true,
    "report_id": "20250221_123456_abc123"   // ID pour télécharger le rapport
  }
}
```

**Réponse 400 (erreur) :**

```json
{
  "error": true,
  "error_code": "VALIDATION_ERROR",
  "message": "Paramètre 'folder' manquant",
  "status_code": 400
}
```

Codes d'erreur : `VALIDATION_ERROR`, `SCAN_ERROR`, `NOT_FOUND`.

### 6.3 GET /api/v1/scans/recent

Retourne `[]` (placeholder, pas de persistance).

### 6.4 GET /api/v1/reports/<report_id>

Télécharge un rapport de scan (JSON ou CSV).

**Paramètres :** `format=json` | `csv` (défaut: json)

**Exemple :** `GET /api/v1/reports/20250221_123456_abc123?format=json` → téléchargement du fichier.

---

## 7. Configuration et variables d'environnement

### 7.1 Fichier `config.py`

| Clé | Classe | Valeur par défaut | Description |
|-----|--------|-------------------|-------------|
| `SECRET_KEY` | Config | `'dev-secret-key-...'` | Clé Flask |
| `MAX_CONTENT_LENGTH` | Config | 100 Mo | Taille max requête |
| `MAX_FILES_PER_SCAN` | Config | 10000 | Limite de fichiers par scan |
| `MAX_FILE_SIZE` | Config | 50 Mo | Taille max par fichier |
| `SCAN_SANDBOX` | Config | `scan_sandbox/` | Sandbox (optionnel) |
| `SQLALCHEMY_DATABASE_URI` | Config | `sqlite:///scanner.db` | Connexion DB |
| `LOG_LEVEL` | Config | `INFO` | Niveau de log |
| `RATELIMIT_DEFAULT` | Config | `100 per hour` | Limite de requêtes |

### 7.2 Variables d'environnement

| Variable | Usage |
|----------|-------|
| `FLASK_ENV` | `development` / `production` / `testing` |
| `SECRET_KEY` | Clé secrète en production |
| `DATABASE_URL` | Connexion PostgreSQL (ex. Docker) |
| `LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING` |

### 7.3 Environnements

- **DevelopmentConfig** : DEBUG=True, RATELIMIT permissif
- **TestingConfig** : SQLite en mémoire, RATELIMIT désactivé
- **ProductionConfig** : DEBUG=False, rate limiting strict

---

## 8. Algorithmes clés

### 8.1 Calcul du score et du risque

```python
# Chaque analyse retourne (score, reason)
total_score = ext_score + name_score + size_score + mtime_score + hidden_score + content_score

if total_score >= 5:  risk_level = "High"
elif total_score >= 2: risk_level = "Medium"
else:                 risk_level = "Low"
```

### 8.2 Contribution par critère

| Critère | Score | Condition |
|---------|-------|-----------|
| Extension dangereuse | +3 | .exe, .bat, .dll, … |
| Extension suspecte | +2 | .zip, .py, .sh, … |
| Mot-clé dans nom | +3 | crack, virus, malware, … |
| Fichier vide | +1 | size == 0 |
| Fichier très petit | +1 | size < 10 o |
| Fichier très volumineux | +2 | size > 50 Mo |
| Modifié récemment | +1 | < 24 h |
| Fichier caché | +1 | nom commence par . |
| Signature connue | +5 | hash dans signature_db |
| YARA match | +1 à +3 | selon meta.threat_level |
| IA anomaly | +2 | si détecté |

### 8.3 Validation des chemins

```python
# scanner.validate_scan_path()
resolved = Path(path).expanduser().resolve()
dangerous = ['/etc', '/bin', '/usr', 'C:\\Windows', 'C:\\Program Files', ...]
for d in dangerous:
    if resolved.startswith(d): return False
return True
```

### 8.4 Justification des choix algorithmiques

**Heuristiques**

Les heuristiques (extension, nom, taille, date) permettent une détection rapide et peu coûteuse en ressources. Elles constituent une première couche de filtrage.

**YARA**

L'utilisation de YARA permet :

- la détection de motifs binaires,
- l'analyse textuelle,
- l'implémentation de règles flexibles et extensibles.

**Base de signatures**

La comparaison par hash (MD5/SHA256) garantit :

- une détection exacte des menaces connues,
- un faible taux de faux positifs.

*Limite* : inefficace contre les variantes modifiées.

**Isolation Forest**

Le modèle Isolation Forest a été choisi car :

- adapté à la détection d'anomalies,
- efficace sans dataset labellisé massif,
- faible coût computationnel.

Il permet d'identifier des fichiers atypiques par rapport à un ensemble de fichiers supposés légitimes.

---

## 9. Formats de fichiers

### 9.1 signature_db.json

```json
{
  "version": "1.0",
  "signatures": [
    {
      "md5": "44d88612fea8a8f36de82e1278abb02f",
      "sha256": "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd7827",
      "name": "EICAR-Test",
      "type": "Test",
      "description": "Fichier de test antivirus"
    }
  ]
}
```

- Au moins `md5` ou `sha256` (minuscules).
- Le scanner calcule les hashes du fichier et cherche dans ces index.

---

## 10. Points d'extension pour développeurs

### 10.1 Ajouter une règle YARA

Dans `scanner.py` ou `app/web_scanner.py`, modifier `YARA_RULES` :

```python
YARA_RULES = r"""
rule Ma_Regle {
    meta:
        description = "Ma description"
        threat_level = "High"
    strings:
        $s1 = "mon_pattern"
    condition:
        $s1
}
"""
```

### 10.2 Ajouter une signature

Éditer `signatures/signature_db.json` et ajouter une entrée avec `md5` et/ou `sha256`.

### 10.3 Ajouter un critère d'analyse

Dans `SecurityScanner` ou `WebMiniSecScanner` :

1. Créer `analyze_mon_critere(self, ...) -> Tuple[int, str]`
2. L'appeler dans `analyze_file()` et additionner le score aux raisons.

### 10.4 Nouvelle route API

1. Ajouter une fonction dans `app/api/routes.py`
2. L'enregistrer sur le blueprint : `@bp.route("/ma-route", methods=["POST"])`
3. L'URL sera `/api/v1/ma-route`

---

## 11. Tests et exécution

### 11.1 Lancer l'application

```bash
# Développement (port 5000)
python wsgi.py

# Production
gunicorn wsgi:app --bind 0.0.0.0:5000 --workers 4
```

### 11.2 Lancer les tests

```bash
pytest tests/ -v
pytest tests/test_flask.py -v -k "scan"
```

### 11.3 CLI

```bash
python minisec_cli.py scan ./mon_dossier --recursive --ai
python minisec_cli.py scan . --recursive --ai --json
```

---

## 12. Annexes

### A. Règles YARA embarquées

- `EICAR_Test_File` : fichier test EICAR
- `Windows_Executable` : signature MZ (PE)
- `Suspicious_Keywords` : crack, virus, malware, etc.
- `Banking_Malware` : paypal, chase, banking
- `Crypto_Miner` : bitcoin, monero, hashrate
- `Suspicious_Code` : eval, exec, system, shell_exec
- `Suspicious_URLs` : http/https

### B. Dépendances Python principales

```
Flask, Flask-SQLAlchemy, Flask-Limiter, Flask-Caching
yara-python
scikit-learn, numpy, pandas, joblib
marshmallow
gunicorn, python-dotenv
pytest, pytest-flask
```

### C. Références

- [YARA](https://yara.readthedocs.io/)
- [EICAR](https://www.eicar.org/)
- [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)
- [Flask](https://flask.palletsprojects.com/)

---

## 13. Analyse critique

### 13.1 Forces du système

- **Architecture modulaire** : séparation claire des responsabilités (web, API, moteur, modèles)
- **Détection hybride multi-couches** : heuristiques, YARA, signatures, ML
- **Fallback sécurisé** en absence d'IA (WebMiniSecScanner)
- **Déploiement Docker** possible
- **Tests automatisés** (pytest, fixtures)

### 13.2 Limites techniques

- **Dataset d'entraînement limité et artificiel**
- **Absence de sandbox d'exécution réelle**
- **Pas de mesure formelle du taux de faux positifs**
- **Score heuristique empirique** (pondérations non optimisées)
- **Base de signatures réduite** par rapport aux solutions industrielles

### 13.3 Risques potentiels

- **Faux positifs** sur scripts légitimes (développement, outils système)
- **Faux négatifs** sur malware obfusqué ou polymorphe
- **Dépendance aux règles embarquées** (non mises à jour automatiquement)

---

## 14. Perspectives d'amélioration

Plusieurs axes d'amélioration peuvent être envisagés :

- **Intégration d'un dataset malware réel** pour l'entraînement des modèles IA
- **Mesure formelle des métriques** (precision, recall, F1-score) sur un benchmark
- **Mise en place d'un système de pondération configurable** pour les scores heuristiques
- **Intégration d'une sandbox isolée** pour l'analyse comportementale
- **Exposition de métriques Prometheus** pour le monitoring
- **Mise à jour automatique des signatures** depuis des feeds threat intelligence

---

## 15. Conclusion

MiniSec Scanner démontre la **faisabilité** d'un moteur d'analyse de sécurité hybride combinant :

- détection statique,
- heuristiques,
- règles YARA,
- Machine Learning.

Bien qu'il ne puisse rivaliser avec des solutions industrielles, il constitue :

- une **base expérimentale solide**,
- un **démonstrateur d'architecture sécurisée**,
- un **outil pédagogique avancé**.

Le projet met en évidence les défis liés à la détection des menaces modernes et souligne l'importance d'**approches multi-couches** en cybersécurité.

---

*Rapport professionnel MiniSec Scanner — Usage pédagogique et académique*

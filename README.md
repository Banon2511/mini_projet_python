# MiniSec Scanner - Analyseur de Sécurité de Fichiers

![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)
![License](https://img.shields.io/badge/license-Educational%20Use-green.svg)
![Status](https://img.shields.io/badge/status-Production%20Ready-brightgreen.svg)

## 📋 Description

MiniSec Scanner est un outil pédagogique de cybersécurité développé en Python permettant d'analyser des fichiers pour détecter des menaces potentielles. Conçu pour l'éducation, il combine des techniques d'analyse heuristiques avec le moteur YARA pour une détection avancée de malware.

### 🎯 Objectifs Pédagogiques

- Comprendre les principes de l'analyse de sécurité
- Apprendre les techniques de détection de malware
- Maîtriser l'analyse de fichiers et de signatures
- Explorer les outils professionnels de cybersécurité (YARA)

## ✨ Fonctionnalités

### 🔍 Analyse Multi-Critères
- **Analyse d'extension** : Identification des extensions dangereuses (.exe, .bat, .dll, etc.)
- **Analyse de nom** : Détection de mots-clés suspects (virus, malware, crack, etc.)
- **Analyse de taille** : Détection d'anomalies de taille (fichiers vides, très volumineux)
- **Analyse de contenu** : Scan profond avec YARA et heuristiques

### 🛡️ Moteur de Détection
- **YARA intégré** : Moteur professionnel de détection de malware
- **Signatures embarquées** : Règles YARA pour menaces courantes
- **Analyse binaire** : Détection d'exécutables Windows/Linux
- **Analyse textuelle** : Recherche de code suspect et d'URLs

### 📊 Rapports Détaillés
- **Affichage console** : Interface colorée et structurée
- **Rapports texte** : Génération automatique de rapports détaillés
- **Classification des risques** : Niveaux Low/Medium/High avec justification
- **Métriques complètes** : Statistiques détaillées de l'analyse

## 🚀 Installation

### Prérequis

```bash
# Python 3.x requis
python --version

# Installation optionnelle de YARA (recommandé)
pip install yara-python
```

### Configuration

1. Clonez ou téléchargez le projet
2. Placez-vous dans le répertoire du projet
3. (Optionnel) Installez YARA pour des analyses avancées

```bash
git clone <repository-url>
cd mini_project_python
pip install yara-python  # Optionnel mais recommandé
```

## 📖 Utilisation

### Lancement du Scanner

```bash
python MiniSec_Scanner.py
```

### Interface Interactive

Le scanner vous guidera à travers plusieurs étapes :

1. **Sélection du dossier** : Chemin du dossier à analyser
2. **Options de scan** : 
   - Scan récursif (sous-dossiers)
   - Analyse de contenu approfondie
3. **Exécution** : Lancement automatique de l'analyse
4. **Rapport** : Génération optionnelle d'un rapport détaillé

### Exemple d'Utilisation

```
╔═══════════════════════════════════════════════════════════════════════╗
║              [ Analyseur de Sécurité de Fichiers v1.0 ]          ║
╚═══════════════════════════════════════════════════════════════════════╝

[?] Entrez le chemin du dossier : /home/user/documents
[?] Activer le scan récursif ? (o/n) : o
[?] Activer l'analyse de contenu approfondie ? (o/n) : o
```

## 📁 Structure du Projet

```
mini_project_python/
├── MiniSec_Scanner.py          # Scanner principal
├── create_test_files.py        # Générateur de fichiers de test
├── yara_test_generator.py      # Générateur de tests YARA
├── fichier_test.txt            # Fichier de test d'exemple
├── rules/                      # Règles YARA
│   ├── malware_rules.yar       # Règles de base
│   └── enhanced_malware_rules.yar  # Règles avancées
├── __pycache__/                # Cache Python
├── rapport_minisec_*.txt       # Rapports générés
└── README.md                   # Ce fichier
```

## 🔧 Configuration Avancée

### Personnalisation des Règles YARA

Les règles YARA sont définies dans la classe `MiniSecScanner` :

```python
YARA_RULES = """
rule EICAR_Test_File {
    meta:
        description = "Standard antivirus test file"
        threat_level = "Medium"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
"""
```

### Extension des Critères d'Analyse

Pour ajouter de nouvelles extensions dangereuses :

```python
HIGH_RISK_EXTENSIONS = {'.exe', '.bat', '.cmd', '.com', '.scr', '.vbs', 
                       '.js', '.jar', '.ps1', '.msi', '.dll', '.sys', '.cpl'}
```

### Ajout de Mots-Clés Suspects

```python
SUSPICIOUS_KEYWORDS = ['crack', 'virus', 'malware', 'password', 'hack',
                      'trojan', 'keylog', 'ransom', 'exploit', 'backdoor']
```

## 🧪 Tests et Validation

### Génération de Fichiers de Test

```bash
# Fichiers de test basiques
python create_test_files.py

# Fichiers de test YARA avancés
python yara_test_generator.py
```

### Scénarios de Test

1. **Test normal** : Dossier avec fichiers standards
2. **Test avec menaces** : Dossier avec fichiers suspects
3. **Test YARA** : Validation des signatures YARA
4. **Test performance** : Gros volumes de fichiers

### Résultats Attendus

| Type de Fichier | Niveau de Risque Attendu | Justification |
|-----------------|-------------------------|---------------|
| `document.txt` | Low | Fichier standard |
| `program.exe` | Medium | Extension exécutable |
| `crack_tool.exe` | High | Extension + nom suspect |
| `eicar_test.txt` | Medium | Signature EICAR détectée |

## 📊 Métriques et Performance

### Niveaux de Risque

- **Low (0-1 point)** : Fichiers standards ou anomalies mineures
- **Medium (2-4 points)** : Extensions suspectes ou contenu modéré
- **High (5+ points)** : Menaces claires ou combinaisons de risques

### Facteurs de Scoring

| Critère | Points | Description |
|----------|--------|-------------|
| Extension dangereuse | +3 | .exe, .dll, .bat, etc. |
| Extension suspecte | +2 | .zip, .py, .sh, etc. |
| Mot-clé dans nom | +3 | virus, malware, crack, etc. |
| Taille anormale | +1-2 | Vide, très petit, très grand |
| Fichier caché | +1 | Fichiers commençant par . |
| Détection YARA | +1-3 | Selon niveau de menace |
| Contenu suspect | +2 | Code malveillant, URLs |

## 🛠️ Développement et Maintenance

### Architecture du Code

```python
class MiniSecScanner:
    ├── __init__()              # Initialisation
    ├── validate_folder()       # Validation du dossier
    ├── scan_files()           # Énumération des fichiers
    ├── analyze_file()         # Analyse complète
    ├── analyze_extension()    # Analyse d'extension
    ├── analyze_filename()     # Analyse de nom
    ├── analyze_size()         # Analyse de taille
    ├── analyze_file_content() # Analyse de contenu
    ├── calculate_risk_level() # Calcul du risque
    ├── display_results()      # Affichage console
    └── generate_report()      # Génération de rapport
```

### Bonnes Pratiques

- **Code modulaire** : Fonctions réutilisables et bien nommées
- **Gestion d'erreurs** : Try/except pour toutes les opérations
- **Documentation** : Docstrings et commentaires explicatifs
- **Performance** : Cache YARA et limitation de l'analyse
- **Sécurité** : Jamais d'exécution ou modification de fichiers

### Extensibilité

Le projet est conçu pour être facilement extensible :

1. **Ajout de nouvelles règles YARA**
2. **Extension des critères d'analyse**
3. **Ajout de nouveaux formats de rapport**
4. **Intégration d'autres moteurs de détection**

## 🔒 Considérations de Sécurité

### ⚠️ Limitations Pédagogiques

- **Outil éducatif uniquement** : Non destiné à un usage en production
- **Faux positifs possibles** : Basé sur des heuristiques simples
- **Pas de quarantaine** : Détection sans action automatique

### 🛡️ Mesures de Sécurité

- **Lecture seule** : Jamais de modification des fichiers analysés
- **Pas d'exécution** : Aucun code n'est exécuté
- **Isolation** : Analyse locale sans connexion réseau
- **Permissions** : Vérification des droits d'accès

## 📈 Évolution et Améliorations

### Version Actuelle : v1.0

- ✅ Analyse multi-critères complète
- ✅ Intégration YARA fonctionnelle
- ✅ Interface française complète
- ✅ Rapports détaillés
- ✅ Tests et validation

### Roadmap Futur

- 🔄 **v1.1** : Interface graphique optionnelle
- 🔄 **v1.2** : Base de données de signatures étendue
- 🔄 **v1.3** : Analyse réseau et comportementale
- 🔄 **v2.0** : Architecture microservices

## 🤝 Contribution

### Comment Contribuer

1. Fork du projet
2. Création d'une branche de fonctionnalité
3. Implémentation des modifications
4. Tests et validation
5. Pull request avec description détaillée

### Normes de Code

- **PEP 8** : Style de code Python
- **Docstrings** : Documentation complète
- **Tests** : Validation systématique
- **Français** : Messages et documentation en français

## 📞 Support et Contact

### Documentation Complémentaire

- **Wiki du projet** : Documentation technique détaillée
- **Exemples** : Cas d'usage et scénarios
- **FAQ** : Questions fréquentes et dépannage

### Signalement de Problèmes

- **Bugs** : Issues GitHub avec description détaillée
- **Suggestions** : Améliorations et nouvelles fonctionnalités
- **Questions** : Support technique et pédagogique

## 📜 Licence

### Usage Éducatif

Ce projet est destiné à un usage pédagogique et éducatif. 

- ✅ **Apprentissage** : Écoles, universités, formations
- ✅ **Recherche** : Études en cybersécurité
- ✅ **Personnel** : Projets d'apprentissage individuels

### Restrictions

- ❌ **Commercial** : Usage commercial interdit
- ❌ **Production** : Non destiné à un environnement de production
- ❌ **Malveillant** : Toute utilisation malveillante est proscrite

## 🏆 Remerciements

### Développement

- **YARA Team** : Moteur de détection de malware open-source
- **Python Community** : Écosystème et bibliothèques
- **Security Researchers** : Signatures et connaissances partagées

### Inspiration

- **Antivirus Industry** : Techniques de détection professionnelles
- **Educational Projects** : Approches pédagogiques innovantes
- **Open Source** : Culture du partage et de la collaboration

---

**MiniSec Scanner v1.0 - Outil Pédagogique de Cybersécurité**

*Développé avec passion pour l'éducation en cybersécurité* 🚀

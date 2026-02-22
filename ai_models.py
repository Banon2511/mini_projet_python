"""
Modèles d'IA pour la détection avancée de menaces
"""
import os
import numpy as np
import pickle
import joblib
from typing import List, Dict, Tuple, Optional
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import logging

logger = logging.getLogger(__name__)


class AIDetector:
    """Détecteur basé sur Machine Learning pour les anomalies de fichiers"""
    
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.trained = False
        self.safe_features = None
        
    def extract_features(self, file_content: str) -> np.ndarray:
        """Extraire des caractéristiques du contenu du fichier"""
        features = []
        
        # Caractéristiques de base
        features.append(len(file_content))  # Longueur
        features.append(len(file_content.split()))  # Nombre de mots
        features.append(len(set(file_content.split())))  # Mots uniques
        features.append(file_content.count('\n'))  # Nombre de lignes
        features.append(file_content.count('\t'))  # Nombre de tabs
        
        # Caractéristiques de contenu
        features.append(len([c for c in file_content if c.isupper()]))  # Majuscules
        features.append(len([c for c in file_content if c.islower()]))  # Minuscules
        features.append(len([c for c in file_content if c.isdigit()]))  # Chiffres
        features.append(len([c for c in file_content if not c.isalnum()]))  # Caractères spéciaux
        
        # Caractéristiques de code
        suspicious_keywords = ['eval', 'exec', 'system', 'subprocess', 'os.system', 
                           'input', 'raw_input', '__import__', 'getattr', 'setattr']
        for keyword in suspicious_keywords:
            features.append(file_content.lower().count(keyword))
        
        # Caractéristiques réseau
        network_keywords = ['socket', 'requests', 'urllib', 'http', 'https', 'ftp']
        for keyword in network_keywords:
            features.append(file_content.lower().count(keyword))
        
        # Caractéristiques de chiffrement
        crypto_keywords = ['encrypt', 'decrypt', 'cipher', 'crypto', 'hash', 'md5', 'sha']
        for keyword in crypto_keywords:
            features.append(file_content.lower().count(keyword))
        
        return np.array(features)
    
    def train_on_safe_files(self, safe_files: List[str]) -> bool:
        """Entraîner sur des fichiers considérés comme sûrs"""
        try:
            all_features = []
            for file_path in safe_files:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    features = self.extract_features(content)
                    all_features.append(features)
                except Exception as e:
                    logger.warning(f"Failed to process {file_path}: {e}")
                    continue
            
            if len(all_features) < 10:
                logger.warning("Not enough safe files for training")
                return False
            
            # Normaliser les caractéristiques
            all_features = np.array(all_features)
            self.safe_features = all_features
            
            # Entraîner le modèle
            self.model.fit(all_features)
            self.trained = True
            
            logger.info(f"AI Detector trained on {len(all_features)} safe files")
            return True
            
        except Exception as e:
            logger.error(f"Training failed: {e}")
            return False
    
    def detect_anomaly(self, file_content: str) -> Tuple[bool, str, float]:
        """Détecter si le contenu est anormal"""
        if not self.trained:
            return False, "Model not trained", 0.0
        
        try:
            features = self.extract_features(file_content)
            features = features.reshape(1, -1)
            
            # Prédiction (-1 = anomalie, 1 = normal)
            prediction = self.model.predict(features)[0]
            
            # Score d'anomalie (plus bas = plus anormal)
            anomaly_score = self.model.decision_function(features)[0]
            
            # Convertir en confiance
            confidence = abs(anomaly_score)
            is_anomaly = prediction == -1
            
            # Ajuster le seuil de détection pour réduire les faux positifs
            if confidence < 0.1:  # Très faible anomalie = considérer comme normal
                is_anomaly = False
                confidence = 0.05
            
            if is_anomaly:
                reason = f"Anomaly detected with {confidence:.2%} confidence"
            else:
                reason = f"Normal content with {confidence:.2%} confidence"
            
            return is_anomaly, reason, confidence
            
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return False, f"Detection failed: {e}", 0.0
    
    def get_confidence(self) -> float:
        """Obtenir le niveau de confiance du modèle"""
        if not self.trained:
            return 0.0
        return 0.85  # Placeholder - pourrait être calculé dynamiquement
    
    def save_model(self, path: str) -> bool:
        """Sauvegarder le modèle entraîné"""
        try:
            model_data = {
                'model': self.model,
                'vectorizer': self.vectorizer,
                'safe_features': self.safe_features,
                'trained': self.trained
            }
            with open(path, 'wb') as f:
                pickle.dump(model_data, f)
            logger.info(f"Model saved to {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
            return False
    
    def load_model(self, path: str) -> bool:
        """Charger un modèle entraîné"""
        try:
            with open(path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.vectorizer = model_data['vectorizer']
            self.safe_features = model_data['safe_features']
            self.trained = model_data['trained']
            
            logger.info(f"Model loaded from {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False


class CodeIntentAnalyzer:
    """Analyseur d'intention de code avec NLP simplifié"""
    
    def __init__(self):
        self.malicious_patterns = {
            'file_deletion': [
                'os.remove', 'os.unlink', 'shutil.rmtree', 'delete', 'del ',
                'rm -rf', 'Remove-Item', 'File.Delete'
            ],
            'system_commands': [
                'os.system', 'subprocess.call', 'subprocess.run', 'exec(',
                'eval(', '__import__', 'getattr(', 'setattr('
            ],
            'network_activity': [
                'socket.socket', 'requests.get', 'requests.post', 'urllib',
                'http://', 'https://', 'ftp://', 'connect('
            ],
            'encryption_crypto': [
                'encrypt(', 'decrypt(', 'cipher', 'crypto', 'hashlib',
                'md5(', 'sha1(', 'sha256(', 'AES', 'RSA'
            ],
            'keylogging': [
                'keyboard', 'keylogger', 'GetAsyncKeyState', 'keyboard_hook',
                'key_down', 'key_up', 'keystroke', 'keydown', 'keyup',
                'addEventListener.*keydown', 'onkeydown', 'onkeypress',
                'document.addEventListener.*key', 'fetch.*log', 'POST.*key'
            ],
            'persistence': [
                'registry', 'startup', 'autorun', 'services', 'cron',
                'schtasks', 'launchd', 'systemd'
            ]
        }
    
    def analyze_code_intent(self, code_content: str) -> Dict:
        """Analyser l'intention du code"""
        code_lower = code_content.lower()
        
        detected_intents = []
        intent_details = {}
        
        for intent, keywords in self.malicious_patterns.items():
            matches = []
            for keyword in keywords:
                count = code_lower.count(keyword.lower())
                if count > 0:
                    matches.append({
                        'keyword': keyword,
                        'count': count,
                        'severity': self._get_keyword_severity(keyword)
                    })
            
            if matches:
                detected_intents.append(intent)
                intent_details[intent] = {
                    'matches': matches,
                    'total_count': sum(m['count'] for m in matches),
                    'max_severity': max(m['severity'] for m in matches)
                }
        
        # Calculer le score de risque
        risk_score = self._calculate_risk_score(intent_details)
        
        return {
            'detected_intents': detected_intents,
            'intent_details': intent_details,
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'is_suspicious': len(detected_intents) > 0
        }
    
    def _get_keyword_severity(self, keyword: str) -> float:
        """Déterminer la sévérité d'un mot-clé"""
        high_severity = ['os.system', 'subprocess', 'eval(', 'exec(']
        medium_severity = ['socket', 'requests', 'encrypt(', 'delete']
        
        if any(high in keyword.lower() for high in high_severity):
            return 1.0
        elif any(medium in keyword.lower() for medium in medium_severity):
            return 0.6
        else:
            return 0.3
    
    def _calculate_risk_score(self, intent_details: Dict) -> float:
        """Calculer le score de risque global"""
        if not intent_details:
            return 0.0
        
        total_score = 0.0
        for intent, details in intent_details.items():
            # Pondérer par le type d'intention
            intent_weight = {
                'file_deletion': 0.8,
                'system_commands': 1.0,
                'network_activity': 0.6,
                'encryption_crypto': 0.5,
                'keylogging': 1.0,
                'persistence': 0.9
            }.get(intent, 0.5)
            
            # Score basé sur le nombre et la sévérité
            intent_score = details['total_count'] * details['max_severity'] * intent_weight
            total_score += intent_score
        
        # Normaliser entre 0 et 1
        return min(total_score / 10.0, 1.0)
    
    def _get_risk_level(self, score: float) -> str:
        """Déterminer le niveau de risque"""
        if score >= 0.7:
            return "High"
        elif score >= 0.4:
            return "Medium"
        else:
            return "Low"


class BinaryAnalyzer:
    """Analyseur de fichiers binaires simplifié"""
    
    def __init__(self):
        self.known_signatures = {
            b'MZ': 'Windows PE',
            b'\x7fELF': 'Linux ELF',
            b'\xca\xfe\xba\xbe': 'Java class',
            b'\xfe\xed\xfa\xce': 'Mach-O binary',
            b'\xfe\xed\xfa\xcf': 'Mach-O binary'
        }
    
    def analyze_binary(self, file_path: str) -> Dict:
        """Analyser un fichier binaire"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(1024)  # Lire les premiers 1024 octets
            
            # Détecter le type de binaire
            file_type = self._detect_binary_type(header)
            
            # Analyser les caractéristiques
            entropy = self._calculate_entropy(header)
            suspicious_strings = self._find_suspicious_strings(header)
            
            # Calculer le score de risque
            risk_score = self._calculate_binary_risk(file_type, entropy, suspicious_strings)
            
            return {
                'file_type': file_type,
                'entropy': entropy,
                'suspicious_strings': suspicious_strings,
                'risk_score': risk_score,
                'risk_level': self._get_risk_level(risk_score),
                'is_executable': file_type in ['Windows PE', 'Linux ELF', 'Mach-O binary']
            }
            
        except Exception as e:
            logger.error(f"Binary analysis failed: {e}")
            return {
                'error': str(e),
                'risk_score': 0.0,
                'risk_level': 'Low'
            }
    
    def _detect_binary_type(self, header: bytes) -> str:
        """Détecter le type de fichier binaire"""
        for signature, file_type in self.known_signatures.items():
            if header.startswith(signature):
                return file_type
        return 'Unknown binary'
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculer l'entropie des données (mesure de randomisation)"""
        if not data:
            return 0.0
        
        # Compter les fréquences des octets
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        
        # Calculer les probabilités
        probabilities = byte_counts / len(data)
        probabilities = probabilities[probabilities > 0]
        
        # Calculer l'entropie de Shannon
        entropy = -np.sum(probabilities * np.log2(probabilities))
        
        return entropy
    
    def _find_suspicious_strings(self, data: bytes) -> List[str]:
        """Trouver des chaînes suspectes dans le binaire"""
        suspicious_strings = []
        
        # Convertir en chaîne pour la recherche
        try:
            data_str = data.decode('utf-8', errors='ignore')
        except:
            data_str = data.decode('latin-1', errors='ignore')
        
        # Patterns suspects
        suspicious_patterns = [
            'password', 'passwd', 'secret', 'key', 'token',
            'admin', 'root', 'privilege', 'escalate',
            'cmd.exe', 'powershell', 'bash', 'sh',
            'http://', 'https://', 'ftp://',
            '127.0.0.1', 'localhost', '0.0.0.0'
        ]
        
        for pattern in suspicious_patterns:
            if pattern.lower() in data_str.lower():
                suspicious_strings.append(pattern)
        
        return suspicious_strings
    
    def _calculate_binary_risk(self, file_type: str, entropy: float, 
                            suspicious_strings: List[str]) -> float:
        """Calculer le score de risque pour le binaire"""
        risk_score = 0.0
        
        # Risque basé sur le type
        type_risk = {
            'Windows PE': 0.6,
            'Linux ELF': 0.5,
            'Mach-O binary': 0.5,
            'Java class': 0.3,
            'Unknown binary': 0.8
        }
        risk_score += type_risk.get(file_type, 0.5)
        
        # Risque basé sur l'entropie (haute entropie = possible chiffrement/packing)
        if entropy > 7.0:  # Très haute entropie
            risk_score += 0.3
        elif entropy > 6.0:
            risk_score += 0.2
        
        # Risque basé sur les chaînes suspectes
        risk_score += len(suspicious_strings) * 0.1
        
        return min(risk_score, 1.0)
    
    def _get_risk_level(self, score: float) -> str:
        """Déterminer le niveau de risque"""
        if score >= 0.7:
            return "High"
        elif score >= 0.4:
            return "Medium"
        else:
            return "Low"


class BehaviorAnalyzer:
    """Analyseur comportemental simplifié"""
    
    def __init__(self):
        self.suspicious_sequences = {
            'file_operations': ['create', 'write', 'execute', 'delete'],
            'network_operations': ['connect', 'send', 'receive', 'listen'],
            'registry_operations': ['create_key', 'set_value', 'delete_key'],
            'process_operations': ['create', 'inject', 'terminate', 'suspend']
        }
    
    def analyze_behavior(self, file_operations: List[str]) -> Dict:
        """Analyser une séquence d'opérations"""
        if not file_operations:
            return {'risk_score': 0.0, 'risk_level': 'Low', 'patterns': []}
        
        detected_patterns = []
        risk_score = 0.0
        
        # Analyser les patterns suspects
        for pattern_name, operations in self.suspicious_sequences.items():
            pattern_count = sum(1 for op in file_operations if op in operations)
            if pattern_count > 1:
                detected_patterns.append({
                    'pattern': pattern_name,
                    'count': pattern_count,
                    'severity': self._get_pattern_severity(pattern_name)
                })
                risk_score += pattern_count * 0.2
        
        # Bonus pour les séquences rapides
        if len(file_operations) > 10:
            risk_score += 0.3
        
        return {
            'detected_patterns': detected_patterns,
            'total_operations': len(file_operations),
            'risk_score': min(risk_score, 1.0),
            'risk_level': self._get_risk_level(risk_score)
        }
    
    def _get_pattern_severity(self, pattern: str) -> float:
        """Déterminer la sévérité d'un pattern"""
        severity_map = {
            'file_operations': 0.6,
            'network_operations': 0.8,
            'registry_operations': 0.9,
            'process_operations': 1.0
        }
        return severity_map.get(pattern, 0.5)
    
    def _get_risk_level(self, score: float) -> str:
        """Déterminer le niveau de risque"""
        if score >= 0.7:
            return "High"
        elif score >= 0.4:
            return "Medium"
        else:
            return "Low"


class AIModelManager:
    """Gestionnaire centralisé pour les modèles IA"""
    
    def __init__(self):
        self.ai_detector = AIDetector()
        self.code_analyzer = CodeIntentAnalyzer()
        self.binary_analyzer = BinaryAnalyzer()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.models_loaded = False
    
    def initialize_models(self, models_path: str = 'models/') -> bool:
        """Initialiser ou charger les modèles IA"""
        import os
        
        try:
            os.makedirs(models_path, exist_ok=True)
            
            # Essayer de charger les modèles existants
            ai_model_path = os.path.join(models_path, 'ai_detector.pkl')
            
            if os.path.exists(ai_model_path):
                success = self.ai_detector.load_model(ai_model_path)
                if success:
                    logger.info("AI models loaded successfully")
                    self.models_loaded = True
                    return True
            
            # Entraîner sur des fichiers système par défaut
            logger.info("Training new AI models...")
            return self.train_default_models(models_path)
            
        except Exception as e:
            logger.error(f"Failed to initialize AI models: {e}")
            return False
    
    def train_default_models(self, models_path: str) -> bool:
        """Entraîner les modèles sur des fichiers par défaut"""
        try:
            # Chercher des fichiers sûrs dans le système
            safe_files = self._find_safe_files()
            
            if len(safe_files) < 10:
                logger.warning("Not enough safe files for training")
                return False
            
            # Entraîner le détecteur d'anomalies
            success = self.ai_detector.train_on_safe_files(safe_files)
            
            if success:
                # Sauvegarder le modèle
                model_path = os.path.join(models_path, 'ai_detector.pkl')
                self.ai_detector.save_model(model_path)
                self.models_loaded = True
                logger.info("AI models trained and saved successfully")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to train default models: {e}")
            return False
    
    def _find_safe_files(self) -> List[str]:
        """Trouver des fichiers considérés comme sûrs pour l'entraînement"""
        import os
        
        safe_files = []
        safe_extensions = ['.txt', '.md', '.py', '.js', '.html', '.css', '.json', '.xml']
        safe_directories = ['/usr/share/doc', '/usr/include', '/etc/ssl', 'C:\\Program Files\\Common Files']
        
        for directory in safe_directories:
            if os.path.exists(directory):
                try:
                    for root, dirs, files in os.walk(directory):
                        for file in files[:50]:  # Limiter pour éviter les temps trop longs
                            if any(file.endswith(ext) for ext in safe_extensions):
                                file_path = os.path.join(root, file)
                                try:
                                    if os.path.getsize(file_path) < 100 * 1024:  # < 100KB
                                        safe_files.append(file_path)
                                except:
                                    continue
                        if len(safe_files) >= 100:  # Assez pour l'entraînement
                            break
                except:
                    continue
                
                if len(safe_files) >= 100:
                    break
        
        # Ajouter quelques fichiers Python standards
        python_files = ['scanner.py', 'app.py', 'config.py', 'models.py']
        for file in python_files:
            if os.path.exists(file) and os.path.getsize(file) < 100 * 1024:
                safe_files.append(file)
        
        logger.info(f"Found {len(safe_files)} safe files for training")
        return safe_files[:100]  # Limiter à 100 fichiers
    
    def get_model_status(self) -> Dict:
        """Obtenir le statut des modèles IA"""
        return {
            'models_loaded': self.models_loaded,
            'ai_detector_trained': self.ai_detector.trained,
            'code_analyzer_ready': True,  # Toujours prêt (pas d'entraînement nécessaire)
            'binary_analyzer_ready': True,  # Toujours prêt
            'behavior_analyzer_ready': True   # Toujours prêt
        }

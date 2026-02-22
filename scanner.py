"""
Scanner de sécurité de fichiers - Logique métier séparée avec IA
"""
import os
import time
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from datetime import datetime

# Import des modèles IA
try:
    from ai_models import AIModelManager
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# Tentative d'import YARA - dépendance optionnelle
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# Base de signatures (hashes de menaces connues)
try:
    from signature_db import get_signature_database
    SIGNATURE_DB_AVAILABLE = True
except ImportError:
    get_signature_database = None
    SIGNATURE_DB_AVAILABLE = False

logger = logging.getLogger(__name__)


class SecurityScanner:
    """Scanner de sécurité de fichiers avancé"""
    
    # Embedded YARA rules - no external files needed (r"" pour préserver \s dans les regex)
    YARA_RULES = r"""
rule EICAR_Test_File {
    meta:
        description = "Standard antivirus test file"
        threat_level = "Medium"
        author = "EICAR"
        reference = "https://www.eicar.org"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule Windows_Executable {
    meta:
        description = "Windows PE executable"
        threat_level = "Medium"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule Suspicious_Keywords {
    meta:
        description = "Malicious keywords detection"
        threat_level = "High"
    strings:
        $keywords = /(crack|virus|malware|password|hack|trojan|keylog|ransom|exploit|backdoor|rootkit|payload|keygen)/i
    condition:
        $keywords
}

rule Banking_Malware {
    meta:
        description = "Banking trojan indicators"
        threat_level = "High"
    strings:
        $banking = /(paypal|chase|banking|credit.card|login.password)/i
    condition:
        $banking
}

rule Crypto_Miner {
    meta:
        description = "Cryptocurrency mining malware"
        threat_level = "High"
    strings:
        $crypto = /(bitcoin|monero|cryptonight|mining.pool|hashrate)/i
    condition:
        $crypto
}

rule Suspicious_Code {
    meta:
        description = "Suspicious code execution patterns"
        threat_level = "Medium"
    strings:
        $eval = /eval\s*\(/i
        $exec = /exec\s*\(/i
        $system = /system\s*\(/i
        $shell = /shell_exec\s*\(/i
    condition:
        any of them
}

rule Suspicious_URLs {
    meta:
        description = "Suspicious URL patterns"
        threat_level = "Low"
    strings:
        $http = /https?:\/\/[^\s]+/i
    condition:
        $http
}
"""
    
    # Threat signatures
    HIGH_RISK_EXTENSIONS = {'.exe', '.bat', '.cmd', '.com', '.scr', '.vbs', 
                           '.js', '.jar', '.ps1', '.msi', '.dll', '.sys', '.cpl'}
    MEDIUM_RISK_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.sh', 
                             '.py', '.rb', '.pl', '.php', '.vbs', '.wsf'}
    
    # Malicious patterns
    SUSPICIOUS_KEYWORDS = ['crack', 'virus', 'malware', 'password', 'hack',
                          'trojan', 'keylog', 'ransom', 'exploit', 'backdoor',
                          'rootkit', 'inject', 'payload', 'keygen', 'pirated',
                          'patch', 'serial', 'keymaker', 'loader', 'dropper']
    
    # Size thresholds
    EMPTY_FILE_SIZE = 0
    VERY_SMALL_SIZE = 10
    VERY_LARGE_SIZE = 50 * 1024 * 1024  # 50 MB
    
    # Time threshold
    RECENT_SECONDS = 24 * 60 * 60
    
    def __init__(self, folder_path: str, recursive: bool = True, analyze_content: bool = True, enable_ai: bool = True):
        """Initialize scanner with target path and options"""
        self.folder_path = folder_path
        self.recursive = recursive
        self.analyze_content = analyze_content
        self.enable_ai = enable_ai and AI_AVAILABLE
        
        # Résultats du scan
        self.scan_results = []
        self.summary = {'Low': 0, 'Medium': 0, 'High': 0}
        self.total_files = 0
        self.analyzed_files = 0
        self.start_time = None
        self.end_time = None
        self._yara_rules_cache = None
        self.scan_progress = 0
        self.scan_status = "initializing"
        
        # Initialiser les modèles IA
        if self.enable_ai:
            self.ai_manager = AIModelManager()
            self.ai_manager.initialize_models()
            logger.info("AI models initialized")
        else:
            self.ai_manager = None
            logger.info("AI disabled - using traditional analysis only")
        
        logger.info(f"Scanner initialized for folder: {folder_path}")
    
    def get_yara_rules(self) -> Optional[object]:
        """Get compiled YARA rules with caching"""
        if not YARA_AVAILABLE:
            logger.warning("YARA not available")
            return None
            
        if self._yara_rules_cache is None:
            try:
                self._yara_rules_cache = yara.compile(source=self.YARA_RULES)
                logger.info("YARA rules compiled successfully")
            except Exception as e:
                logger.error(f"YARA compilation error: {e}")
                self._yara_rules_cache = None
        
        return self._yara_rules_cache
    
    def validate_folder(self) -> Tuple[bool, str]:
        """Validate target directory"""
        logger.info(f"Validating folder: {self.folder_path}")
        
        if not os.path.exists(self.folder_path):
            return False, "Le chemin n'existe pas"
        
        if not os.path.isdir(self.folder_path):
            return False, "Ce n'est pas un dossier"
        
        if not os.access(self.folder_path, os.R_OK):
            return False, "Permission refusée"
        
        logger.info("Folder validation successful")
        return True, "Dossier validé"
    
    def scan_files(self) -> List[Dict]:
        """Enumerate files in target directory"""
        logger.info("Starting file enumeration")
        files_info = []
        
        try:
            if self.recursive:
                for dirpath, dirnames, filenames in os.walk(self.folder_path):
                    for filename in filenames:
                        self.total_files += 1
                        file_path = os.path.join(dirpath, filename)
                        file_info = self._get_file_info(file_path, filename)
                        if file_info:
                            files_info.append(file_info)
            else:
                for item in os.listdir(self.folder_path):
                    item_path = os.path.join(self.folder_path, item)
                    if os.path.isfile(item_path):
                        self.total_files += 1
                        file_info = self._get_file_info(item_path, item)
                        if file_info:
                            files_info.append(file_info)
                            
        except PermissionError as e:
            logger.error(f"Permission error during scan: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
        
        logger.info(f"File enumeration completed: {len(files_info)} files found")
        return files_info
    
    def _get_file_info(self, file_path: str, filename: str) -> Optional[Dict]:
        """Extract file metadata"""
        try:
            stat_info = os.stat(file_path)
            return {
                'name': filename,
                'path': file_path,
                'size': stat_info.st_size,
                'extension': os.path.splitext(filename)[1].lower(),
                'mtime': stat_info.st_mtime,
                'is_hidden': filename.startswith('.'),
                'created': stat_info.st_ctime
            }
        except OSError as e:
            logger.warning(f"Error getting file info for {file_path}: {e}")
            return None
    
    def analyze_extension(self, extension: str) -> Tuple[int, str]:
        """Analyze file extension for threats"""
        if extension in self.HIGH_RISK_EXTENSIONS:
            return (3, f"Extension dangereuse: {extension}")
        elif extension in self.MEDIUM_RISK_EXTENSIONS:
            return (2, f"Extension suspecte: {extension}")
        return (0, "")
    
    def analyze_filename(self, filename: str) -> Tuple[int, str]:
        """Pattern matching on filename"""
        filename_lower = filename.lower()
        found_keywords = []
        
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in filename_lower:
                found_keywords.append(keyword)
        
        if found_keywords:
            keywords_str = ', '.join(found_keywords)
            return (3, f"Motif malveillant détecté: {keywords_str}")
        
        return (0, "")
    
    def analyze_size(self, size: int) -> Tuple[int, str]:
        """Analyze file size anomalies"""
        if size == self.EMPTY_FILE_SIZE:
            return (1, "Fichier vide (0 octets)")
        elif size < self.VERY_SMALL_SIZE:
            return (1, f"Fichier anormalement petit ({size} octets)")
        elif size > self.VERY_LARGE_SIZE:
            size_mb = size / (1024 * 1024)
            return (2, f"Fichier anormalement volumineux ({size_mb:.1f} MB)")
        
        return (0, "")
    
    def analyze_modification_date(self, mtime: float) -> Tuple[int, str]:
        """Check for recent modifications"""
        if time.time() - mtime < self.RECENT_SECONDS:
            hours_ago = (time.time() - mtime) / 3600
            return (1, f"Modifié récemment ({hours_ago:.1f}h)")
        return (0, "")
    
    def analyze_hidden_file(self, is_hidden: bool, filename: str) -> Tuple[int, str]:
        """Detect hidden files"""
        if is_hidden:
            return (1, "Fichier caché détecté")
        return (0, "")

    def analyze_signature(self, file_path: str) -> Tuple[int, str]:
        """Vérifie si le fichier correspond à une signature connue (base de hashes)."""
        if not SIGNATURE_DB_AVAILABLE or not get_signature_database:
            return (0, "")
        try:
            db = get_signature_database()
            threat = db.get_threat(file_path)
            if threat:
                desc = threat.get("description", "")
                name = threat.get("name", "Menace connue")
                reason = f"Signature connue: {name}"
                if desc:
                    reason += f" — {desc}"
                return (5, reason)  # Score élevé = détection signature
        except Exception as e:
            logger.debug(f"Signature check failed for {file_path}: {e}")
        return (0, "")

    def analyze_file_content(self, file_path: str, filename: str) -> Tuple[int, List[str]]:
        """Analyse de contenu améliorée avec YARA et IA"""
        suspicious_lines = []
        score = 0
        
        # Analyse YARA si disponible et si l'analyse de contenu est activée
        if YARA_AVAILABLE and self.analyze_content:
            yara_rules = self.get_yara_rules()
            if yara_rules:
                try:
                    matches = yara_rules.match(file_path)
                    if matches:
                        for match in matches:
                            threat_level = match.meta.get('threat_level', 'Medium').lower()
                            if threat_level == 'high':
                                score += 3
                            elif threat_level == 'medium':
                                score += 2
                            suspicious_lines.append(f"YARA: {match.rule} - {match.meta.get('description', '')}")
                except Exception as e:
                    logger.warning(f"YARA analysis failed for {filename}: {e}")
        
        # Analyse IA si activée
        ai_analysis = {}
        code_analysis = None
        binary_analysis = None
        is_anomaly, confidence = False, 0.0
        if self.enable_ai and self.ai_manager:
            try:
                # Analyser le contenu avec les modèles IA (fichiers texte uniquement pour anomaly/code)
                content = ""
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                except (OSError, UnicodeDecodeError):
                    content = ""
                
                # 1. Détection d'anomalies (contenu texte)
                if content:
                    is_anomaly, anomaly_reason, confidence = self.ai_manager.ai_detector.detect_anomaly(content)
                    if is_anomaly:
                        score += 2
                        suspicious_lines.append(f"AI Anomaly: {anomaly_reason}")
                
                # 2. Analyse d'intention de code
                if content and filename.endswith(('.py', '.js', '.php', '.bat', '.sh', '.ps1')):
                    code_analysis = self.ai_manager.code_analyzer.analyze_code_intent(content)
                    if code_analysis.get('is_suspicious'):
                        score += int(code_analysis.get('risk_score', 0) * 3)
                        for intent in code_analysis.get('detected_intents', []):
                            suspicious_lines.append(f"AI Code Intent: {intent}")
                
                # 3. Analyse binaire pour les exécutables (ne pas ouvrir en texte)
                if filename.endswith(('.exe', '.dll', '.so', '.bin')):
                    binary_analysis = self.ai_manager.binary_analyzer.analyze_binary(file_path)
                    if binary_analysis.get('risk_score', 0) > 0.5:
                        score += int(binary_analysis.get('risk_score', 0) * 2)
                        suspicious_lines.append(f"AI Binary: {binary_analysis.get('file_type', 'Unknown')} with risk {binary_analysis.get('risk_score', 0):.2f}")
                
                ai_analysis = {
                    'anomaly_detected': is_anomaly,
                    'anomaly_confidence': confidence,
                    'code_analysis': code_analysis,
                    'binary_analysis': binary_analysis
                }
                
            except Exception as e:
                logger.warning(f"AI analysis failed for {filename}: {e}")
                ai_analysis = {'error': str(e)}
        
        # Analyse heuristique traditionnelle
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                # Patterns suspects
                suspicious_patterns = [
                    'eval(', 'exec(', 'system(', 'subprocess', 'os.system',
                    'base64', 'decode', 'encode', 'encrypt', 'decrypt',
                    'socket', 'connect', 'bind', 'listen', 'accept',
                    'registry', 'regedit', 'CreateProcess', 'ShellExecute'
                ]
                
                for i, line in enumerate(lines[:100]):  # Limiter à 100 premières lignes
                    for pattern in suspicious_patterns:
                        if pattern in line:
                            score += 1
                            suspicious_lines.append(f"Ligne {i+1}: {pattern}")
                            break  # Une seule détection par ligne
                
        except Exception as e:
            logger.debug(f"Content analysis failed for {filename}: {e}")
        
        # Ajouter l'analyse IA aux résultats
        if ai_analysis:
            suspicious_lines.append(f"AI Analysis: {ai_analysis}")
        
        return (score, suspicious_lines)
    
    def calculate_risk_level(self, total_score: int) -> str:
        """Calculate threat level"""
        if total_score >= 5:
            return 'High'
        elif total_score >= 2:
            return 'Medium'
        else:
            return 'Low'

    def analyze_file(self, file_info: Dict) -> Dict:
        """Analyse complète d'un fichier (extension, nom, taille, date, caché, signatures, contenu, IA)."""
        reasons = []
        total_score = 0

        ext_score, ext_reason = self.analyze_extension(file_info['extension'])
        total_score += ext_score
        if ext_reason:
            reasons.append(ext_reason)

        name_score, name_reason = self.analyze_filename(file_info['name'])
        total_score += name_score
        if name_reason:
            reasons.append(name_reason)

        size_score, size_reason = self.analyze_size(file_info['size'])
        total_score += size_score
        if size_reason:
            reasons.append(size_reason)

        mtime_score, mtime_reason = self.analyze_modification_date(file_info['mtime'])
        total_score += mtime_score
        if mtime_reason:
            reasons.append(mtime_reason)

        hidden_score, hidden_reason = self.analyze_hidden_file(
            file_info['is_hidden'], file_info['name']
        )
        total_score += hidden_score
        if hidden_reason:
            reasons.append(hidden_reason)

        sig_score, sig_reason = self.analyze_signature(file_info['path'])
        total_score += sig_score
        if sig_reason:
            reasons.append(sig_reason)

        if self.analyze_content:
            content_score, content_reasons = self.analyze_file_content(
                file_info['path'], file_info['name']
            )
            total_score += content_score
            if content_reasons:
                reasons.extend(content_reasons[:5])

        risk_level = self.calculate_risk_level(total_score)

        ai_info = {}
        if self.enable_ai and self.ai_manager:
            try:
                ai_info['models_status'] = self.ai_manager.get_model_status()
            except Exception as e:
                logger.warning(f"Failed to get AI status: {e}")

        return {
            'name': file_info['name'],
            'path': file_info['path'],
            'size': file_info['size'],
            'extension': file_info['extension'],
            'risk_level': risk_level,
            'score': total_score,
            'reasons': reasons if reasons else ['Aucune menace détectée'],
            'ai_info': ai_info,
            'is_hidden': file_info['is_hidden'],
            'created': file_info.get('created', 0),
            'modified': file_info['mtime']
        }
    
    def run_analysis(self) -> Tuple[bool, str]:
        """Execute full security scan"""
        self.start_time = time.time()
        self.scan_status = "validating"
        
        logger.info(f"Starting analysis for {self.folder_path}")
        
        valid, message = self.validate_folder()
        if not valid:
            logger.error(f"Folder validation failed: {message}")
            return False, message
        
        self.scan_status = "enumerating"
        files_info = self.scan_files()
        
        if not files_info:
            self.end_time = time.time()
            return True, "Aucun fichier trouvé dans le dossier cible"
        
        self.scan_status = "analyzing"
        logger.info(f"Starting analysis of {len(files_info)} files")
        
        # Analyze files with progress tracking
        for idx, file_info in enumerate(files_info, 1):
            result = self.analyze_file(file_info)
            self.scan_results.append(result)
            self.summary[result['risk_level']] += 1
            
            # Update progress
            self.scan_progress = (idx / len(files_info)) * 100
            
            # Log progress every 10%
            if idx % max(1, len(files_info) // 10) == 0:
                logger.info(f"Progress: {self.scan_progress:.1f}% ({idx}/{len(files_info)} files)")
        
        self.end_time = time.time()
        self.scan_status = "completed"
        
        duration = self.end_time - self.start_time
        logger.info(f"Analysis completed in {duration:.2f} seconds")
        
        return True, f"Analyse terminée avec succès en {duration:.2f} secondes"
    
    def get_scan_summary(self) -> Dict:
        """Get comprehensive scan summary"""
        duration = (self.end_time or time.time()) - (self.start_time or time.time())
        
        return {
            'total_files': self.total_files,
            'analyzed_files': len(self.scan_results),
            'high_risk': self.summary["High"],
            'medium_risk': self.summary["Medium"],
            'low_risk': self.summary["Low"],
            'scan_duration': duration,
            'folder': self.folder_path,
            'recursive': self.recursive,
            'analyze_content': self.analyze_content,
            'yara_available': YARA_AVAILABLE,
            'scan_status': self.scan_status,
            'threat_percentage': (self.summary["High"] + self.summary["Medium"]) / max(1, len(self.scan_results)) * 100
        }
    
    def export_results(self, format_type: str = 'json') -> str:
        """Export scan results in different formats"""
        if format_type == 'json':
            import json
            return json.dumps({
                'summary': self.get_scan_summary(),
                'results': self.scan_results
            }, indent=2, default=str)
        
        elif format_type == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Header
            writer.writerow(['Name', 'Path', 'Risk Level', 'Score', 'Size', 'Extension', 'Reasons'])
            
            # Data
            for result in self.scan_results:
                writer.writerow([
                    result['name'],
                    result['path'],
                    result['risk_level'],
                    result['score'],
                    result['size'],
                    result['extension'],
                    '; '.join(result['reasons'])
                ])
            
            return output.getvalue()
        
        else:
            raise ValueError(f"Unsupported format: {format_type}")


def validate_scan_path(path: str) -> bool:
    """Validate if path is safe for scanning (évite les dossiers système sensibles)"""
    if not path or not isinstance(path, str):
        return False
    try:
        # Chemins système sensibles (Unix et Windows)
        dangerous_paths = [
            '/system', '/windows', '/program files', '/program files (x86)',
            '/usr/bin', '/usr/sbin', '/bin', '/sbin', '/boot', '/dev',
            '/etc', '/proc', '/sys',
            'c:\\windows', 'c:\\program files', 'c:\\program files (x86)',
            'c:\\etc', '/system32', '\\windows\\system32'
        ]
        resolved = str(Path(path).expanduser().resolve()).replace("\\", "/").lower()
        for dangerous in dangerous_paths:
            d = dangerous.replace("\\", "/")
            if resolved.startswith(d) or f"/{d}" in resolved or f"\\{d}" in resolved:
                return False
        return True
    except (OSError, ValueError):
        return False

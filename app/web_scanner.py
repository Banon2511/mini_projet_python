"""
Scanner web de repli - utilisé quand scanner.SecurityScanner n'est pas disponible
"""
import os
import time
from typing import List, Dict, Tuple, Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    from signature_db import get_signature_database
    SIGNATURE_DB_AVAILABLE = True
except Exception:
    get_signature_database = None
    SIGNATURE_DB_AVAILABLE = False


class WebMiniSecScanner:
    """Scanner de sécurité de fichiers pour interface web (fallback sans IA)"""

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
"""

    HIGH_RISK_EXTENSIONS = {'.exe', '.bat', '.cmd', '.com', '.scr', '.vbs',
                           '.js', '.jar', '.ps1', '.msi', '.dll'}
    MEDIUM_RISK_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.sh',
                             '.py', '.rb', '.pl', '.php'}
    SUSPICIOUS_KEYWORDS = ['crack', 'virus', 'malware', 'password', 'hack',
                          'trojan', 'keylog', 'ransom', 'exploit', 'backdoor',
                          'rootkit', 'inject', 'payload', 'keygen', 'pirated']
    EMPTY_FILE_SIZE = 0
    VERY_SMALL_SIZE = 10
    VERY_LARGE_SIZE = 50 * 1024 * 1024  # 50 MB
    RECENT_SECONDS = 24 * 60 * 60

    def __init__(self, folder_path: str, recursive: bool = False,
                 analyze_content: bool = False):
        self.folder_path = folder_path
        self.recursive = recursive
        self.analyze_content = analyze_content
        self.scan_results = []
        self.summary = {'Low': 0, 'Medium': 0, 'High': 0}
        self.total_files = 0
        self._yara_rules_cache = None
        self.scan_progress = 0
        self.scan_status = "initializing"
        self.enable_ai = False
        self.ai_manager = None

    def get_yara_rules(self) -> Optional[object]:
        if not YARA_AVAILABLE:
            return None
        if self._yara_rules_cache is None:
            try:
                self._yara_rules_cache = yara.compile(source=self.YARA_RULES)
            except Exception:
                self._yara_rules_cache = None
        return self._yara_rules_cache

    def validate_folder(self) -> Tuple[bool, str]:
        if not os.path.exists(self.folder_path):
            return False, "Le chemin n'existe pas"
        if not os.path.isdir(self.folder_path):
            return False, "Ce n'est pas un dossier"
        if not os.access(self.folder_path, os.R_OK):
            return False, "Permission refusée"
        return True, "Dossier validé"

    def scan_files(self) -> List[Dict]:
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
        except (PermissionError, Exception):
            pass
        return files_info

    def _get_file_info(self, file_path: str, filename: str) -> Dict:
        try:
            stat_info = os.stat(file_path)
            return {
                'name': filename, 'path': file_path, 'size': stat_info.st_size,
                'extension': os.path.splitext(filename)[1].lower(),
                'mtime': stat_info.st_mtime, 'is_hidden': filename.startswith('.')
            }
        except OSError:
            return None

    def analyze_extension(self, extension: str) -> Tuple[int, str]:
        if extension in self.HIGH_RISK_EXTENSIONS:
            return (3, f"Extension dangereuse: {extension}")
        if extension in self.MEDIUM_RISK_EXTENSIONS:
            return (2, f"Extension suspecte: {extension}")
        return (0, "")

    def analyze_filename(self, filename: str) -> Tuple[int, str]:
        filename_lower = filename.lower()
        found = [k for k in self.SUSPICIOUS_KEYWORDS if k in filename_lower]
        if found:
            return (3, f"Motif malveillant détecté: {', '.join(found)}")
        return (0, "")

    def analyze_size(self, size: int) -> Tuple[int, str]:
        if size == self.EMPTY_FILE_SIZE:
            return (1, "Fichier vide (0 octets)")
        if size < self.VERY_SMALL_SIZE:
            return (1, f"Fichier anormalement petit ({size} octets)")
        if size > self.VERY_LARGE_SIZE:
            return (2, f"Fichier anormalement volumineux ({size / (1024*1024):.1f} MB)")
        return (0, "")

    def analyze_modification_date(self, mtime: float) -> Tuple[int, str]:
        if time.time() - mtime < self.RECENT_SECONDS:
            return (1, f"Modifié récemment ({(time.time() - mtime) / 3600:.1f}h)")
        return (0, "")

    def analyze_hidden_file(self, is_hidden: bool, filename: str) -> Tuple[int, str]:
        return (1, "Fichier caché détecté") if is_hidden else (0, "")

    def analyze_signature(self, file_path: str) -> Tuple[int, str]:
        if not SIGNATURE_DB_AVAILABLE or not get_signature_database:
            return (0, "")
        try:
            db = get_signature_database()
            threat = db.get_threat(file_path)
            if threat:
                desc = threat.get("description", "")
                name = threat.get("name", "Menace connue")
                reason = f"Signature connue: {name}" + (f" — {desc}" if desc else "")
                return (5, reason)
        except Exception:
            pass
        return (0, "")

    def analyze_file_content(self, file_path: str, filename: str) -> Tuple[int, List[str]]:
        suspicious_lines = []
        score = 0
        if YARA_AVAILABLE and self.analyze_content:
            yara_rules = self.get_yara_rules()
            if yara_rules:
                try:
                    for match in yara_rules.match(file_path):
                        lvl = match.meta.get('threat_level', 'Medium').lower()
                        score += 3 if lvl == 'high' else 2 if lvl == 'medium' else 1
                        suspicious_lines.append(f"YARA: {match.rule}")
                except Exception:
                    pass
        binary_exts = {'.exe', '.dll', '.bin', '.jpg', '.png', '.gif',
                      '.zip', '.rar', '.7z', '.tar', '.gz', '.pdf', '.doc', '.docx'}
        ext = os.path.splitext(filename)[1].lower()
        if ext in binary_exts:
            try:
                with open(file_path, 'rb') as f:
                    h = f.read(1024)
                    if h.startswith(b'MZ'):
                        suspicious_lines.append("Signature d'exécutable Windows")
                        score += 2
                    elif h.startswith(b'\x7fELF'):
                        suspicious_lines.append("Signature d'exécutable Linux")
                        score += 2
                    elif b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' in h:
                        suspicious_lines.append("Fichier test EICAR")
                        score += 2
            except (PermissionError, OSError):
                pass
            return (score, suspicious_lines)
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f.readlines()[:100], 1):
                    line_lower = line.lower()
                    for keyword in self.SUSPICIOUS_KEYWORDS:
                        if keyword in line_lower:
                            suspicious_lines.append(f"Ligne {line_num}: motif suspect '{keyword}'")
                            score = max(score, 2)
                            break
                    if any(s in line_lower for s in ['eval(', 'exec(', 'system(', 'shell_exec']):
                        suspicious_lines.append(f"Ligne {line_num}: exécution de code")
                        score = max(score, 2)
        except (PermissionError, OSError, UnicodeDecodeError):
            pass
        return (score, suspicious_lines)

    def calculate_risk_level(self, total_score: int) -> str:
        return 'High' if total_score >= 5 else 'Medium' if total_score >= 2 else 'Low'

    def analyze_file(self, file_info: Dict) -> Dict:
        reasons = []
        total_score = 0
        for score, reason in [
            self.analyze_extension(file_info['extension']),
            self.analyze_filename(file_info['name']),
            self.analyze_size(file_info['size']),
            self.analyze_modification_date(file_info['mtime']),
            self.analyze_hidden_file(file_info['is_hidden'], file_info['name']),
            self.analyze_signature(file_info['path']),
        ]:
            total_score += score
            if reason:
                reasons.append(reason)
        if self.analyze_content:
            content_score, content_reasons = self.analyze_file_content(
                file_info['path'], file_info['name']
            )
            total_score += content_score
            reasons.extend(content_reasons[:3])
        risk_level = self.calculate_risk_level(total_score)
        return {
            'name': file_info['name'], 'path': file_info['path'],
            'size': file_info['size'], 'extension': file_info['extension'],
            'risk_level': risk_level, 'score': total_score,
            'reasons': reasons if reasons else ['Aucune menace détectée']
        }

    def run_analysis(self) -> Tuple[bool, str]:
        self.scan_status = "validating"
        valid, message = self.validate_folder()
        if not valid:
            return False, message
        self.scan_status = "enumerating"
        files_info = self.scan_files()
        if not files_info:
            return True, "Aucun fichier trouvé dans le dossier cible"
        self.scan_status = "analyzing"
        for idx, file_info in enumerate(files_info, 1):
            result = self.analyze_file(file_info)
            self.scan_results.append(result)
            self.summary[result['risk_level']] += 1
            self.scan_progress = (idx / len(files_info)) * 100
        self.scan_status = "completed"
        return True, "Analyse terminée avec succès"

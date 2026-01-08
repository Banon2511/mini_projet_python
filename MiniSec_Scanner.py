"""
MiniSec Scanner - Analyseur de Sécurité de Fichiers
Outil pédagogique de cybersécurité - Édition Terminal
"""
import os
import sys
import time
from typing import List, Dict, Tuple, Optional
from datetime import datetime

# Tentative d'import YARA - dépendance optionnelle
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("[!] YARA non disponible - utilisation des heuristiques de base")


class Colors:
    """Codes de couleurs ANSI pour le terminal"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GREY = '\033[90m'


def clear_screen():
    """Effacer l'écran du terminal"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_slow(text, delay=0.03):
    """Affiche le texte avec effet de dactylographie"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def print_banner():
    """Affiche la bannière cyberpunk avec animation"""
    clear_screen()
    
    banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   {Colors.RED}███╗   ███╗██╗███╗   ██╗██╗███████╗███████╗ ██████╗                {Colors.CYAN}║
║   {Colors.RED}████╗ ████║██║████╗  ██║██║██╔════╝██╔════╝██╔════╝                {Colors.CYAN}║
║   {Colors.RED}██╔████╔██║██║██╔██╗ ██║██║███████╗█████╗  ██║                     {Colors.CYAN}║
║   {Colors.RED}██║╚██╔╝██║██║██║╚██╗██║██║╚════██║██╔══╝  ██║                     {Colors.CYAN}║
║   {Colors.RED}██║ ╚═╝ ██║██║██║ ╚████║██║███████║███████╗╚██████╗                {Colors.CYAN}║
║   {Colors.RED}╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝╚══════╝╚══════╝ ╚═════╝                {Colors.CYAN}║
║                                                                       ║
║              {Colors.YELLOW}[ Analyseur de Sécurité de Fichiers v1.0 ]{Colors.CYAN}          ║
║                                                                       ║
║   {Colors.GREEN}[+]{Colors.WHITE} Moteur de Détection         {Colors.GREY}|{Colors.WHITE}  Reconnaissance de Patterns {Colors.CYAN}║
║   {Colors.GREEN}[+]{Colors.WHITE} Analyse Multi-Critères      {Colors.GREY}|{Colors.WHITE}  Évaluation des Risques     {Colors.CYAN}║
║   {Colors.GREEN}[+]{Colors.WHITE} Scan Récursif              {Colors.GREY}|{Colors.WHITE}  Rapports Automatisés      {Colors.CYAN}║
║                                                                       ║
║   {Colors.RED}[!]{Colors.YELLOW} Outil Éducatif - À des Fins d'Apprentissage Uniquement{Colors.CYAN}     ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝{Colors.ENDC}
"""
    
    print(banner)
    
    # Effet de chargement animé
    print(f"\n{Colors.GREY}[*]{Colors.WHITE} Initialisation de MiniSec Scanner...", end='')
    for _ in range(3):
        time.sleep(0.3)
        sys.stdout.write('.')
        sys.stdout.flush()
    print(f" {Colors.GREEN}TERMINÉ{Colors.ENDC}")
    
    time.sleep(0.5)
    print(f"{Colors.GREY}[*]{Colors.WHITE} Chargement des modules de détection...", end='')
    for _ in range(3):
        time.sleep(0.2)
        sys.stdout.write('.')
        sys.stdout.flush()
    print(f" {Colors.GREEN}TERMINÉ{Colors.ENDC}")
    
    time.sleep(0.5)
    print(f"{Colors.GREY}[*]{Colors.WHITE} Initialisation de la base de menaces...", end='')
    for _ in range(3):
        time.sleep(0.2)
        sys.stdout.write('.')
        sys.stdout.flush()
    print(f" {Colors.GREEN}TERMINÉ{Colors.ENDC}\n")
    
    time.sleep(0.3)


def print_separator(char='─', length=75):
    """Affiche une ligne de séparation"""
    print(f"{Colors.GREY}{char * length}{Colors.ENDC}")


class MiniSecScanner:
    """Scanner de sécurité de fichiers avancé avec détection de menaces"""
    
    # Embedded YARA rules - no external files needed
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
    
    # Threat signatures
    HIGH_RISK_EXTENSIONS = {'.exe', '.bat', '.cmd', '.com', '.scr', '.vbs', 
                           '.js', '.jar', '.ps1', '.msi', '.dll'}
    MEDIUM_RISK_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.sh', 
                             '.py', '.rb', '.pl', '.php'}
    
    # Malicious patterns
    SUSPICIOUS_KEYWORDS = ['crack', 'virus', 'malware', 'password', 'hack',
                          'trojan', 'keylog', 'ransom', 'exploit', 'backdoor',
                          'rootkit', 'inject', 'payload', 'keygen', 'pirated']
    
    # Size thresholds
    EMPTY_FILE_SIZE = 0
    VERY_SMALL_SIZE = 10
    VERY_LARGE_SIZE = 50 * 1024 * 1024  # 50 MB
    
    # Time threshold
    RECENT_SECONDS = 24 * 60 * 60
    
    def __init__(self, folder_path: str, recursive: bool = False, 
                 analyze_content: bool = False):
        """Initialize scanner with target path and options"""
        self.folder_path = folder_path
        self.recursive = recursive
        self.analyze_content = analyze_content
        self.scan_results = []
        self.summary = {'Low': 0, 'Medium': 0, 'High': 0}
        self.total_files = 0
        self._yara_rules_cache = None  # Cache for performance
    
    def get_yara_rules(self) -> Optional[object]:
        """Get compiled YARA rules with caching"""
        if not YARA_AVAILABLE:
            return None
            
        if self._yara_rules_cache is None:
            try:
                self._yara_rules_cache = yara.compile(source=self.YARA_RULES)
                print(f"{Colors.GREEN}[+] Règles YARA chargées avec succès{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Erreur de compilation YARA : {e}{Colors.ENDC}")
                self._yara_rules_cache = None
        
        return self._yara_rules_cache
    
    def validate_folder(self) -> bool:
        """Validate target directory"""
        print(f"{Colors.GREY}[*]{Colors.WHITE} Validating target path...")
        time.sleep(0.3)
        
        if not os.path.exists(self.folder_path):
            print(f"{Colors.RED}[!] ERREUR : Le chemin n'existe pas{Colors.ENDC}")
            return False
        
        if not os.path.isdir(self.folder_path):
            print(f"{Colors.RED}[!] ERREUR : Ce n'est pas un dossier{Colors.ENDC}")
            return False
        
        if not os.access(self.folder_path, os.R_OK):
            print(f"{Colors.RED}[!] ERREUR : Permission refusée{Colors.ENDC}")
            return False
        
        print(f"{Colors.GREEN}[+] Cible validée avec succès{Colors.ENDC}")
        return True
    
    def scan_files(self) -> List[Dict]:
        """Enumerate files in target directory"""
        files_info = []
        
        print(f"\n{Colors.YELLOW}[~] Starting file enumeration...{Colors.ENDC}")
        time.sleep(0.3)
        
        try:
            if self.recursive:
                for dirpath, dirnames, filenames in os.walk(self.folder_path):
                    for filename in filenames:
                        self.total_files += 1
                        file_path = os.path.join(dirpath, filename)
                        file_info = self._get_file_info(file_path, filename)
                        if file_info:
                            files_info.append(file_info)
                            # Show progress
                            if self.total_files % 10 == 0:
                                print(f"{Colors.GREY}[*] Enumerated: {self.total_files} files...{Colors.ENDC}", end='\r')
            else:
                for item in os.listdir(self.folder_path):
                    item_path = os.path.join(self.folder_path, item)
                    if os.path.isfile(item_path):
                        self.total_files += 1
                        file_info = self._get_file_info(item_path, item)
                        if file_info:
                            files_info.append(file_info)
                            
        except PermissionError:
            print(f"\n{Colors.RED}[!] Permission refusée sur le dossier{Colors.ENDC}")
        except Exception as e:
            print(f"\n{Colors.RED}[!] Erreur de scan : {e}{Colors.ENDC}")
        
        print(f"\n{Colors.GREEN}[+] Énumération terminée : {len(files_info)} fichiers accessibles{Colors.ENDC}")
        return files_info
    
    def _get_file_info(self, file_path: str, filename: str) -> Dict:
        """Extract file metadata"""
        try:
            stat_info = os.stat(file_path)
            return {
                'name': filename,
                'path': file_path,
                'size': stat_info.st_size,
                'extension': os.path.splitext(filename)[1].lower(),
                'mtime': stat_info.st_mtime,
                'is_hidden': filename.startswith('.')
            }
        except OSError:
            return None
    
    def analyze_extension(self, extension: str) -> Tuple[int, str]:
        """Analyze file extension for threats"""
        if extension in self.HIGH_RISK_EXTENSIONS:
            return (3, f"Dangerous extension: {extension}")
        elif extension in self.MEDIUM_RISK_EXTENSIONS:
            return (2, f"Suspicious extension: {extension}")
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
            return (3, f"Malicious pattern detected: {keywords_str}")
        
        return (0, "")
    
    def analyze_size(self, size: int) -> Tuple[int, str]:
        """Analyze file size anomalies"""
        if size == self.EMPTY_FILE_SIZE:
            return (1, "Empty file (0 bytes)")
        elif size < self.VERY_SMALL_SIZE:
            return (1, f"Unusually small file ({size} bytes)")
        elif size > self.VERY_LARGE_SIZE:
            size_mb = size / (1024 * 1024)
            return (2, f"Unusually large file ({size_mb:.1f} MB)")
        
        return (0, "")
    
    def analyze_modification_date(self, mtime: float) -> Tuple[int, str]:
        """Check for recent modifications"""
        if time.time() - mtime < self.RECENT_SECONDS:
            hours_ago = (time.time() - mtime) / 3600
            return (1, f"Recently modified ({hours_ago:.1f}h ago)")
        return (0, "")
    
    def analyze_hidden_file(self, is_hidden: bool, filename: str) -> Tuple[int, str]:
        """Detect hidden files"""
        if is_hidden:
            return (1, f"Hidden file detected")
        return (0, "")
    
    def analyze_file_content(self, file_path: str, filename: str) -> Tuple[int, List[str]]:
        """Analyse de contenu améliorée avec intégration YARA"""
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
                            else:
                                score += 1
                            
                            suspicious_lines.append(
                                f"YARA: {match.rule} - {match.meta.get('description', 'Aucune description')}"
                            )
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] Erreur de scan YARA pour {filename}: {e}{Colors.ENDC}")
        
        # Analyse de contenu textuel pour tous les fichiers (sans YARA)
        binary_extensions = {'.exe', '.dll', '.bin', '.jpg', '.png', '.gif', 
                           '.zip', '.rar', '.7z', '.tar', '.gz', '.pdf', '.doc', '.docx'}
        ext = os.path.splitext(filename)[1].lower()
        
        # Pour les fichiers binaires, essayer de détecter des signatures simples
        if ext in binary_extensions:
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(1024)  # Lire les premiers 1KB
                    
                    # Signatures simples de fichiers exécutables
                    if header.startswith(b'MZ'):
                        suspicious_lines.append("Signature d'exécutable Windows détectée")
                        score += 2
                    elif header.startswith(b'\x7fELF'):
                        suspicious_lines.append("Signature d'exécutable Linux détectée")
                        score += 2
                    elif b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' in header:
                        suspicious_lines.append("Fichier test EICAR détecté")
                        score += 2
                        
            except (PermissionError, OSError):
                pass
            
            return (score, suspicious_lines)
        
        # Pour les fichiers texte, analyse du contenu
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content_lines = f.readlines()
                
                for line_num, line in enumerate(content_lines[:100], start=1):  # Limiter à 100 lignes
                    line_lower = line.lower()
                    
                    # Rechercher les mots-clés suspects
                    for keyword in self.SUSPICIOUS_KEYWORDS:
                        if keyword in line_lower:
                            suspicious_lines.append(
                                f"Ligne {line_num}: motif suspect '{keyword}' détecté"
                            )
                            score = max(score, 2)
                            break
                    
                    # Détecter du code suspect
                    if any(suspicious in line_lower for suspicious in ['eval(', 'exec(', 'system(', 'shell_exec']):
                        suspicious_lines.append(f"Ligne {line_num}: fonction d'exécution de code détectée")
                        score = max(score, 2)
                    
                    # Détecter des URLs suspectes
                    if 'http://' in line_lower or 'https://' in line_lower:
                        suspicious_lines.append(f"Ligne {line_num}: URL détectée")
                        score = max(score, 1)
                        
        except (PermissionError, OSError, UnicodeDecodeError):
            pass
        
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
        """Comprehensive file analysis"""
        reasons = []
        total_score = 0
        
        # Run all analysis modules
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
        
        if self.analyze_content:
            content_score, content_reasons = self.analyze_file_content(
                file_info['path'], file_info['name']
            )
            total_score += content_score
            if content_reasons:
                reasons.extend(content_reasons[:3])
        
        risk_level = self.calculate_risk_level(total_score)
        
        return {
            'name': file_info['name'],
            'path': file_info['path'],
            'size': file_info['size'],
            'extension': file_info['extension'],
            'risk_level': risk_level,
            'score': total_score,
            'reasons': reasons if reasons else ['No threats detected']
        }
    
    def run_analysis(self) -> bool:
        """Execute full security scan"""
        print(f"\n{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗{Colors.ENDC}")
        print(f"{Colors.CYAN}║{Colors.YELLOW}                    SCAN CONFIGURATION                        {Colors.CYAN}║{Colors.ENDC}")
        print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}")
        
        print(f"\n{Colors.GREY}[*]{Colors.WHITE} Target: {Colors.CYAN}{self.folder_path}{Colors.ENDC}")
        print(f"{Colors.GREY}[*]{Colors.WHITE} Mode: {Colors.CYAN}{'Recursive' if self.recursive else 'Standard'}{Colors.ENDC}")
        print(f"{Colors.GREY}[*]{Colors.WHITE} Content Analysis: {Colors.CYAN}{'Enabled' if self.analyze_content else 'Disabled'}{Colors.ENDC}")
        
        # Show YARA status
        if YARA_AVAILABLE:
            print(f"{Colors.GREEN}[*]{Colors.WHITE} YARA Engine: {Colors.GREEN}Available{Colors.ENDC}")
        else:
            print(f"{Colors.YELLOW}[*]{Colors.WHITE} YARA Engine: {Colors.YELLOW}Not Available (pip install yara-python){Colors.ENDC}")
        
        print()
        
        if not self.validate_folder():
            return False
        
        files_info = self.scan_files()
        
        if not files_info:
            print(f"\n{Colors.YELLOW}[~] No files found in target directory{Colors.ENDC}")
            return True
        
        print(f"\n{Colors.YELLOW}[~] Analyzing {len(files_info)} files...{Colors.ENDC}")
        time.sleep(0.5)
        
        # Analyze files with progress bar
        for idx, file_info in enumerate(files_info, 1):
            result = self.analyze_file(file_info)
            self.scan_results.append(result)
            self.summary[result['risk_level']] += 1
            
            # Progress indicator
            progress = (idx / len(files_info)) * 100
            bar_length = 40
            filled = int(bar_length * idx / len(files_info))
            bar = '█' * filled + '░' * (bar_length - filled)
            print(f"{Colors.GREY}[*] Progress: [{Colors.CYAN}{bar}{Colors.GREY}] {progress:.1f}%{Colors.ENDC}", end='\r')
        
        print(f"\n{Colors.GREEN}[+] Analysis complete{Colors.ENDC}\n")
        return True
    
    def display_results(self):
        """Display scan results in terminal"""
        if not self.scan_results:
            print(f"{Colors.YELLOW}[~] No results to display{Colors.ENDC}")
            return
        
        print(f"\n{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗{Colors.ENDC}")
        print(f"{Colors.CYAN}║{Colors.YELLOW}                    THREAT ANALYSIS REPORT                    {Colors.CYAN}║{Colors.ENDC}")
        print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")
        
        for risk_level in ['High', 'Medium', 'Low']:
            files = [f for f in self.scan_results if f['risk_level'] == risk_level]
            
            if files:
                if risk_level == 'High':
                    color = Colors.RED
                    symbol = '[!]'
                elif risk_level == 'Medium':
                    color = Colors.YELLOW
                    symbol = '[~]'
                else:
                    color = Colors.GREEN
                    symbol = '[+]'
                
                print(f"{color}{symbol} THREAT LEVEL: {risk_level.upper()} ({len(files)} file(s)){Colors.ENDC}")
                print_separator()
                
                for file in files:
                    size_kb = file['size'] / 1024
                    print(f"\n  {Colors.WHITE}File:{Colors.ENDC} {file['name']}")
                    print(f"  {Colors.GREY}Path:{Colors.ENDC} {file['path']}")
                    print(f"  {Colors.GREY}Size:{Colors.ENDC} {size_kb:.2f} KB")
                    print(f"  {Colors.GREY}Threat Score:{Colors.ENDC} {file['score']}")
                    print(f"  {Colors.GREY}Indicators:{Colors.ENDC}")
                    for reason in file['reasons']:
                        print(f"    {Colors.RED}▸{Colors.ENDC} {reason}")
                
                print()
        
        # Summary
        print(f"{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗{Colors.ENDC}")
        print(f"{Colors.CYAN}║{Colors.YELLOW}                        SCAN SUMMARY                          {Colors.CYAN}║{Colors.ENDC}")
        print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")
        print(f"  {Colors.WHITE}Total Files Scanned:{Colors.ENDC} {self.total_files}")
        print(f"  {Colors.WHITE}Files Analyzed:{Colors.ENDC} {len(self.scan_results)}")
        print(f"  {Colors.RED}High Risk:{Colors.ENDC} {self.summary['High']}")
        print(f"  {Colors.YELLOW}Medium Risk:{Colors.ENDC} {self.summary['Medium']}")
        print(f"  {Colors.GREEN}Low Risk:{Colors.ENDC} {self.summary['Low']}")
        print()
    
    def generate_report(self, output_file: str = None) -> str:
        """Génère un rapport de sécurité détaillé"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"rapport_minisec_{timestamp}.txt"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("═" * 70 + "\n")
                f.write("        MINISEC SCANNER - RAPPORT D'ANALYSE DE SÉCURITÉ\n")
                f.write("═" * 70 + "\n\n")
                
                f.write(f"Date du scan : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Chemin cible : {self.folder_path}\n")
                f.write(f"Mode de scan : {'Récursif' if self.recursive else 'Standard'}\n")
                f.write(f"Analyse de contenu : {'Activée' if self.analyze_content else 'Désactivée'}\n")
                f.write(f"Fichiers scannés : {self.total_files}\n")
                f.write(f"Fichiers analysés : {len(self.scan_results)}\n\n")
                
                f.write("RÉSUMÉ DES MENACES\n")
                f.write("─" * 70 + "\n")
                f.write(f"[!] Risque Élevé : {self.summary['High']} fichier(s)\n")
                f.write(f"[~] Risque Moyen : {self.summary['Medium']} fichier(s)\n")
                f.write(f"[+] Risque Faible : {self.summary['Low']} fichier(s)\n\n")
                
                for risk_level in ['High', 'Medium', 'Low']:
                    files = [f for f in self.scan_results if f['risk_level'] == risk_level]
                    
                    if files:
                        f.write("\n" + "═" * 70 + "\n")
                        f.write(f"NIVEAU DE MENACE : {risk_level.upper()} ({len(files)})\n")
                        f.write("═" * 70 + "\n\n")
                        
                        for file in files:
                            f.write(f"Fichier : {file['name']}\n")
                            f.write(f"Chemin : {file['path']}\n")
                            f.write(f"Taille : {file['size'] / 1024:.2f} KB\n")
                            f.write(f"Score de menace : {file['score']}\n")
                            f.write(f"Indicateurs :\n")
                            for reason in file['reasons']:
                                f.write(f"  ▸ {reason}\n")
                            f.write("\n")
                
                f.write("═" * 70 + "\n")
                f.write("Fin du rapport\n")
            
            print(f"{Colors.GREEN}[+] Rapport sauvegardé : {output_file}{Colors.ENDC}")
            return output_file
            
        except Exception as e:
            print(f"{Colors.RED}[!] Erreur lors de la génération du rapport : {e}{Colors.ENDC}")
            return None


def main():
    """Flux d'exécution principal"""
    print_banner()
    
    print(f"{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗{Colors.ENDC}")
    print(f"{Colors.CYAN}║{Colors.WHITE}                    CONFIGURATION DE LA CIBLE                  {Colors.CYAN}║{Colors.ENDC}")
    print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")
    
    folder = input(f"{Colors.YELLOW}[?]{Colors.WHITE} Entrez le chemin du dossier (ou Entrée pour le dossier actuel) : {Colors.ENDC}").strip()
    
    if not folder:
        folder = "."
    folder = os.path.abspath(folder)
    
    print(f"\n{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗{Colors.ENDC}")
    print(f"{Colors.CYAN}║{Colors.WHITE}                      OPTIONS DE SCAN                            {Colors.CYAN}║{Colors.ENDC}")
    print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")
    
    recursive = input(f"{Colors.YELLOW}[?]{Colors.WHITE} Activer le scan récursif ? (o/n) [{Colors.GREY}n{Colors.WHITE}] : {Colors.ENDC}").strip().lower() in ['o', 'oui']
    analyze_content = input(f"{Colors.YELLOW}[?]{Colors.WHITE} Activer l'analyse de contenu approfondie ? (o/n) [{Colors.GREY}n{Colors.WHITE}] : {Colors.ENDC}").strip().lower() in ['o', 'oui']
    
    try:
        scanner = MiniSecScanner(folder, recursive=recursive, analyze_content=analyze_content)
        
        if scanner.run_analysis():
            scanner.display_results()
            
            generate = input(f"\n{Colors.YELLOW}[?]{Colors.WHITE} Générer un fichier rapport ? (o/n) : {Colors.ENDC}").strip().lower()
            
            if generate in ['o', 'oui']:
                scanner.generate_report()
            
            print(f"\n{Colors.GREEN}[+] Scan terminé avec succès{Colors.ENDC}")
            print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")
        else:
            print(f"\n{Colors.RED}[!] Le scan a échoué{Colors.ENDC}\n")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan interrompu par l'utilisateur{Colors.ENDC}\n")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Erreur fatale : {e}{Colors.ENDC}\n")


if __name__ == "__main__":
    main()
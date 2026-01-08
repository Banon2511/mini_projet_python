"""
MiniSec Scanner - Test Environment Generator
Creates test files for security analysis demonstration
"""
import os
import sys
import time


class Colors:
    """Terminal color codes"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GREY = '\033[90m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def clear_screen():
    """Clear terminal"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    """Display test generator banner"""
    clear_screen()
    print(f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║              {Colors.YELLOW}TEST ENVIRONMENT GENERATOR{Colors.CYAN}                               ║
║              {Colors.GREY}For MiniSec Scanner v1.0{Colors.CYAN}                                  ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝{Colors.ENDC}
""")
    
    print(f"{Colors.GREY}[*]{Colors.WHITE} Initializing generator...", end='')
    for _ in range(3):
        time.sleep(0.2)
        sys.stdout.write('.')
        sys.stdout.flush()
    print(f" {Colors.GREEN}DONE{Colors.ENDC}\n")


def create_test_files():
    """Generate test file environment"""
    
    test_folder = "test_files"
    
    print(f"{Colors.GREY}[*]{Colors.WHITE} Creating test directory: {Colors.CYAN}{test_folder}{Colors.ENDC}")
    
    if not os.path.exists(test_folder):
        os.makedirs(test_folder)
        print(f"{Colors.GREEN}[+] Directory created{Colors.ENDC}")
    else:
        print(f"{Colors.YELLOW}[~] Directory already exists{Colors.ENDC}")
    
    # Test file definitions
    test_files = {
        # Normal files (Low risk)
        "document.txt": {
            "content": b"This is a normal text document with safe content.",
            "description": "Normal text file"
        },
        "image.jpg": {
            "content": b"FAKE_JPEG_DATA" * 100,
            "description": "Simulated image file"
        },
        "report.pdf": {
            "content": b"%PDF-1.4 FAKE_PDF_CONTENT" * 50,
            "description": "Simulated PDF document"
        },
        "data.csv": {
            "content": b"name,age,email\nJohn,25,john@example.com\nJane,30,jane@example.com",
            "description": "CSV data file"
        },
        
        # Dangerous extensions (High/Medium risk)
        "installer.exe": {
            "content": b"MZ" + b"X" * 1000,
            "description": "Windows executable"
        },
        "script.bat": {
            "content": b"@echo off\necho Hello World\npause",
            "description": "Batch script"
        },
        "autorun.vbs": {
            "content": b"WScript.Echo \"Test\"",
            "description": "VBScript file"
        },
        "backup.zip": {
            "content": b"PK" + b"Z" * 500,
            "description": "ZIP archive"
        },
        "archive.rar": {
            "content": b"Rar!" + b"R" * 800,
            "description": "RAR archive"
        },
        "module.py": {
            "content": b"print('Hello World')",
            "description": "Python script"
        },
        
        # Malicious patterns (High risk)
        "crack_keygen.exe": {
            "content": b"MZ" + b"C" * 2000,
            "description": "Executable with malicious name"
        },
        "password_stealer.txt": {
            "content": b"Password list...",
            "description": "Suspicious text file"
        },
        "virus_payload.com": {
            "content": b"COM_FILE" * 50,
            "description": "COM file with virus pattern"
        },
        "trojan_backdoor.dll": {
            "content": b"DLL_HEADER" * 100,
            "description": "DLL with multiple threats"
        },
        "hack_tool.jar": {
            "content": b"JAR_FILE" * 150,
            "description": "JAR with hack pattern"
        },
        "exploit_kit.js": {
            "content": b"// Malicious JavaScript\neval(atob('...'))",
            "description": "JavaScript exploit"
        },
        
        # Size anomalies
        "empty.txt": {
            "content": b"",
            "description": "Empty file (0 bytes)"
        },
        "tiny.dat": {
            "content": b"AB",
            "description": "Very small file (2 bytes)"
        },
        "huge_file.bin": {
            "content": b"L" * (55 * 1024 * 1024),
            "description": "Large file (55 MB)"
        },
        
        # Combined threats
        "keylogger_crack.exe": {
            "content": b"MZ" + b"K" * 3000,
            "description": "Multiple malicious patterns"
        },
        "ransomware.zip": {
            "content": b"PK" + b"M" * 1000,
            "description": "Archive with ransom pattern"
        },
        
        # Hidden files
        ".hidden_config": {
            "content": b"Hidden configuration file",
            "description": "Hidden file (Unix style)"
        },
    }
    
    print(f"\n{Colors.YELLOW}[~] Generating {len(test_files)} test files...{Colors.ENDC}\n")
    
    created_count = 0
    skipped_count = 0
    
    for filename, info in test_files.items():
        filepath = os.path.join(test_folder, filename)
        
        if os.path.exists(filepath):
            print(f"{Colors.GREY}[*] Skipped (exists): {filename}{Colors.ENDC}")
            skipped_count += 1
            continue
        
        try:
            with open(filepath, "wb") as f:
                f.write(info["content"])
            
            size = len(info["content"])
            if size < 1024:
                size_str = f"{size:,} bytes"
            elif size < 1024*1024:
                size_str = f"{size/1024:.2f} KB"
            else:
                size_str = f"{size/(1024*1024):.2f} MB"
            
            print(f"{Colors.GREEN}[+] Created: {filename:35} | {size_str:15} | {info['description']}{Colors.ENDC}")
            created_count += 1
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error creating {filename}: {e}{Colors.ENDC}")
    
    print(f"\n{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗{Colors.ENDC}")
    print(f"{Colors.CYAN}║{Colors.WHITE}                    GENERATION SUMMARY                        {Colors.CYAN}║{Colors.ENDC}")
    print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")
    print(f"  {Colors.WHITE}Files Created:{Colors.ENDC} {created_count}")
    print(f"  {Colors.WHITE}Files Skipped:{Colors.ENDC} {skipped_count}")
    print(f"  {Colors.WHITE}Total:{Colors.ENDC} {len(test_files)}")
    print(f"\n{Colors.GREEN}[+] Test environment ready in: {os.path.abspath(test_folder)}{Colors.ENDC}\n")


def display_expected_results():
    """Show expected scan results"""
    print(f"\n{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗{Colors.ENDC}")
    print(f"{Colors.CYAN}║{Colors.WHITE}                  EXPECTED SCAN RESULTS                       {Colors.CYAN}║{Colors.ENDC}")
    print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")
    
    print(f"{Colors.RED}[!] HIGH RISK - Expected Detections:{Colors.ENDC}")
    high_risk = [
        "crack_keygen.exe → .exe extension + 'crack' + 'keygen' patterns",
        "virus_payload.com → .com extension + 'virus' pattern",
        "trojan_backdoor.dll → .dll extension + 'trojan' + 'backdoor'",
        "keylogger_crack.exe → .exe + 'keylog' + 'crack'",
        "password_stealer.txt → 'password' pattern",
        "hack_tool.jar → .jar extension + 'hack' pattern",
        "ransomware.zip → .zip + 'ransom' pattern",
        "exploit_kit.js → .js extension + 'exploit'"
    ]
    for item in high_risk:
        print(f"  {Colors.RED}▸{Colors.ENDC} {item}")
    
    print(f"\n{Colors.YELLOW}[~] MEDIUM RISK - Expected Detections:{Colors.ENDC}")
    medium_risk = [
        "installer.exe → .exe extension",
        "script.bat → .bat extension",
        "autorun.vbs → .vbs extension",
        "backup.zip → .zip extension",
        "archive.rar → .rar extension",
        "module.py → .py extension",
        "huge_file.bin → Size > 50 MB"
    ]
    for item in medium_risk:
        print(f"  {Colors.YELLOW}▸{Colors.ENDC} {item}")
    
    print(f"\n{Colors.GREEN}[+] LOW RISK - Expected Detections:{Colors.ENDC}")
    low_risk = [
        "document.txt → Normal file",
        "image.jpg → Normal file",
        "report.pdf → Normal file",
        "data.csv → Normal file",
        "empty.txt → Empty file anomaly",
        "tiny.dat → Small size anomaly",
        ".hidden_config → Hidden file"
    ]
    for item in low_risk:
        print(f"  {Colors.GREEN}▸{Colors.ENDC} {item}")
    
    print()


def print_usage_instructions():
    """Display instructions for running scanner"""
    print(f"{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗{Colors.ENDC}")
    print(f"{Colors.CYAN}║{Colors.WHITE}                    NEXT STEPS                                {Colors.CYAN}║{Colors.ENDC}")
    print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")
    
    print(f"{Colors.YELLOW}[1]{Colors.WHITE} Run the scanner:{Colors.ENDC}")
    print(f"    {Colors.GREY}$ python minisec_scanner.py{Colors.ENDC}\n")
    
    print(f"{Colors.YELLOW}[2]{Colors.WHITE} Enter target path:{Colors.ENDC}")
    print(f"    {Colors.GREY}{os.path.abspath('test_files')}{Colors.ENDC}\n")
    
    print(f"{Colors.YELLOW}[3]{Colors.WHITE} Configure scan options as needed{Colors.ENDC}\n")
    
    print(f"{Colors.GREEN}[+] Ready to scan!{Colors.ENDC}\n")


def main():
    """Main execution"""
    print_banner()
    
    try:
        create_test_files()
        
        show_expected = input(f"{Colors.YELLOW}[?]{Colors.WHITE} Show expected scan results? (y/n): {Colors.ENDC}").strip().lower()
        
        if show_expected in ['y', 'yes']:
            display_expected_results()
        
        print_usage_instructions()
        
        print(f"{Colors.GREEN}[+] Generation completed successfully{Colors.ENDC}")
        print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")
        
    except Exception as e:
        print(f"\n{Colors.RED}[!] Fatal error: {e}{Colors.ENDC}\n")
    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}[!] Generation interrupted by user{Colors.ENDC}\n")


if __name__ == "__main__":
    main()
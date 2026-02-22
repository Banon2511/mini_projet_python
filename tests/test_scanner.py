"""
Tests unitaires pour MiniSec Scanner
"""
import pytest
import tempfile
import os
import json
from unittest.mock import patch, MagicMock
from pathlib import Path

# Import des modules à tester
from scanner import SecurityScanner, validate_scan_path
from models import ScanHistory, QuarantinedFile, SystemSettings
from validators import ScanRequestSchema, QuarantineRequestSchema, ValidationUtils
from error_handlers import ScannerError, ValidationError, FileNotFoundError


class TestSecurityScanner:
    """Tests pour la classe SecurityScanner"""
    
    def test_scanner_initialization(self):
        """Test l'initialisation du scanner"""
        scanner = SecurityScanner("/test/path", recursive=True, analyze_content=True)
        
        assert scanner.folder_path == "/test/path"
        assert scanner.recursive is True
        assert scanner.analyze_content is True
        assert scanner.scan_results == []
        assert scanner.summary == {'Low': 0, 'Medium': 0, 'High': 0}
        assert scanner.total_files == 0
    
    def test_validate_folder_success(self):
        """Test la validation d'un dossier valide"""
        with tempfile.TemporaryDirectory() as temp_dir:
            scanner = SecurityScanner(temp_dir)
            valid, message = scanner.validate_folder()
            
            assert valid is True
            assert "validé" in message.lower()
    
    def test_validate_folder_not_exists(self):
        """Test la validation d'un dossier qui n'existe pas"""
        scanner = SecurityScanner("/nonexistent/path")
        valid, message = scanner.validate_folder()
        
        assert valid is False
        assert "n'existe pas" in message.lower()
    
    def test_validate_folder_is_file(self):
        """Test la validation d'un fichier au lieu d'un dossier"""
        with tempfile.NamedTemporaryFile() as temp_file:
            scanner = SecurityScanner(temp_file.name)
            valid, message = scanner.validate_folder()
            
            assert valid is False
            assert "dossier" in message.lower()
    
    def test_analyze_extension_high_risk(self):
        """Test l'analyse d'extension à haut risque"""
        scanner = SecurityScanner("/test")
        score, reason = scanner.analyze_extension(".exe")
        
        assert score == 3
        assert "dangereuse" in reason.lower()
        assert ".exe" in reason
    
    def test_analyze_extension_medium_risk(self):
        """Test l'analyse d'extension à risque moyen"""
        scanner = SecurityScanner("/test")
        score, reason = scanner.analyze_extension(".zip")
        
        assert score == 2
        assert "suspecte" in reason.lower()
        assert ".zip" in reason
    
    def test_analyze_extension_safe(self):
        """Test l'analyse d'extension sûre"""
        scanner = SecurityScanner("/test")
        score, reason = scanner.analyze_extension(".txt")
        
        assert score == 0
        assert reason == ""
    
    def test_analyze_filename_suspicious(self):
        """Test l'analyse de nom de fichier suspect"""
        scanner = SecurityScanner("/test")
        score, reason = scanner.analyze_filename("crack_tool.exe")
        
        assert score == 3
        assert "malveillant" in reason.lower()
        assert "crack" in reason.lower()
    
    def test_analyze_filename_safe(self):
        """Test l'analyse de nom de fichier sûr"""
        scanner = SecurityScanner("/test")
        score, reason = scanner.analyze_filename("document.txt")
        
        assert score == 0
        assert reason == ""
    
    def test_analyze_size_empty(self):
        """Test l'analyse de fichier vide"""
        scanner = SecurityScanner("/test")
        score, reason = scanner.analyze_size(0)
        
        assert score == 1
        assert "vide" in reason.lower()
    
    def test_analyze_size_very_small(self):
        """Test l'analyse de très petit fichier"""
        scanner = SecurityScanner("/test")
        score, reason = scanner.analyze_size(5)
        
        assert score == 1
        assert "petit" in reason.lower()
    
    def test_analyze_size_very_large(self):
        """Test l'analyse de très gros fichier"""
        scanner = SecurityScanner("/test")
        large_size = 100 * 1024 * 1024  # 100MB
        score, reason = scanner.analyze_size(large_size)
        
        assert score == 2
        assert "volumineux" in reason.lower()
    
    def test_analyze_size_normal(self):
        """Test l'analyse de taille normale"""
        scanner = SecurityScanner("/test")
        score, reason = scanner.analyze_size(1024)  # 1KB
        
        assert score == 0
        assert reason == ""
    
    def test_calculate_risk_level_high(self):
        """Test le calcul de niveau de risque élevé"""
        scanner = SecurityScanner("/test")
        risk = scanner.calculate_risk_level(6)
        
        assert risk == "High"
    
    def test_calculate_risk_level_medium(self):
        """Test le calcul de niveau de risque moyen"""
        scanner = SecurityScanner("/test")
        risk = scanner.calculate_risk_level(3)
        
        assert risk == "Medium"
    
    def test_calculate_risk_level_low(self):
        """Test le calcul de niveau de risque faible"""
        scanner = SecurityScanner("/test")
        risk = scanner.calculate_risk_level(1)
        
        assert risk == "Low"
    
    def test_scan_files_with_temp_directory(self):
        """Test le scan de fichiers avec un dossier temporaire"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Créer des fichiers de test
            test_files = ["test1.txt", "test2.exe", "document.pdf"]
            for filename in test_files:
                Path(temp_dir, filename).touch()
            
            scanner = SecurityScanner(temp_dir, recursive=False)
            files_info = scanner.scan_files()
            
            assert len(files_info) == 3
            assert all('name' in info for info in files_info)
            assert all('path' in info for info in files_info)
            assert all('size' in info for info in files_info)
    
    def test_analyze_file_complete(self):
        """Test l'analyse complète d'un fichier"""
        scanner = SecurityScanner("/test")
        
        file_info = {
            'name': 'test.exe',
            'path': '/test/test.exe',
            'size': 1024,
            'extension': '.exe',
            'mtime': 1640995200,  # Timestamp fixe
            'is_hidden': False
        }
        
        result = scanner.analyze_file(file_info)
        
        assert result['name'] == 'test.exe'
        assert result['risk_level'] in ['Low', 'Medium', 'High']
        assert result['score'] >= 0
        assert 'reasons' in result
        assert isinstance(result['reasons'], list)
    
    def test_export_results_json(self):
        """Test l'export des résultats en JSON"""
        scanner = SecurityScanner("/test")
        scanner.scan_results = [
            {
                'name': 'test.exe',
                'risk_level': 'High',
                'score': 5
            }
        ]
        
        json_output = scanner.export_results('json')
        parsed = json.loads(json_output)
        
        assert 'summary' in parsed
        assert 'results' in parsed
        assert len(parsed['results']) == 1
        assert parsed['results'][0]['name'] == 'test.exe'
    
    def test_export_results_csv(self):
        """Test l'export des résultats en CSV"""
        scanner = SecurityScanner("/test")
        scanner.scan_results = [
            {
                'name': 'test.exe',
                'path': '/test/test.exe',
                'risk_level': 'High',
                'score': 5,
                'size': 1024,
                'extension': '.exe',
                'reasons': ['Extension dangereuse']
            }
        ]
        
        csv_output = scanner.export_results('csv')
        
        assert 'Name' in csv_output
        assert 'test.exe' in csv_output
        assert 'High' in csv_output


class TestValidationUtils:
    """Tests pour les utilitaires de validation"""
    
    def test_validate_path_security_valid(self):
        """Test la validation de chemin sécurisé valide"""
        assert ValidationUtils.validate_path_security("/home/user/documents") is True
        assert ValidationUtils.validate_path_security("C:\\Users\\Test\\Documents") is True
    
    def test_validate_path_security_dangerous(self):
        """Test la validation de chemin dangereux"""
        assert ValidationUtils.validate_path_security("../../../etc/passwd") is False
        assert ValidationUtils.validate_path_security("/etc/passwd") is False
        assert ValidationUtils.validate_path_security("C:\\Windows\\System32") is False
    
    def test_sanitize_filename(self):
        """Test le nettoyage de nom de fichier"""
        assert ValidationUtils.sanitize_filename("test<file>.txt") == "test_file_.txt"
        assert ValidationUtils.sanitize_filename("") == "unnamed_file"
        
        # Test de nom très long
        long_name = "a" * 300 + ".txt"
        sanitized = ValidationUtils.sanitize_filename(long_name)
        assert len(sanitized) <= 255
        assert sanitized.endswith(".txt")
    
    def test_validate_file_size(self):
        """Test la validation de taille de fichier"""
        assert ValidationUtils.validate_file_size(1024) is True
        assert ValidationUtils.validate_file_size(0) is True
        assert ValidationUtils.validate_file_size(-1) is False
        assert ValidationUtils.validate_file_size(100 * 1024 * 1024 + 1) is False
    
    def test_validate_ip_address(self):
        """Test la validation d'adresse IP"""
        assert ValidationUtils.validate_ip_address("192.168.1.1") is True
        assert ValidationUtils.validate_ip_address("::1") is True
        assert ValidationUtils.validate_ip_address("invalid.ip") is False
        assert ValidationUtils.validate_ip_address("") is False
    
    def test_validate_email(self):
        """Test la validation d'adresse email"""
        assert ValidationUtils.validate_email("test@example.com") is True
        assert ValidationUtils.validate_email("user.name+tag@domain.co.uk") is True
        assert ValidationUtils.validate_email("invalid.email") is False
        assert ValidationUtils.validate_email("@domain.com") is False


class TestSchemas:
    """Tests pour les schémas Marshmallow"""
    
    def test_scan_request_schema_valid(self):
        """Test le schéma de requête de scan valide"""
        schema = ScanRequestSchema()
        data = {
            'folder': '/test/path',
            'recursive': True,
            'analyze_content': False
        }
        
        result = schema.load(data)
        
        assert result['folder'] == '/test/path'
        assert result['recursive'] is True
        assert result['analyze_content'] is False
    
    def test_scan_request_schema_missing_folder(self):
        """Test le schéma avec dossier manquant"""
        schema = ScanRequestSchema()
        data = {
            'recursive': True
        }
        
        with pytest.raises(Exception):  # ValidationError
            schema.load(data)
    
    def test_scan_request_schema_dangerous_path(self):
        """Test le schéma avec chemin dangereux"""
        schema = ScanRequestSchema()
        data = {
            'folder': '../../../etc/passwd'
        }
        
        with pytest.raises(Exception):  # ValidationError
            schema.load(data)
    
    def test_quarantine_request_schema_valid(self):
        """Test le schéma de quarantaine valide"""
        schema = QuarantineRequestSchema()
        data = {
            'file_id': 'test_file.exe',
            'reason': 'Test quarantine'
        }
        
        result = schema.load(data)
        
        assert result['file_id'] == 'test_file.exe'
        assert result['reason'] == 'Test quarantine'
    
    def test_quarantine_request_schema_missing_file_id(self):
        """Test le schéma avec file_id manquant"""
        schema = QuarantineRequestSchema()
        data = {
            'reason': 'Test quarantine'
        }
        
        with pytest.raises(Exception):  # ValidationError
            schema.load(data)


class TestErrorHandling:
    """Tests pour la gestion d'erreurs"""
    
    def test_scanner_error_creation(self):
        """Test la création d'erreur de scanner"""
        error = ScannerError("Test error", "TEST_ERROR", 400)
        
        assert error.message == "Test error"
        assert error.error_code == "TEST_ERROR"
        assert error.status_code == 400
    
    def test_validation_error_creation(self):
        """Test la création d'erreur de validation"""
        error = ValidationError("Invalid input", "test_field")
        
        assert error.message == "Invalid input"
        assert error.error_code == "VALIDATION_ERROR"
        assert error.status_code == 400
        assert error.field == "test_field"
    
    def test_file_not_found_error_creation(self):
        """Test la création d'erreur fichier non trouvé"""
        error = FileNotFoundError("/nonexistent/file.txt")
        
        assert error.path == "/nonexistent/file.txt"
        assert "non trouvé" in error.message
        assert error.error_code == "FILE_NOT_FOUND"
        assert error.status_code == 404


class TestValidateScanPath:
    """Tests pour la fonction validate_scan_path"""
    
    def test_validate_scan_path_valid(self):
        """Test la validation de chemin valide"""
        assert validate_scan_path("/home/user/documents") is True
        assert validate_scan_path("C:\\Users\\Test\\Documents") is True
    
    def test_validate_scan_path_invalid(self):
        """Test la validation de chemin invalide"""
        assert validate_scan_path("") is False
        assert validate_scan_path(None) is False
        assert validate_scan_path("/etc/passwd") is False
        assert validate_scan_path("C:\\Windows\\System32") is False
        assert validate_scan_path(123) is False


class TestIntegration:
    """Tests d'intégration"""
    
    def test_full_scan_workflow(self):
        """Test le workflow complet de scan"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Créer des fichiers de test avec différents niveaux de risque
            test_files = {
                "safe.txt": "Contenu sûr",
                "suspicious.exe": "Fake executable content",
                "crack_tool.exe": "Crack tool content"
            }
            
            for filename, content in test_files.items():
                with open(os.path.join(temp_dir, filename), 'w') as f:
                    f.write(content)
            
            # Exécuter le scan
            scanner = SecurityScanner(temp_dir, recursive=True, analyze_content=True)
            success, message = scanner.run_analysis()
            
            assert success is True
            assert len(scanner.scan_results) == 3
            assert scanner.total_files == 3
            
            # Vérifier que les fichiers à haut risque sont détectés
            high_risk_files = [r for r in scanner.scan_results if r['risk_level'] == 'High']
            assert len(high_risk_files) >= 1  # Au moins crack_tool.exe
    
    def test_export_and_import_workflow(self):
        """Test le workflow d'export et d'import"""
        scanner = SecurityScanner("/test")
        scanner.scan_results = [
            {
                'name': 'test.exe',
                'path': '/test/test.exe',
                'risk_level': 'High',
                'score': 5,
                'size': 1024,
                'extension': '.exe',
                'reasons': ['Extension dangereuse', 'Motif malveillant']
            }
        ]
        
        # Exporter en JSON
        json_export = scanner.export_results('json')
        
        # Vérifier que le JSON est valide
        parsed = json.loads(json_export)
        assert 'results' in parsed
        assert len(parsed['results']) == 1
        
        # Exporter en CSV
        csv_export = scanner.export_results('csv')
        assert 'test.exe' in csv_export
        assert 'High' in csv_export


# Fixtures pour les tests
@pytest.fixture
def temp_directory():
    """Fixture pour créer un dossier temporaire"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


@pytest.fixture
def sample_scanner():
    """Fixture pour créer un scanner d'exemple"""
    return SecurityScanner("/test", recursive=True, analyze_content=True)


@pytest.fixture
def sample_file_info():
    """Fixture pour créer des infos de fichier d'exemple"""
    return {
        'name': 'test.exe',
        'path': '/test/test.exe',
        'size': 1024,
        'extension': '.exe',
        'mtime': 1640995200,
        'is_hidden': False
    }


# Configuration de pytest
def pytest_configure(config):
    """Configuration de pytest"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])

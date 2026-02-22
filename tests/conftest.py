"""
Configuration des tests pour MiniSec Scanner
"""
import pytest
import tempfile
import os
from pathlib import Path


@pytest.fixture(scope='session')
def temp_dir():
    """Crée un dossier temporaire pour toute la session de tests"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


@pytest.fixture
def sample_files_dir(temp_dir):
    """Crée un dossier avec des fichiers de test"""
    test_dir = Path(temp_dir) / "test_files"
    test_dir.mkdir(exist_ok=True)
    
    # Fichiers sûrs
    (test_dir / "document.txt").write_text("Ceci est un document normal.")
    (test_dir / "image.jpg").write_bytes(b"fake_image_content")
    (test_dir / "data.csv").write_text("col1,col2\nval1,val2")
    
    # Fichiers suspects
    (test_dir / "program.exe").write_text("fake_executable")
    (test_dir / "crack_tool.exe").write_text("crack content")
    (test_dir / "virus.bat").write_text("malicious batch file")
    
    # Fichiers avec contenu suspect
    (test_dir / "suspicious.py").write_text("import os; os.system('rm -rf /')")
    (test_dir / "keylogger.js").write_text("document.addEventListener('keydown', logKey)")
    
    # Fichier EICAR de test
    (test_dir / "eicar.txt").write_text("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    
    # Dossiers imbriqués
    nested_dir = test_dir / "nested"
    nested_dir.mkdir(exist_ok=True)
    (nested_dir / "hidden.exe").write_text("hidden executable")
    
    return str(test_dir)


@pytest.fixture
def empty_dir(temp_dir):
    """Crée un dossier vide pour les tests"""
    empty_dir = Path(temp_dir) / "empty"
    empty_dir.mkdir()
    return str(empty_dir)


@pytest.fixture
def large_files_dir(temp_dir):
    """Crée un dossier avec des fichiers de différentes tailles"""
    test_dir = Path(temp_dir) / "size_test"
    test_dir.mkdir()
    
    # Fichier vide
    (test_dir / "empty.txt").write_text("")
    
    # Petit fichier
    (test_dir / "small.txt").write_text("x")
    
    # Gros fichier (simulé)
    large_content = "x" * (50 * 1024 * 1024)  # 50MB
    (test_dir / "large.txt").write_text(large_content)
    
    return str(test_dir)


@pytest.fixture
def mock_yara_available():
    """Mock YARA comme étant disponible"""
    import scanner
    original_yara = scanner.YARA_AVAILABLE
    scanner.YARA_AVAILABLE = True
    yield
    scanner.YARA_AVAILABLE = original_yara


@pytest.fixture
def mock_yara_unavailable():
    """Mock YARA comme n'étant pas disponible"""
    import scanner
    original_yara = scanner.YARA_AVAILABLE
    scanner.YARA_AVAILABLE = False
    yield
    scanner.YARA_AVAILABLE = original_yara


@pytest.fixture
def sample_scan_results():
    """Résultats de scan d'exemple"""
    return [
        {
            'name': 'safe.txt',
            'path': '/test/safe.txt',
            'size': 1024,
            'extension': '.txt',
            'risk_level': 'Low',
            'score': 0,
            'reasons': ['Aucune menace détectée'],
            'is_hidden': False,
            'created': 1640995200,
            'modified': 1640995200
        },
        {
            'name': 'suspicious.exe',
            'path': '/test/suspicious.exe',
            'size': 2048,
            'extension': '.exe',
            'risk_level': 'High',
            'score': 6,
            'reasons': [
                'Extension dangereuse: .exe',
                'Motif malveillant détecté: suspicious'
            ],
            'is_hidden': False,
            'created': 1640995200,
            'modified': 1640995200
        },
        {
            'name': 'archive.zip',
            'path': '/test/archive.zip',
            'size': 10240,
            'extension': '.zip',
            'risk_level': 'Medium',
            'score': 2,
            'reasons': ['Extension suspecte: .zip'],
            'is_hidden': False,
            'created': 1640995200,
            'modified': 1640995200
        }
    ]


@pytest.fixture
def sample_scan_history():
    """Historique de scan d'exemple"""
    return {
        'id': 1,
        'folder_path': '/test/folder',
        'recursive': True,
        'analyze_content': True,
        'total_files': 100,
        'analyzed_files': 95,
        'high_risk_count': 5,
        'medium_risk_count': 15,
        'low_risk_count': 75,
        'scan_duration': 45.5,
        'scan_status': 'completed',
        'yara_available': True,
        'started_at': '2024-01-01T10:00:00',
        'completed_at': '2024-01-01T10:00:45',
        'threat_percentage': 21.1
    }


@pytest.fixture
def client():
    """Crée un client de test Flask"""
    from app import create_app
    from config import TestingConfig
    app = create_app(TestingConfig)
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as c:
        yield c


@pytest.fixture
def app():
    """Crée une application Flask pour les tests"""
    from app import create_app
    from config import TestingConfig
    a = create_app(TestingConfig)
    a.config["TESTING"] = True
    a.config["WTF_CSRF_ENABLED"] = False
    return a


# Helper functions pour les tests
def create_test_file(file_path: str, content: str = "test content"):
    """Crée un fichier de test"""
    Path(file_path).parent.mkdir(parents=True, exist_ok=True)
    Path(file_path).write_text(content)


def create_test_binary(file_path: str, content: bytes = b"binary content"):
    """Crée un fichier binaire de test"""
    Path(file_path).parent.mkdir(parents=True, exist_ok=True)
    Path(file_path).write_bytes(content)


def assert_file_analysis(result, expected_name, expected_risk_level, min_score=0):
    """Vérifie les résultats d'analyse de fichier"""
    assert result['name'] == expected_name
    assert result['risk_level'] == expected_risk_level
    assert result['score'] >= min_score
    assert 'reasons' in result
    assert isinstance(result['reasons'], list)


def assert_scan_summary(summary, expected_total_files, expected_high_risk=0, expected_medium_risk=0, expected_low_risk=0):
    """Vérifie le résumé de scan"""
    assert summary['total_files'] == expected_total_files
    assert summary['high_risk_count'] == expected_high_risk
    assert summary['medium_risk_count'] == expected_medium_risk
    assert summary['low_risk_count'] == expected_low_risk

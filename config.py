"""
Configuration centralisée pour l'application MiniSec Scanner
"""
import os
from pathlib import Path


class Config:
    """Configuration de base"""
    
    # Configuration Flask
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Configuration de l'application
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    UPLOAD_FOLDER = 'uploads'
    QUARANTINE_FOLDER = 'quarantine'
    
    # Configuration du scanner
    DEFAULT_SCAN_TIMEOUT = 300  # 5 minutes
    MAX_FILES_PER_SCAN = 10000
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
    FILE_TIMEOUT_SECONDS = 10.0  # timeout par fichier
    
    # Sandbox : seul ce dossier est autorisé pour le scan (sécurité)
    SCAN_SANDBOX = os.path.abspath(os.path.join(os.path.dirname(__file__), 'scan_sandbox'))
    
    # Configuration YARA
    YARA_RULES_FILE = 'rules/malware_rules.yar'
    YARA_TIMEOUT = 30
    
    # Configuration de la base de données
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///scanner.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Configuration du logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'
    LOG_FILE = 'scanner.log'
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 5
    
    # Configuration du rate limiting
    RATELIMIT_STORAGE_URL = 'memory://'
    RATELIMIT_DEFAULT = "100 per hour"
    
    # Configuration des rapports
    REPORTS_FOLDER = 'reports'
    MAX_REPORTS_AGE_DAYS = 30
    
    # Configuration de sécurité
    ALLOWED_EXTENSIONS = {'txt', 'log', 'csv', 'json', 'xml'}
    DANGEROUS_PATHS = [
        '/System', '/Windows', '/Program Files', '/Program Files (x86)',
        '/usr/bin', '/usr/sbin', '/bin', '/sbin', '/boot', '/dev',
        'C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)'
    ]
    
    # Configuration API
    API_VERSION = 'v1'
    API_PREFIX = f'/api/{API_VERSION}'
    
    @staticmethod
    def init_app(app):
        """Initialisation de l'application avec la configuration"""
        # Créer les dossiers nécessaires
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(Config.QUARANTINE_FOLDER, exist_ok=True)
        os.makedirs(Config.REPORTS_FOLDER, exist_ok=True)
        os.makedirs(Config.SCAN_SANDBOX, exist_ok=True)


class DevelopmentConfig(Config):
    """Configuration de développement"""
    DEBUG = True
    TESTING = False
    
    # Logging plus verbeux en développement
    LOG_LEVEL = 'DEBUG'
    
    # Pas de rate limiting en développement
    RATELIMIT_DEFAULT = "1000 per hour"


class TestingConfig(Config):
    """Configuration de test"""
    TESTING = True
    DEBUG = True
    
    # Base de données en mémoire pour les tests
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Désactiver le rate limiting pour les tests
    RATELIMIT_ENABLED = False
    
    # Logging minimal pour les tests
    LOG_LEVEL = 'WARNING'


class ProductionConfig(Config):
    """Configuration de production"""
    DEBUG = False
    TESTING = False
    
    # Sécurité renforcée en production
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32)
    
    # Rate limiting plus strict en production
    RATELIMIT_DEFAULT = "10 per minute"
    
    # Logging en production
    LOG_LEVEL = 'WARNING'
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Configuration spécifique à la production
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not app.debug and not app.testing:
            file_handler = RotatingFileHandler(
                cls.LOG_FILE,
                maxBytes=cls.LOG_MAX_BYTES,
                backupCount=cls.LOG_BACKUP_COUNT
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(logging.INFO)
            app.logger.addHandler(file_handler)
            
            app.logger.setLevel(logging.INFO)
            app.logger.info('MiniSec Scanner startup')


# Configuration par environnement
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}


def get_config():
    """Récupérer la configuration en fonction de l'environnement"""
    env = os.environ.get('FLASK_ENV', 'default')
    return config.get(env, config['default'])


# Validation de la configuration
def validate_config():
    """Valider la configuration actuelle"""
    current_config = get_config()
    
    # Vérifier les dossiers critiques
    required_dirs = [
        current_config.UPLOAD_FOLDER,
        current_config.QUARANTINE_FOLDER,
        current_config.REPORTS_FOLDER
    ]
    
    for dir_path in required_dirs:
        if not os.path.exists(dir_path):
            try:
                os.makedirs(dir_path, exist_ok=True)
            except OSError as e:
                raise RuntimeError(f"Impossible de créer le dossier {dir_path}: {e}")
    
    # Vérifier la clé secrète en production
    if (isinstance(current_config, ProductionConfig) and 
        current_config.SECRET_KEY == 'dev-secret-key-change-in-production'):
        raise RuntimeError("SECRET_KEY doit être défini en production")
    
    return True

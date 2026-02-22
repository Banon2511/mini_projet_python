"""
Configuration du logging et du rate limiting pour MiniSec Scanner
"""
import logging
import logging.handlers
import os
from datetime import datetime
from functools import wraps
from flask import Flask, request, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
import time


def setup_logging(app: Flask) -> None:
    """Configurer le logging pour l'application"""
    
    # Créer le dossier de logs si nécessaire
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    
    # Configuration du logging
    log_level = getattr(logging, app.config.get('LOG_LEVEL', 'INFO').upper())
    
    # Logger principal
    app.logger.setLevel(log_level)
    
    # Formatter pour les logs
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s - '
        'IP: %(client_ip)s - Path: %(path)s - Method: %(method)s'
    )
    
    # Handler pour les fichiers avec rotation
    log_file = os.path.join(log_dir, app.config.get('LOG_FILE', 'scanner.log'))
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=app.config.get('LOG_MAX_BYTES', 10 * 1024 * 1024),  # 10MB
        backupCount=app.config.get('LOG_BACKUP_COUNT', 5)
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(log_level)
    
    # Handler pour la console (uniquement en développement)
    if app.debug:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(log_level)
        app.logger.addHandler(console_handler)
    
    # Handler pour les erreurs séparées
    error_log_file = os.path.join(log_dir, 'errors.log')
    error_handler = logging.handlers.RotatingFileHandler(
        error_log_file,
        maxBytes=5 * 1024 * 1024,  # 5MB
        backupCount=3
    )
    error_handler.setFormatter(formatter)
    error_handler.setLevel(logging.ERROR)
    
    # Ajouter les handlers au logger de l'application
    app.logger.addHandler(file_handler)
    app.logger.addHandler(error_handler)
    
    # Configurer les loggers spécifiques
    setup_specific_loggers(log_level, log_dir)
    
    app.logger.info("Logging system initialized")
    app.logger.info(f"Log level: {logging.getLevelName(log_level)}")


def setup_specific_loggers(log_level: int, log_dir: str) -> None:
    """Configurer les loggers spécifiques pour différents composants"""
    
    # Logger pour les scans
    scan_logger = logging.getLogger('scanner')
    scan_logger.setLevel(log_level)
    
    scan_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, 'scans.log'),
        maxBytes=20 * 1024 * 1024,  # 20MB
        backupCount=10
    )
    scan_handler.setFormatter(logging.Formatter(
        '%(asctime)s - SCANNER - %(levelname)s - %(message)s'
    ))
    scan_logger.addHandler(scan_handler)
    
    # Logger pour l'API
    api_logger = logging.getLogger('api')
    api_logger.setLevel(log_level)
    
    api_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, 'api.log'),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    api_handler.setFormatter(logging.Formatter(
        '%(asctime)s - API - %(levelname)s - %(message)s - '
        'IP: %(client_ip)s - Endpoint: %(endpoint)s'
    ))
    api_logger.addHandler(api_handler)
    
    # Logger pour la sécurité
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    
    security_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, 'security.log'),
        maxBytes=5 * 1024 * 1024,  # 5MB
        backupCount=5
    )
    security_handler.setFormatter(logging.Formatter(
        '%(asctime)s - SECURITY - %(levelname)s - %(message)s - '
        'IP: %(client_ip)s - User-Agent: %(user_agent)s'
    ))
    security_logger.addHandler(security_handler)
    
    # Logger pour les performances
    perf_logger = logging.getLogger('performance')
    perf_logger.setLevel(logging.INFO)
    
    perf_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, 'performance.log'),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=3
    )
    perf_handler.setFormatter(logging.Formatter(
        '%(asctime)s - PERF - %(levelname)s - %(message)s - '
        'Duration: %(duration)sms - Memory: %(memory)sMB'
    ))
    perf_logger.addHandler(perf_handler)


def setup_rate_limiting(app: Flask) -> Limiter:
    """Configurer le rate limiting"""
    
    # Configuration du rate limiting
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=[app.config.get('RATELIMIT_DEFAULT', '100 per hour')],
        storage_uri=app.config.get('RATELIMIT_STORAGE_URL', 'memory://')
    )
    
    # Limits spécifiques par endpoint
    @limiter.limit("10 per minute")
    def limit_scan_requests():
        """Limiter les requêtes de scan"""
        pass
    
    @limiter.limit("60 per minute")
    def limit_api_requests():
        """Limiter les requêtes API générales"""
        pass
    
    @limiter.limit("5 per minute")
    def limit_quarantine_requests():
        """Limiter les requêtes de quarantaine (plus strict)"""
        pass
    
    @limiter.limit("20 per minute")
    def limit_export_requests():
        """Limiter les requêtes d'export"""
        pass
    
    app.logger.info("Rate limiting initialized")
    return limiter


def setup_caching(app: Flask) -> Cache:
    """Configurer le cache"""
    
    cache_config = {
        'CACHE_TYPE': 'simple',
        'CACHE_DEFAULT_TIMEOUT': 300,  # 5 minutes
        'CACHE_KEY_PREFIX': 'minisec_',
        'CACHE_REDIS_URL': app.config.get('REDIS_URL', 'redis://localhost:6379/0')
    }
    
    # Utiliser Redis si disponible, sinon SimpleCache
    if app.config.get('CACHE_TYPE') == 'redis':
        cache_config['CACHE_TYPE'] = 'RedisCache'
    
    cache = Cache(app, config=cache_config)
    
    app.logger.info(f"Caching initialized with type: {cache_config['CACHE_TYPE']}")
    return cache


def log_request_info(func):
    """Décorateur pour logger les informations de requête"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        
        # Logger les informations de la requête
        api_logger = logging.getLogger('api')
        api_logger.info(
            f"Request started - {request.method} {request.path} - "
            f"IP: {request.remote_addr} - User-Agent: {request.headers.get('User-Agent', 'Unknown')}"
        )
        
        try:
            result = func(*args, **kwargs)
            
            # Calculer la durée
            duration = (time.time() - start_time) * 1000  # en ms
            
            # Logger la fin de la requête
            api_logger.info(
                f"Request completed - {request.method} {request.path} - "
                f"Duration: {duration:.2f}ms - Status: {getattr(result, 'status_code', 200)}"
            )
            
            # Logger les performances si c'est lent
            if duration > 1000:  # Plus d'une seconde
                perf_logger = logging.getLogger('performance')
                perf_logger.warning(
                    f"Slow request detected - {request.method} {request.path} - "
                    f"Duration: {duration:.2f}ms"
                )
            
            return result
            
        except Exception as e:
            duration = (time.time() - start_time) * 1000
            api_logger.error(
                f"Request failed - {request.method} {request.path} - "
                f"Duration: {duration:.2f}ms - Error: {str(e)}"
            )
            raise
    
    return wrapper


def log_security_event(event_type: str, details: dict = None):
    """Logger un événement de sécurité"""
    security_logger = logging.getLogger('security')
    
    log_data = {
        'event_type': event_type,
        'timestamp': datetime.utcnow().isoformat(),
        'ip_address': request.remote_addr if request else 'unknown',
        'user_agent': request.headers.get('User-Agent', 'unknown') if request else 'unknown',
        'path': request.path if request else 'unknown',
        'method': request.method if request else 'unknown'
    }
    
    if details:
        log_data.update(details)
    
    # Formater le message
    message_parts = [f"{event_type}"]
    for key, value in log_data.items():
        if key != 'event_type':
            message_parts.append(f"{key}: {value}")
    
    message = " - ".join(message_parts)
    
    # Logger selon le type d'événement
    if event_type in ['SUSPICIOUS_PATH', 'RATE_LIMIT_EXCEEDED', 'UNAUTHORIZED_ACCESS']:
        security_logger.warning(message)
    elif event_type in ['QUARANTINE_ACTION', 'FILE_DELETION']:
        security_logger.info(message)
    else:
        security_logger.debug(message)


def log_scan_operation(operation: str, folder: str, file_count: int, 
                      duration: float, threats_found: int = 0):
    """Logger une opération de scan"""
    scan_logger = logging.getLogger('scanner')
    
    scan_logger.info(
        f"Scan {operation} - Folder: {folder} - Files: {file_count} - "
        f"Duration: {duration:.2f}s - Threats: {threats_found}"
    )
    
    # Logger les performances
    perf_logger = logging.getLogger('performance')
    files_per_second = file_count / max(duration, 0.001)
    perf_logger.info(
        f"Scan performance - Files/sec: {files_per_second:.2f} - "
        f"Total files: {file_count} - Duration: {duration:.2f}s"
    )


def log_memory_usage():
    """Logger l'utilisation de la mémoire"""
    try:
        import psutil
        process = psutil.Process()
        memory_info = process.memory_info()
        memory_mb = memory_info.rss / 1024 / 1024
        
        perf_logger = logging.getLogger('performance')
        perf_logger.debug(f"Memory usage: {memory_mb:.2f}MB")
        
        return memory_mb
    except ImportError:
        return None


class SecurityMiddleware:
    """Middleware pour la sécurité et le monitoring"""
    
    def __init__(self, app: Flask):
        self.app = app
        self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialiser le middleware"""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        app.teardown_appcontext(self.teardown_request)
    
    def before_request(self):
        """Exécuté avant chaque requête"""
        g.start_time = time.time()
        
        # Logger les requêtes suspectes
        path = request.path
        user_agent = request.headers.get('User-Agent', '')
        
        # Détecter les patterns suspects
        suspicious_patterns = [
            '../', '%2e%2e', 'admin', 'config', '.env',
            'php://', 'data://', 'expect://'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in path.lower():
                log_security_event('SUSPICIOUS_PATH', {
                    'pattern': pattern,
                    'full_path': path
                })
                break
        
        # Détecter les User-Agents suspects
        suspicious_uas = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'zap',
            'burp', 'metasploit', 'python-requests'
        ]
        
        for ua in suspicious_uas:
            if ua.lower() in user_agent.lower():
                log_security_event('SUSPICIOUS_USER_AGENT', {
                    'user_agent': user_agent,
                    'tool_detected': ua
                })
                break
    
    def after_request(self, response):
        """Exécuté après chaque requête"""
        # Logger les informations de réponse
        if hasattr(g, 'start_time'):
            duration = (time.time() - g.start_time) * 1000
            
            # Logger les réponses lentes
            if duration > 2000:  # Plus de 2 secondes
                perf_logger = logging.getLogger('performance')
                perf_logger.warning(
                    f"Slow response - {request.method} {request.path} - "
                    f"Duration: {duration:.2f}ms - Status: {response.status_code}"
                )
        
        # Ajouter des headers de sécurité
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        return response
    
    def teardown_request(self, exception):
        """Exécuté à la fin de chaque requête"""
        if exception:
            log_security_event('REQUEST_EXCEPTION', {
                'exception_type': type(exception).__name__,
                'exception_message': str(exception)
            })


def create_log_file(filename: str, content: str, log_dir: str = 'logs') -> str:
    """Créer un fichier de log personnalisé"""
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_filename = f"{timestamp}_{filename}"
    log_path = os.path.join(log_dir, log_filename)
    
    with open(log_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    return log_path


def cleanup_old_logs(log_dir: str = 'logs', days_to_keep: int = 30):
    """Nettoyer les anciens fichiers de log"""
    import glob
    from datetime import datetime, timedelta
    
    if not os.path.exists(log_dir):
        return
    
    cutoff_date = datetime.now() - timedelta(days=days_to_keep)
    
    log_files = glob.glob(os.path.join(log_dir, '*.log*'))
    deleted_count = 0
    
    for log_file in log_files:
        try:
            file_time = datetime.fromtimestamp(os.path.getmtime(log_file))
            if file_time < cutoff_date:
                os.remove(log_file)
                deleted_count += 1
        except OSError as e:
            logging.getLogger(__name__).warning(f"Failed to delete old log {log_file}: {e}")
    
    if deleted_count > 0:
        logging.getLogger(__name__).info(f"Cleaned up {deleted_count} old log files")


# Configuration du monitoring
def setup_monitoring(app: Flask):
    """Configurer le monitoring de l'application"""
    
    # Logger les métriques de démarrage
    app.logger.info("Application starting up...")
    app.logger.info(f"Debug mode: {app.debug}")
    app.logger.info(f"Environment: {app.config.get('ENV', 'development')}")
    
    # Logger l'utilisation mémoire au démarrage
    memory_mb = log_memory_usage()
    if memory_mb:
        app.logger.info(f"Startup memory usage: {memory_mb:.2f}MB")
    
    # Configurer le nettoyage automatique des logs
    import atexit
    atexit.register(lambda: cleanup_old_logs())
    
    app.logger.info("Monitoring system initialized")

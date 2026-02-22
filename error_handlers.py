"""
Gestion des erreurs et exceptions pour MiniSec Scanner
"""
import logging
import time
import traceback
from functools import wraps
from flask import jsonify, request
from typing import Dict, Any, Optional


class ScannerError(Exception):
    """Exception de base pour le scanner"""
    def __init__(self, message: str, error_code: str = "SCANNER_ERROR", status_code: int = 500):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code


class ValidationError(ScannerError):
    """Erreur de validation"""
    def __init__(self, message: str, field: str = None):
        super().__init__(message, "VALIDATION_ERROR", 400)
        self.field = field


class FileNotFoundError(ScannerError):
    """Fichier non trouvé"""
    def __init__(self, path: str):
        super().__init__(f"Fichier non trouvé: {path}", "FILE_NOT_FOUND", 404)
        self.path = path


class PermissionError(ScannerError):
    """Erreur de permission"""
    def __init__(self, path: str, operation: str = "accès"):
        super().__init__(f"Permission refusée pour {operation}: {path}", "PERMISSION_ERROR", 403)
        self.path = path
        self.operation = operation


class ScanTimeoutError(ScannerError):
    """Timeout lors du scan"""
    def __init__(self, timeout: int):
        super().__init__(f"Timeout du scan après {timeout} secondes", "SCAN_TIMEOUT", 408)
        self.timeout = timeout


class QuarantineError(ScannerError):
    """Erreur lors de la mise en quarantaine"""
    def __init__(self, message: str, file_path: str = None):
        super().__init__(message, "QUARANTINE_ERROR", 500)
        self.file_path = file_path


class DatabaseError(ScannerError):
    """Erreur de base de données"""
    def __init__(self, message: str, operation: str = None):
        super().__init__(f"Erreur base de données: {message}", "DATABASE_ERROR", 500)
        self.operation = operation


class YaraError(ScannerError):
    """Erreur YARA"""
    def __init__(self, message: str):
        super().__init__(f"Erreur YARA: {message}", "YARA_ERROR", 500)


class ConfigurationError(ScannerError):
    """Erreur de configuration"""
    def __init__(self, message: str, config_key: str = None):
        super().__init__(f"Erreur de configuration: {message}", "CONFIG_ERROR", 500)
        self.config_key = config_key


def handle_scanner_error(func):
    """Décorateur pour gérer les erreurs du scanner"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ScannerError as e:
            logger = logging.getLogger(__name__)
            logger.error(f"ScannerError: {e.message} (Code: {e.error_code})")
            
            response = {
                'error': True,
                'error_code': e.error_code,
                'message': e.message,
                'status_code': e.status_code
            }
            
            # Ajouter des informations supplémentaires si disponibles
            if hasattr(e, 'path'):
                response['path'] = e.path
            if hasattr(e, 'field'):
                response['field'] = e.field
            if hasattr(e, 'operation'):
                response['operation'] = e.operation
            
            return jsonify(response), e.status_code
            
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Unexpected error in {func.__name__}: {str(e)}")
            logger.error(traceback.format_exc())
            
            return jsonify({
                'error': True,
                'error_code': 'INTERNAL_ERROR',
                'message': 'Erreur interne du serveur',
                'status_code': 500
            }), 500
    
    return wrapper


def validate_scan_request(data: Dict[str, Any]) -> None:
    """Valider une requête de scan"""
    errors = []
    
    # Validation du chemin
    if not data.get('folder'):
        errors.append('Le chemin du dossier est requis')
    elif not isinstance(data['folder'], str):
        errors.append('Le chemin du dossier doit être une chaîne de caractères')
    elif len(data['folder']) > 500:
        errors.append('Le chemin du dossier est trop long')
    else:
        # Validation de sécurité du chemin
        from scanner import validate_scan_path
        if not validate_scan_path(data['folder']):
            errors.append('Le chemin spécifié n\'est pas autorisé pour des raisons de sécurité')
    
    # Validation des options booléennes
    for field in ['recursive', 'analyze_content']:
        if field in data and data[field] is not None and not isinstance(data[field], bool):
            errors.append(f'Le champ {field} doit être un booléen')
    
    if errors:
        raise ValidationError('; '.join(errors))


def validate_quarantine_request(data: Dict[str, Any]) -> None:
    """Valider une requête de quarantaine"""
    errors = []
    
    if not data.get('file_id'):
        errors.append('L\'identifiant du fichier est requis')
    elif not isinstance(data['file_id'], str):
        errors.append('L\'identifiant du fichier doit être une chaîne de caractères')
    
    if errors:
        raise ValidationError('; '.join(errors))


def safe_file_operation(operation: str):
    """Décorateur pour les opérations sur fichiers avec gestion d'erreurs"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except PermissionError as e:
                raise PermissionError(str(e).split('\'')[1] if '\'' in str(e) else 'inconnu', operation)
            except FileNotFoundError as e:
                raise FileNotFoundError(str(e).split('\'')[1] if '\'' in str(e) else 'inconnu')
            except OSError as e:
                raise ScannerError(f"Erreur système lors de {operation}: {str(e)}", "OS_ERROR", 500)
        return wrapper
    return decorator


def log_api_request(func):
    """Décorateur pour logger les requêtes API"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger = logging.getLogger('api')
        
        # Logger la requête
        logger.info(f"API Request: {request.method} {request.path} from {request.remote_addr}")
        
        if request.json:
            logger.debug(f"Request data: {request.json}")
        
        try:
            result = func(*args, **kwargs)
            
            # Logger la réponse
            if hasattr(result, 'status_code'):
                logger.info(f"API Response: {result.status_code}")
            else:
                logger.info("API Response: 200")
            
            return result
            
        except Exception as e:
            logger.error(f"API Error in {func.__name__}: {str(e)}")
            raise
    
    return wrapper


class ErrorReporter:
    """Rapporteur d'erreurs pour le monitoring"""
    
    def __init__(self):
        self.logger = logging.getLogger('error_reporter')
        self.error_counts = {}
        self.last_errors = []
    
    def report_error(self, error: Exception, context: Dict[str, Any] = None):
        """Rapporter une erreur"""
        error_type = type(error).__name__
        
        # Compter les erreurs
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
        
        # Garder les dernières erreurs
        error_info = {
            'type': error_type,
            'message': str(error),
            'context': context or {},
            'timestamp': time.time(),
            'traceback': traceback.format_exc()
        }
        
        self.last_errors.append(error_info)
        
        # Garder seulement les 100 dernières erreurs
        if len(self.last_errors) > 100:
            self.last_errors = self.last_errors[-100:]
        
        # Logger l'erreur
        self.logger.error(f"Error reported: {error_type} - {str(error)}")
        if context:
            self.logger.error(f"Context: {context}")
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Obtenir un résumé des erreurs"""
        return {
            'error_counts': self.error_counts,
            'total_errors': sum(self.error_counts.values()),
            'recent_errors': len(self.last_errors),
            'last_error': self.last_errors[-1] if self.last_errors else None
        }
    
    def get_recent_errors(self, limit: int = 10) -> list:
        """Obtenir les erreurs récentes"""
        return self.last_errors[-limit:]


# Instance globale du rapporteur d'erreurs
error_reporter = ErrorReporter()


def setup_error_handlers(app):
    """Configurer les gestionnaires d'erreurs Flask"""
    
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            'error': True,
            'error_code': 'BAD_REQUEST',
            'message': 'Requête invalide',
            'status_code': 400
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({
            'error': True,
            'error_code': 'UNAUTHORIZED',
            'message': 'Non autorisé',
            'status_code': 401
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            'error': True,
            'error_code': 'FORBIDDEN',
            'message': 'Accès interdit',
            'status_code': 403
        }), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'error': True,
            'error_code': 'NOT_FOUND',
            'message': 'Ressource non trouvée',
            'status_code': 404
        }), 404
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({
            'error': True,
            'error_code': 'METHOD_NOT_ALLOWED',
            'message': 'Méthode non autorisée',
            'status_code': 405
        }), 405
    
    @app.errorhandler(413)
    def payload_too_large(error):
        return jsonify({
            'error': True,
            'error_code': 'PAYLOAD_TOO_LARGE',
            'message': 'Fichier trop volumineux',
            'status_code': 413
        }), 413
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return jsonify({
            'error': True,
            'error_code': 'RATE_LIMIT_EXCEEDED',
            'message': 'Trop de requêtes - veuillez réessayer plus tard',
            'status_code': 429
        }), 429
    
    @app.errorhandler(500)
    def internal_server_error(error):
        error_reporter.report_error(error, {
            'path': request.path,
            'method': request.method,
            'remote_addr': request.remote_addr
        })
        
        return jsonify({
            'error': True,
            'error_code': 'INTERNAL_SERVER_ERROR',
            'message': 'Erreur interne du serveur',
            'status_code': 500
        }), 500
    
    @app.errorhandler(ScannerError)
    def handle_scanner_exception(error):
        error_reporter.report_error(error, {
            'path': request.path,
            'method': request.method,
            'remote_addr': request.remote_addr
        })
        
        response = {
            'error': True,
            'error_code': error.error_code,
            'message': error.message,
            'status_code': error.status_code
        }
        
        # Ajouter des informations supplémentaires
        if hasattr(error, 'path'):
            response['path'] = error.path
        if hasattr(error, 'field'):
            response['field'] = error.field
        
        return jsonify(response), error.status_code


# Fonctions utilitaires pour la gestion d'erreurs
def create_error_response(error_code: str, message: str, status_code: int = 400, **kwargs) -> tuple:
    """Créer une réponse d'erreur standardisée"""
    response = {
        'error': True,
        'error_code': error_code,
        'message': message,
        'status_code': status_code
    }
    response.update(kwargs)
    
    return jsonify(response), status_code


def log_function_call(func):
    """Décorateur pour logger les appels de fonction"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger = logging.getLogger(func.__module__)
        logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
        
        try:
            result = func(*args, **kwargs)
            logger.debug(f"{func.__name__} completed successfully")
            return result
        except Exception as e:
            logger.error(f"{func.__name__} failed: {str(e)}")
            raise
    
    return wrapper

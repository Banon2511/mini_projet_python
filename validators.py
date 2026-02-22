"""
Schémas de validation avec Marshmallow pour MiniSec Scanner
"""
import os
import re
from marshmallow import Schema, fields, validate, validates, ValidationError, post_load
from typing import Dict, Any, Optional


class ScanRequestSchema(Schema):
    """Schéma de validation pour les requêtes de scan"""
    folder = fields.Str(required=True, validate=validate.Length(min=1, max=500))
    recursive = fields.Bool(missing=False)
    analyze_content = fields.Bool(missing=False)
    
    @validates('folder')
    def validate_folder_path(self, value):
        """Valider que le chemin du dossier est sûr et valide"""
        # Normaliser le chemin
        normalized_path = os.path.normpath(value)
        
        # Vérifier que le chemin n'est pas vide
        if not normalized_path.strip():
            raise ValidationError("Le chemin du dossier ne peut pas être vide")
        
        # Vérifier les caractères dangereux
        dangerous_patterns = [
            r'\.\./.*',  # Directory traversal
            r'^\.\.[/\\]',  # Commence par ../
            r'^[\\/]',  # Commence par / ou \
            r'[<>:"|?*]',  # Caractères interdits Windows
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValidationError("Le chemin contient des caractères dangereux")
        
        # Vérifier les chemins système dangereux
        dangerous_paths = [
            '/System', '/Windows', '/Program Files', '/Program Files (x86)',
            '/usr/bin', '/usr/sbin', '/bin', '/sbin', '/boot', '/dev',
            'C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)',
            '/etc', '/proc', '/sys'
        ]
        
        normalized_lower = normalized_path.lower()
        for dangerous in dangerous_paths:
            if normalized_lower.startswith(dangerous.lower()):
                raise ValidationError("Le chemin spécifié n'est pas autorisé pour des raisons de sécurité")
        
        # Vérifier que le chemin existe (optionnel, car peut être vérifié plus tard)
        # if not os.path.exists(normalized_path):
        #     raise ValidationError("Le chemin spécifié n'existe pas")
    
    @post_load
    def make_scan_request(self, data, **kwargs):
        """Créer l'objet de requête de scan"""
        return data


class QuarantineRequestSchema(Schema):
    """Schéma de validation pour les requêtes de quarantaine"""
    file_id = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    reason = fields.Str(missing="Mise en quarantaine automatique", validate=validate.Length(max=500))
    
    @validates('file_id')
    def validate_file_id(self, value):
        """Valider l'identifiant du fichier"""
        if not value or not value.strip():
            raise ValidationError("L'identifiant du fichier est requis")
        
        # Vérifier les caractères valides
        if not re.match(r'^[a-zA-Z0-9_\-\.\\\/]+$', value):
            raise ValidationError("L'identifiant du fichier contient des caractères invalides")
    
    @post_load
    def make_quarantine_request(self, data, **kwargs):
        """Créer l'objet de requête de quarantaine"""
        return data


class ScanScheduleSchema(Schema):
    """Schéma de validation pour la planification de scans"""
    name = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    folder_path = fields.Str(required=True, validate=validate.Length(min=1, max=500))
    recursive = fields.Bool(missing=True)
    analyze_content = fields.Bool(missing=True)
    schedule_type = fields.Str(required=True, validate=validate.OneOf(['daily', 'weekly', 'monthly']))
    schedule_interval = fields.Int(missing=1, validate=validate.Range(min=1, max=365))
    schedule_time = fields.Time(required=False)
    is_active = fields.Bool(missing=True)
    
    @validates('folder_path')
    def validate_folder_path(self, value):
        """Valider le chemin du dossier (même validation que ScanRequestSchema)"""
        ScanRequestSchema().validate({'folder': value, 'recursive': False, 'analyze_content': False})
    
    @validates('schedule_interval')
    def validate_schedule_interval(self, value, **kwargs):
        """Valider que l'intervalle est cohérent avec le type de schedule"""
        schedule_type = kwargs.get('schedule_type', 'daily')
        
        if schedule_type == 'daily' and value > 365:
            raise ValidationError("L'intervalle quotidien ne peut pas dépasser 365 jours")
        elif schedule_type == 'weekly' and value > 52:
            raise ValidationError("L'intervalle hebdomadaire ne peut pas dépasser 52 semaines")
        elif schedule_type == 'monthly' and value > 12:
            raise ValidationError("L'intervalle mensuel ne peut pas dépasser 12 mois")
    
    @post_load
    def make_scan_schedule(self, data, **kwargs):
        """Créer l'objet de planification de scan"""
        return data


class SystemSettingsSchema(Schema):
    """Schéma de validation pour les paramètres système"""
    key = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    value = fields.Str(required=True, validate=validate.Length(max=1000))
    value_type = fields.Str(missing='string', validate=validate.OneOf(['string', 'integer', 'boolean', 'json']))
    description = fields.Str(missing="", validate=validate.Length(max=500))
    
    @validates('key')
    def validate_key(self, value):
        """Valider la clé du paramètre"""
        if not re.match(r'^[a-zA-Z0-9_\-]+$', value):
            raise ValidationError("La clé ne peut contenir que des lettres, chiffres, underscores et tirets")
    
    @validates('value')
    def validate_value(self, value, **kwargs):
        """Valider la valeur selon son type"""
        value_type = kwargs.get('value_type', 'string')
        
        if value_type == 'integer':
            try:
                int(value)
            except ValueError:
                raise ValidationError("La valeur doit être un entier")
        elif value_type == 'boolean':
            if value.lower() not in ['true', 'false']:
                raise ValidationError("La valeur doit être 'true' ou 'false'")
        elif value_type == 'json':
            import json
            try:
                json.loads(value)
            except json.JSONDecodeError:
                raise ValidationError("La valeur doit être un JSON valide")
    
    @post_load
    def make_system_setting(self, data, **kwargs):
        """Créer l'objet de paramètre système"""
        return data


class ScanHistoryQuerySchema(Schema):
    """Schéma de validation pour les requêtes d'historique de scans"""
    limit = fields.Int(missing=10, validate=validate.Range(min=1, max=100))
    offset = fields.Int(missing=0, validate=validate.Range(min=0))
    folder_path = fields.Str(missing=None, validate=validate.Length(max=500))
    start_date = fields.DateTime(missing=None)
    end_date = fields.DateTime(missing=None)
    risk_level = fields.Str(missing=None, validate=validate.OneOf(['High', 'Medium', 'Low']))
    
    @validates('start_date')
    def validate_date_range(self, value, **kwargs):
        """Valider que la date de début est avant la date de fin"""
        end_date = kwargs.get('end_date')
        if end_date and value > end_date:
            raise ValidationError("La date de début doit être antérieure à la date de fin")
    
    @post_load
    def make_history_query(self, data, **kwargs):
        """Créer l'objet de requête d'historique"""
        return data


class ExportRequestSchema(Schema):
    """Schéma de validation pour les requêtes d'export"""
    format = fields.Str(required=True, validate=validate.OneOf(['json', 'csv', 'xml']))
    scan_id = fields.Int(required=True, validate=validate.Range(min=1))
    include_details = fields.Bool(missing=True)
    
    @post_load
    def make_export_request(self, data, **kwargs):
        """Créer l'objet de requête d'export"""
        return data


class FileOperationSchema(Schema):
    """Schéma de validation pour les opérations sur fichiers"""
    operation = fields.Str(required=True, validate=validate.OneOf(['restore', 'delete', 'move']))
    file_id = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    destination = fields.Str(missing=None, validate=validate.Length(max=500))
    
    @validates('file_id')
    def validate_file_id(self, value):
        """Valider l'identifiant du fichier"""
        if not re.match(r'^[a-zA-Z0-9_\-\.\\\/]+$', value):
            raise ValidationError("L'identifiant du fichier contient des caractères invalides")
    
    @validates('destination')
    def validate_destination(self, value, **kwargs):
        """Valider le chemin de destination si nécessaire"""
        operation = kwargs.get('operation')
        
        if operation == 'move' and not value:
            raise ValidationError("La destination est requise pour l'opération de déplacement")
        
        if value:
            # Valider que le chemin de destination est sûr
            dangerous_patterns = [
                r'\.\./.*',
                r'^\.\.[/\\]',
                r'[<>:"|?*]',
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    raise ValidationError("Le chemin de destination contient des caractères dangereux")
    
    @post_load
    def make_file_operation(self, data, **kwargs):
        """Créer l'objet d'opération sur fichier"""
        return data


class ValidationUtils:
    """Utilitaires de validation"""
    
    @staticmethod
    def validate_path_security(path: str) -> bool:
        """Valider la sécurité d'un chemin"""
        if not path or not isinstance(path, str):
            return False
        
        # Normaliser le chemin
        normalized = os.path.normpath(path)
        
        # Vérifier les patterns dangereux
        dangerous_patterns = [
            r'\.\./.*',
            r'^\.\.[/\\]',
            r'^[\\/]',
            r'[<>:"|?*]',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return False
        
        # Vérifier les chemins système
        system_paths = [
            '/System', '/Windows', '/Program Files',
            '/usr/bin', '/usr/sbin', '/bin', '/sbin',
            'C:\\Windows', 'C:\\Program Files'
        ]
        
        normalized_lower = normalized.lower()
        for sys_path in system_paths:
            if normalized_lower.startswith(sys_path.lower()):
                return False
        
        return True
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Nettoyer un nom de fichier"""
        if not filename:
            return "unnamed_file"
        
        # Remplacer les caractères dangereux
        sanitized = re.sub(r'[<>:"|?*]', '_', filename)
        
        # Limiter la longueur
        if len(sanitized) > 255:
            name, ext = os.path.splitext(sanitized)
            sanitized = name[:255-len(ext)] + ext
        
        return sanitized
    
    @staticmethod
    def validate_file_size(size: int, max_size: int = 50 * 1024 * 1024) -> bool:
        """Valider la taille d'un fichier"""
        return 0 <= size <= max_size
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Valider une adresse IP"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Valider une adresse email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None


# Fonction de validation principale
def validate_request_data(schema_class: Schema, data: Dict[str, Any]) -> Dict[str, Any]:
    """Valider les données de requête avec un schéma Marshmallow"""
    try:
        schema = schema_class()
        return schema.load(data)
    except ValidationError as e:
        # Formater les erreurs pour une meilleure API response
        errors = {}
        for field, field_errors in e.messages.items():
            errors[field] = field_errors if isinstance(field_errors, list) else [field_errors]
        
        raise ValidationError(errors)


# Décorateurs de validation
def validate_scan_request(func):
    """Décorateur pour valider les requêtes de scan"""
    def wrapper(*args, **kwargs):
        from flask import request
        from error_handlers import ValidationError
        
        try:
            data = validate_request_data(ScanRequestSchema, request.json or {})
            return func(data, *args, **kwargs)
        except ValidationError as e:
            from error_handlers import ValidationError as CustomValidationError
            raise CustomValidationError(f"Erreur de validation: {e.messages}")
    
    return wrapper


def validate_quarantine_request(func):
    """Décorateur pour valider les requêtes de quarantaine"""
    def wrapper(*args, **kwargs):
        from flask import request
        from error_handlers import ValidationError
        
        try:
            data = validate_request_data(QuarantineRequestSchema, request.json or {})
            return func(data, *args, **kwargs)
        except ValidationError as e:
            from error_handlers import ValidationError as CustomValidationError
            raise CustomValidationError(f"Erreur de validation: {e.messages}")
    
    return wrapper


def validate_system_settings(func):
    """Décorateur pour valider les paramètres système"""
    def wrapper(*args, **kwargs):
        from flask import request
        from error_handlers import ValidationError
        
        try:
            data = validate_request_data(SystemSettingsSchema, request.json or {})
            return func(data, *args, **kwargs)
        except ValidationError as e:
            from error_handlers import ValidationError as CustomValidationError
            raise CustomValidationError(f"Erreur de validation: {e.messages}")
    
    return wrapper

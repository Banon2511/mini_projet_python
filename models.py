"""
Modèles de données pour MiniSec Scanner
Base de données pour l'historique des scans et la persistance
"""
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Index, JSON
import json

db = SQLAlchemy()


class ScanHistory(db.Model):
    """Historique des scans effectués"""
    __tablename__ = 'scan_history'
    
    id = db.Column(db.Integer, primary_key=True)
    folder_path = db.Column(db.String(500), nullable=False)
    recursive = db.Column(db.Boolean, default=False, nullable=False)
    analyze_content = db.Column(db.Boolean, default=False, nullable=False)
    
    # Statistiques du scan
    total_files = db.Column(db.Integer, default=0)
    analyzed_files = db.Column(db.Integer, default=0)
    high_risk_count = db.Column(db.Integer, default=0)
    medium_risk_count = db.Column(db.Integer, default=0)
    low_risk_count = db.Column(db.Integer, default=0)
    
    # Métadonnées
    scan_duration = db.Column(db.Float)  # en secondes
    scan_status = db.Column(db.String(20), default='completed')
    yara_available = db.Column(db.Boolean, default=False)
    
    # Timestamps
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    completed_at = db.Column(db.DateTime)
    
    # Résultats complets (JSON)
    results_json = db.Column(db.Text)  # Stockage JSON des résultats détaillés
    
    # Index pour les performances
    __table_args__ = (
        Index('idx_scan_folder', 'folder_path'),
        Index('idx_scan_date', 'started_at'),
        Index('idx_scan_status', 'scan_status'),
    )
    
    def __repr__(self):
        return f'<ScanHistory {self.id}: {self.folder_path}>'
    
    def to_dict(self):
        """Convertir en dictionnaire pour l'API"""
        return {
            'id': self.id,
            'folder_path': self.folder_path,
            'recursive': self.recursive,
            'analyze_content': self.analyze_content,
            'total_files': self.total_files,
            'analyzed_files': self.analyzed_files,
            'high_risk_count': self.high_risk_count,
            'medium_risk_count': self.medium_risk_count,
            'low_risk_count': self.low_risk_count,
            'scan_duration': self.scan_duration,
            'scan_status': self.scan_status,
            'yara_available': self.yara_available,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'threat_percentage': ((self.high_risk_count + self.medium_risk_count) / 
                                max(1, self.analyzed_files) * 100) if self.analyzed_files > 0 else 0
        }
    
    def get_results(self):
        """Récupérer les résultats détaillés"""
        if self.results_json:
            try:
                return json.loads(self.results_json)
            except json.JSONDecodeError:
                return []
        return []
    
    def set_results(self, results):
        """Définir les résultats détaillés"""
        if results:
            self.results_json = json.dumps(results, default=str)
        else:
            self.results_json = None
    
    @classmethod
    def get_recent_scans(cls, limit=10):
        """Récupérer les scans récents"""
        return cls.query.order_by(cls.started_at.desc()).limit(limit).all()
    
    @classmethod
    def get_scans_by_folder(cls, folder_path, limit=50):
        """Récupérer les scans pour un dossier spécifique"""
        return cls.query.filter_by(folder_path=folder_path)\
                       .order_by(cls.started_at.desc())\
                       .limit(limit).all()
    
    @classmethod
    def get_statistics(cls, days=30):
        """Récupérer les statistiques globales"""
        since_date = datetime.utcnow() - timedelta(days=days)
        
        scans = cls.query.filter(cls.started_at >= since_date).all()
        
        total_scans = len(scans)
        total_files = sum(s.total_files for s in scans)
        total_threats = sum(s.high_risk_count + s.medium_risk_count for s in scans)
        avg_duration = sum(s.scan_duration or 0 for s in scans) / max(1, total_scans)
        
        return {
            'total_scans': total_scans,
            'total_files_scanned': total_files,
            'total_threats_detected': total_threats,
            'average_scan_duration': avg_duration,
            'threat_detection_rate': (total_threats / max(1, total_files)) * 100
        }


class QuarantinedFile(db.Model):
    """Fichiers mis en quarantaine"""
    __tablename__ = 'quarantined_files'
    
    id = db.Column(db.Integer, primary_key=True)
    original_path = db.Column(db.String(500), nullable=False)
    quarantine_path = db.Column(db.String(500), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    
    # Informations sur le fichier
    file_size = db.Column(db.Integer)
    file_extension = db.Column(db.String(10))
    file_hash = db.Column(db.String(64))  # SHA-256
    
    # Raison de la quarantaine
    risk_level = db.Column(db.String(10), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    detection_reasons = db.Column(db.Text)  # JSON
    
    # Métadonnées
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_history.id'))
    quarantined_by = db.Column(db.String(100))  # IP ou utilisateur
    quarantined_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Status
    status = db.Column(db.String(20), default='quarantined')  # quarantined, restored, deleted
    
    # Relations
    scan = db.relationship('ScanHistory', backref=db.backref('quarantined_files', lazy=True))
    
    __table_args__ = (
        Index('idx_quarantine_file', 'original_path'),
        Index('idx_quarantine_date', 'quarantined_at'),
        Index('idx_quarantine_status', 'status'),
        Index('idx_quarantine_hash', 'file_hash'),
    )
    
    def __repr__(self):
        return f'<QuarantinedFile {self.id}: {self.original_name}>'
    
    def to_dict(self):
        """Convertir en dictionnaire pour l'API"""
        return {
            'id': self.id,
            'original_path': self.original_path,
            'original_name': self.original_name,
            'file_size': self.file_size,
            'file_extension': self.file_extension,
            'file_hash': self.file_hash,
            'risk_level': self.risk_level,
            'risk_score': self.risk_score,
            'detection_reasons': json.loads(self.detection_reasons) if self.detection_reasons else [],
            'scan_id': self.scan_id,
            'quarantined_by': self.quarantined_by,
            'quarantined_at': self.quarantined_at.isoformat() if self.quarantined_at else None,
            'status': self.status
        }
    
    def get_detection_reasons(self):
        """Récupérer les raisons de détection"""
        if self.detection_reasons:
            try:
                return json.loads(self.detection_reasons)
            except json.JSONDecodeError:
                return []
        return []
    
    def set_detection_reasons(self, reasons):
        """Définir les raisons de détection"""
        if reasons:
            self.detection_reasons = json.dumps(reasons)
        else:
            self.detection_reasons = None


class ScanSchedule(db.Model):
    """Planification de scans automatiques"""
    __tablename__ = 'scan_schedules'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    folder_path = db.Column(db.String(500), nullable=False)
    
    # Configuration du scan
    recursive = db.Column(db.Boolean, default=True)
    analyze_content = db.Column(db.Boolean, default=True)
    
    # Planification
    schedule_type = db.Column(db.String(20), nullable=False)  # daily, weekly, monthly
    schedule_interval = db.Column(db.Integer, default=1)  # tous les X jours/semains/mois
    schedule_time = db.Column(db.Time)  # Heure d'exécution
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    last_run = db.Column(db.DateTime)
    next_run = db.Column(db.DateTime)
    
    # Métadonnées
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by = db.Column(db.String(100))
    
    __table_args__ = (
        Index('idx_schedule_folder', 'folder_path'),
        Index('idx_schedule_active', 'is_active'),
        Index('idx_schedule_next_run', 'next_run'),
    )
    
    def __repr__(self):
        return f'<ScanSchedule {self.id}: {self.name}>'
    
    def to_dict(self):
        """Convertir en dictionnaire pour l'API"""
        return {
            'id': self.id,
            'name': self.name,
            'folder_path': self.folder_path,
            'recursive': self.recursive,
            'analyze_content': self.analyze_content,
            'schedule_type': self.schedule_type,
            'schedule_interval': self.schedule_interval,
            'schedule_time': self.schedule_time.isoformat() if self.schedule_time else None,
            'is_active': self.is_active,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'next_run': self.next_run.isoformat() if self.next_run else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.created_by
        }
    
    def calculate_next_run(self):
        """Calculer la prochaine date d'exécution"""
        from datetime import time as dt_time
        
        now = datetime.utcnow()
        
        if self.schedule_type == 'daily':
            next_run = now + timedelta(days=self.schedule_interval)
        elif self.schedule_type == 'weekly':
            next_run = now + timedelta(weeks=self.schedule_interval)
        elif self.schedule_type == 'monthly':
            next_run = now + timedelta(days=30 * self.schedule_interval)
        else:
            next_run = now + timedelta(days=1)
        
        # Appliquer l'heure spécifiée
        if self.schedule_time:
            next_run = next_run.replace(
                hour=self.schedule_time.hour,
                minute=self.schedule_time.minute,
                second=self.schedule_time.second,
                microsecond=0
            )
        
        self.next_run = next_run
        return next_run


class SystemSettings(db.Model):
    """Paramètres système globaux"""
    __tablename__ = 'system_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    value_type = db.Column(db.String(20), default='string')  # string, integer, boolean, json
    description = db.Column(db.Text)
    
    # Métadonnées
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.String(100))
    
    __table_args__ = (
        Index('idx_settings_key', 'key'),
    )
    
    def __repr__(self):
        return f'<SystemSettings {self.key}: {self.value}>'
    
    def to_dict(self):
        """Convertir en dictionnaire pour l'API"""
        # Convertir la valeur selon son type
        if self.value_type == 'integer':
            value = int(self.value) if self.value else 0
        elif self.value_type == 'boolean':
            value = self.value.lower() == 'true' if self.value else False
        elif self.value_type == 'json':
            try:
                value = json.loads(self.value) if self.value else {}
            except json.JSONDecodeError:
                value = {}
        else:
            value = self.value
        
        return {
            'id': self.id,
            'key': self.key,
            'value': value,
            'value_type': self.value_type,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'updated_by': self.updated_by
        }
    
    @classmethod
    def get_setting(cls, key, default=None):
        """Récupérer un paramètre"""
        setting = cls.query.filter_by(key=key).first()
        if not setting:
            return default
        
        if setting.value_type == 'integer':
            return int(setting.value) if setting.value else 0
        elif setting.value_type == 'boolean':
            return setting.value.lower() == 'true' if setting.value else False
        elif setting.value_type == 'json':
            try:
                return json.loads(setting.value) if setting.value else {}
            except json.JSONDecodeError:
                return {}
        else:
            return setting.value
    
    @classmethod
    def set_setting(cls, key, value, value_type='string', description=None, updated_by=None):
        """Définir un paramètre"""
        setting = cls.query.filter_by(key=key).first()
        
        if value_type == 'json':
            value = json.dumps(value)
        elif value_type == 'boolean':
            value = str(value).lower()
        
        if setting:
            setting.value = value
            setting.value_type = value_type
            setting.updated_by = updated_by
            setting.updated_at = datetime.utcnow()
        else:
            setting = cls(
                key=key,
                value=value,
                value_type=value_type,
                description=description,
                updated_by=updated_by
            )
            db.session.add(setting)
        
        db.session.commit()
        return setting


# Fonctions utilitaires pour la base de données
def init_db():
    """Initialiser la base de données"""
    db.create_all()
    
    # Créer les paramètres système par défaut
    default_settings = [
        ('max_scan_duration', 300, 'integer', 'Durée maximale d\'un scan en secondes'),
        ('auto_quarantine_high_risk', True, 'boolean', 'Mettre automatiquement en quarantaine les fichiers à haut risque'),
        ('retention_days', 30, 'integer', 'Nombre de jours de conservation des historiques'),
        ('enable_notifications', False, 'boolean', 'Activer les notifications par email'),
        ('default_scan_recursive', True, 'boolean', 'Scan récursif par défaut'),
        ('default_analyze_content', False, 'boolean', 'Analyse de contenu par défaut'),
    ]
    
    for key, value, value_type, description in default_settings:
        if not SystemSettings.query.filter_by(key=key).first():
            setting = SystemSettings(
                key=key,
                value=str(value),
                value_type=value_type,
                description=description
            )
            db.session.add(setting)
    
    db.session.commit()


def cleanup_old_records():
    """Nettoyer les anciens enregistrements"""
    retention_days = SystemSettings.get_setting('retention_days', 30)
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
    
    # Nettoyer les anciens scans
    old_scans = ScanHistory.query.filter(ScanHistory.started_at < cutoff_date).all()
    for scan in old_scans:
        db.session.delete(scan)
    
    # Nettoyer les fichiers de quarantaine supprimés depuis plus de 7 jours
    quarantine_cutoff = datetime.utcnow() - timedelta(days=7)
    old_quarantine = QuarantinedFile.query.filter(
        QuarantinedFile.status == 'deleted',
        QuarantinedFile.quarantined_at < quarantine_cutoff
    ).all()
    
    for file in old_quarantine:
        db.session.delete(file)
    
    db.session.commit()
    return len(old_scans) + len(old_quarantine)

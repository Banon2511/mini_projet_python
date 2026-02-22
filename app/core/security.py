"""Validation des chemins de scan (sandbox et chemins dangereux)"""
import os
from pathlib import Path


def validate_scan_path_safe(path: str) -> bool:
    """Valide qu'un chemin n'est pas un dossier système sensible (fallback sans config)."""
    if not path or not isinstance(path, str):
        return False
    try:
        dangerous = [
            '/system', '/windows', '/program files', '/usr/bin', '/usr/sbin',
            '/bin', '/sbin', '/boot', '/dev', '/etc', '/proc', '/sys',
            'c:\\windows', 'c:\\program files', 'c:\\etc'
        ]
        resolved = str(Path(path).expanduser().resolve()).replace("\\", "/").lower()
        for d in dangerous:
            d_n = d.replace("\\", "/")
            if resolved.startswith(d_n) or f"/{d_n}" in resolved:
                return False
        return True
    except (OSError, ValueError):
        return False


def validate_scan_path(path: str, allowed_base: str = None) -> bool:
    """Vérifie que le chemin est dans le sandbox autorisé."""
    if not path or not isinstance(path, str):
        return False
    try:
        from config import Config
        base = allowed_base or Config.SCAN_SANDBOX
        allowed = os.path.abspath(base)
        resolved = os.path.abspath(os.path.normpath(path))
        return resolved.startswith(allowed)
    except Exception:
        return False

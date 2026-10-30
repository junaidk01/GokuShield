"""
GoKushield AI v1.0
API Blueprints Initialization
"""

from .auth import auth_bp
from .scans import scans_bp
from .admin import admin_bp
from .client import client_bp
from .services import services_bp
from .chatbot import chatbot_bp
from .payments import payments_bp

__all__ = [
    'auth_bp',
    'scans_bp',
    'admin_bp',
    'client_bp',
    'services_bp',
    'chatbot_bp',
    'payments_bp'
]

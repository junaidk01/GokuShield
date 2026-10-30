"""
Enterprise Integration Patch
=============================

This file adds enterprise module integration to app.py
WITHOUT modifying existing production logic.

Add this to app.py after line 126:
"""

# Enterprise module integration (add after free_audit_bp registration)
try:
    from enterprise.api import enterprise_bp
    app.register_blueprint(enterprise_bp, url_prefix='/api/enterprise')
    app.logger.info("Enterprise module enabled")
except ImportError:
    app.logger.warning("Enterprise module not available")

# Initialize enterprise components
try:
    from enterprise import is_feature_enabled
    from enterprise.siem import get_siem_manager
    from enterprise.plugins import get_plugin_registry
    
    # Initialize SIEM manager (passive logging only)
    app.siem_manager = get_siem_manager()
    
    # Initialize plugin registry
    app.plugin_registry = get_plugin_registry()
    
    app.logger.info("Enterprise components initialized")
except Exception as e:
    app.logger.warning(f"Enterprise components initialization skipped: {e}")

from flask import Flask, jsonify, request, send_file, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from celery import Celery
import os
import logging
import redis
from datetime import datetime
from logging.handlers import RotatingFileHandler

from config import config, VERSION
from models import db, bcrypt
from api import auth_bp, client_bp, admin_bp, scans_bp, services_bp, chatbot_bp, payments_bp
from api.free_audit import free_audit_bp
from enterprise.api import enterprise_bp
from utils.decorators import rate_limit
from ai.security_engine import OllamaClient, SecurityEngine
from middleware.security import add_security_headers

def create_celery_app(app=None):
    """Create Celery instance with beat schedule"""
    app = app or create_app()
    
    celery = Celery(
        app.import_name,
        broker=app.config['CELERY_BROKER_URL'],
        backend=app.config['CELERY_RESULT_BACKEND']
    )
    
    celery.conf.update(app.config)
    
    # Configure Celery Beat schedule
    from celery.schedules import crontab
    celery.conf.beat_schedule = {
        'reset-daily-usage': {
            'task': 'tasks.security_tasks.reset_daily_usage',
            'schedule': crontab(hour=0, minute=0),  # Daily at midnight UTC
        },
        'reset-monthly-usage': {
            'task': 'tasks.security_tasks.reset_monthly_usage',
            'schedule': crontab(day_of_month=1, hour=0, minute=0),  # 1st of month
        },
        'cleanup-expired-blacklists': {
            'task': 'tasks.security_tasks.cleanup_expired_blacklists',
            'schedule': crontab(minute=0),  # Every hour
        },
        'health-check-ollama': {
            'task': 'tasks.security_tasks.health_check_ollama',
            'schedule': 300.0,  # Every 5 minutes
        },
        'health-check-system': {
            'task': 'tasks.security_tasks.health_check_system',
            'schedule': 900.0,  # Every 15 minutes
        },
        'process-outreach-queue': {
            'task': 'tasks.security_tasks.process_outreach_queue',
            'schedule': 600.0,  # Every 10 minutes
        },
        'follow-up-unconverted-leads': {
            'task': 'tasks.security_tasks.follow_up_unconverted_leads',
            'schedule': crontab(hour=10, minute=0),  # Daily at 10am UTC
        },
    }
    celery.conf.timezone = 'UTC'
    
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    return celery

def create_app(config_name='production'):
    """Application factory"""
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    jwt = JWTManager(app)
    Migrate(app, db)
    
    # CORS
    CORS(app, origins=app.config['CORS_ORIGINS'], supports_credentials=True)
    
    # Logging
    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/gokushield.log', maxBytes=10240000, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info(f'{VERSION} startup')
    
    # Initialize Ollama
    ollama_client = OllamaClient(
        base_url=app.config['OLLAMA_BASE_URL'],
        default_model=app.config['OLLAMA_DEFAULT_MODEL'],
        timeout=app.config['OLLAMA_TIMEOUT']
    )
    
    security_engine = SecurityEngine(ollama_client)
    app.security_engine = security_engine
    app.ollama_client = ollama_client
    
    # Initialize Redis
    try:
        app.redis_client = redis.from_url(app.config['REDIS_URL'])
        app.redis_client.ping()
    except Exception as e:
        app.logger.error(f"Redis connection failed: {e}")
        app.redis_client = None
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(client_bp, url_prefix='/api/client')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(scans_bp, url_prefix='/api/scans')
    app.register_blueprint(services_bp, url_prefix='/api')
    app.register_blueprint(chatbot_bp, url_prefix='/api/chatbot')
    app.register_blueprint(free_audit_bp, url_prefix='/api/free-audit')
    app.register_blueprint(enterprise_bp, url_prefix='/api/enterprise')
    app.register_blueprint(payments_bp, url_prefix='/api/payments')
    
    # Add security headers to all responses
    @app.after_request
    def after_request(response):
        return add_security_headers(response)
    
    # Health check endpoint - PRODUCTION READY
    @app.route('/health', methods=['GET'])
    def health_check():
        from models import Service
        
        health_status = {
            'version': VERSION,
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'components': {
                'api': 'up',
                'database': 'unknown',
                'redis': 'unknown',
                'celery': 'unknown',
                'ollama': 'unknown'
            },
            'services': {
                'enabled_count': 0,
                'total_count': 0
            }
        }
        
        # Check database
        try:
            from sqlalchemy import text
            db.session.execute(text('SELECT 1'))
            health_status['components']['database'] = 'up'
            
            # Get service count
            total_services = Service.query.count()
            enabled_services = Service.query.filter_by(is_enabled=True).count()
            health_status['services']['total_count'] = total_services
            health_status['services']['enabled_count'] = enabled_services
            
        except Exception as e:
            health_status['components']['database'] = 'down'
            health_status['status'] = 'degraded'
            health_status['errors'] = health_status.get('errors', [])
            health_status['errors'].append(f'Database: {str(e)}')
            app.logger.error(f"Database health check failed: {e}")
        
        # Check Redis
        if app.redis_client:
            try:
                app.redis_client.ping()
                health_status['components']['redis'] = 'up'
            except Exception as e:
                health_status['components']['redis'] = 'down'
                health_status['status'] = 'degraded'
                health_status['errors'] = health_status.get('errors', [])
                health_status['errors'].append(f'Redis: {str(e)}')
        else:
            health_status['components']['redis'] = 'down'
            health_status['status'] = 'degraded'
        
        # Check Ollama with inference test
        try:
            if ollama_client.is_available():
                # Test actual inference
                test_response = ollama_client.generate(
                    prompt='Respond with OK',
                    model=ollama_client.default_model
                )
                if test_response:
                    health_status['components']['ollama'] = 'up'
                    health_status['ollama_model'] = ollama_client.default_model
                else:
                    health_status['components']['ollama'] = 'degraded'
                    health_status['status'] = 'degraded'
            else:
                health_status['components']['ollama'] = 'down'
                health_status['status'] = 'critical'
                health_status['errors'] = health_status.get('errors', [])
                health_status['errors'].append('Ollama: AI service unavailable - system cannot process scans')
        except Exception as e:
            health_status['components']['ollama'] = 'down'
            health_status['status'] = 'critical'
            health_status['errors'] = health_status.get('errors', [])
            health_status['errors'].append(f'Ollama: {str(e)}')
        
        # Check Celery
        try:
            from celery import current_app as celery_app
            inspect = celery_app.control.inspect()
            stats = inspect.stats()
            if stats:
                health_status['components']['celery'] = 'up'
                health_status['celery_workers'] = len(stats)
            else:
                health_status['components']['celery'] = 'down'
                health_status['status'] = 'degraded'
        except Exception as e:
            health_status['components']['celery'] = 'unknown'
            app.logger.warning(f"Celery health check failed: {e}")
        
        # Determine overall status code
        if health_status['status'] == 'critical':
            status_code = 503
        elif health_status['status'] == 'degraded':
            status_code = 503
        else:
            status_code = 200
        
        return jsonify(health_status), status_code
    
    # Root and static UI endpoints
    @app.route('/', methods=['GET'])
    def index():
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        frontend_index = os.path.join(base_dir, 'frontend', 'index.html')
        # If client explicitly asks for JSON, or frontend file missing, return API status
        if request.headers.get('Accept') == 'application/json' or not os.path.exists(frontend_index):
            return jsonify({
                'version': VERSION,
                'api': 'GoKushield AI',
                'status': 'active',
                'endpoints': {
                    'health': '/health',
                    'auth': '/api/auth',
                    'client': '/api/client',
                    'admin': '/api/admin',
                    'scans': '/api/scans',
                    'payments': '/api/payments',
                    'chatbot': '/api/chatbot'
                }
            })
        return send_file(frontend_index)

    @app.route('/client-dashboard', methods=['GET'])
    @app.route('/client-dashboard/', methods=['GET'])
    @app.route('/client-dashboard/<path:filename>', methods=['GET'])
    def serve_client_dashboard(filename='client-dashboard.html'):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        folder = os.path.join(base_dir, 'client-dashboard')
        if not filename or filename == '':
            filename = 'client-dashboard.html'
        return send_from_directory(folder, filename)

    @app.route('/admin-panel', methods=['GET'])
    @app.route('/admin-panel/', methods=['GET'])
    @app.route('/admin-panel/<path:filename>', methods=['GET'])
    def serve_admin_panel(filename='admin-panel.html'):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        folder = os.path.join(base_dir, 'admin-panel')
        if not filename or filename == '':
            filename = 'admin-panel.html'
        return send_from_directory(folder, filename)

    @app.route('/frontend/<path:filename>', methods=['GET'])
    def serve_frontend_assets(filename):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        folder = os.path.join(base_dir, 'frontend')
        return send_from_directory(folder, filename)
    
    # Service status endpoint
    @app.route('/api/services', methods=['GET'])
    def list_services():
        from models import Service, ServiceStatus
        
        services = Service.query.filter_by(is_enabled=True).all()
        
        return jsonify({
            'version': VERSION,
            'total_services': len(services),
            'services': [s.to_dict() for s in services]
        })
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found', 'version': VERSION}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        app.logger.error(f"Internal error: {error}")
        return jsonify({'error': 'Internal server error', 'version': VERSION}), 500
    
    @app.errorhandler(429)
    def ratelimit_handler(error):
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please try again later.',
            'version': VERSION
        }), 429
    
    # JWT error handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({'error': 'Token has expired', 'version': VERSION}), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({'error': 'Invalid token', 'version': VERSION}), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({'error': 'Authorization required', 'version': VERSION}), 401

    # Global compatibility routes for /api/audit/<id>
    @app.route('/api/audit/<path:audit_id>', methods=['GET'])
    def global_audit_route(audit_id):
        from api.free_audit import get_audit_result
        try:
            scan_id = int(audit_id)
            return get_audit_result(scan_id)
        except ValueError:
            from api.scans import get_audit_by_id
            return get_audit_by_id(audit_id)

    @app.route('/api/audit/<path:audit_id>/download', methods=['GET'])
    def global_audit_download(audit_id):
        from api.free_audit import download_audit_report
        try:
            scan_id = int(audit_id)
            return download_audit_report(scan_id)
        except ValueError:
            return jsonify({'error': 'Invalid scan ID for download', 'version': VERSION}), 400

    return app

# NOTE: do not instantiate a module-level `celery = create_celery_app()` here.
# Doing so made every import of this module (by gunicorn, pytest, flask db
# migrate, etc.) silently build a second full Flask app as a side effect of
# import, since create_celery_app() defaults to calling create_app(). Celery's
# CLI (`celery -A app.create_celery_app worker`) already calls the factory
# function itself when it sees a callable target — see docker-compose.yml.

if __name__ == '__main__':
    app = create_app(os.environ.get('FLASK_ENV', 'development'))
    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            app.logger.warning(f"Initial db.create_all check: {e}")
    app.run(host='0.0.0.0', port=5000, debug=False)

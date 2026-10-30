import os
from datetime import timedelta

VERSION = "GoKushield AI v1.0"

class Config:
    """Base configuration"""
    VERSION = VERSION
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Database (Oracle/PostgreSQL support)
    DB_TYPE = os.environ.get('DB_TYPE', 'postgresql')  # 'postgresql' or 'oracle'
    
    if DB_TYPE == 'oracle':
        SQLALCHEMY_DATABASE_URI = os.environ.get('ORACLE_DATABASE_URL') or \
            f"oracle+cx_oracle://{os.environ.get('ORACLE_USER', 'admin')}:" \
            f"{os.environ.get('ORACLE_PASSWORD', 'password')}@" \
            f"{os.environ.get('ORACLE_HOST', 'localhost')}:" \
            f"{os.environ.get('ORACLE_PORT', '1521')}/" \
            f"{os.environ.get('ORACLE_SERVICE', 'GOKUSHIELD')}"
    else:
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
            f"postgresql://{os.environ.get('DB_USER', 'gokushield')}:" \
            f"{os.environ.get('DB_PASSWORD', 'securepass')}@" \
            f"{os.environ.get('DB_HOST', 'db')}:" \
            f"{os.environ.get('DB_PORT', '5432')}/" \
            f"{os.environ.get('DB_NAME', 'gokushield')}"
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_POOL_SIZE = 20
    SQLALCHEMY_MAX_OVERFLOW = 40
    SQLALCHEMY_POOL_RECYCLE = 3600
    SQLALCHEMY_POOL_TIMEOUT = 30
    
    # JWT
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    
    # Redis
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
    
    # Celery
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://redis:6379/0')
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://redis:6379/0')
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_TIMEZONE = 'UTC'
    CELERY_ENABLE_UTC = True
    CELERY_TASK_TRACK_STARTED = True
    CELERY_TASK_TIME_LIMIT = 300
    CELERY_TASK_SOFT_TIME_LIMIT = 270
    
    # Celery Beat Schedule
    CELERY_BEAT_SCHEDULE = {
        'reset-monthly-usage': {
            'task': 'tasks.security_tasks.reset_monthly_usage',
            'schedule': timedelta(days=30),  # Every 30 days
        },
        'cleanup-expired-blacklists': {
            'task': 'tasks.security_tasks.cleanup_expired_blacklists',
            'schedule': timedelta(hours=1),
        },
        'health-check-ollama': {
            'task': 'tasks.security_tasks.health_check_ollama',
            'schedule': timedelta(minutes=5),
        }
    }
    
    # Ollama AI
    OLLAMA_BASE_URL = os.environ.get('OLLAMA_BASE_URL', 'http://host.docker.internal:11434')
    OLLAMA_DEFAULT_MODEL = os.environ.get('OLLAMA_DEFAULT_MODEL', 'mistral:7b')
    OLLAMA_TIMEOUT = int(os.environ.get('OLLAMA_TIMEOUT', '120'))
    OLLAMA_MODELS = {
        'reasoning': 'mistral:7b',
        'code_analysis': 'deepseek-coder:6.7b',
        'general': 'llama3:8b',
        'embedding': 'nomic-embed-text'
    }
    
    # Security
    BCRYPT_LOG_ROUNDS = 12
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'redis://redis:6379/1')
    RATELIMIT_DEFAULT = "100/hour"
    RATELIMIT_HEADERS_ENABLED = True
    
    # Login Security
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_LOCKOUT_DURATION = timedelta(minutes=30)
    
    # Session
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_TIMEOUT = timedelta(hours=2)
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # CAPTCHA
    RECAPTCHA_ENABLED = os.environ.get('RECAPTCHA_ENABLED', 'false').lower() == 'true'
    RECAPTCHA_SITE_KEY = os.environ.get('RECAPTCHA_SITE_KEY', '')
    RECAPTCHA_SECRET_KEY = os.environ.get('RECAPTCHA_SECRET_KEY', '')
    
    # Email (future)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@gokushield.com')
    
    # Scan Configuration
    SCAN_CACHE_TTL = int(os.environ.get('SCAN_CACHE_TTL', '3600'))  # 1 hour
    SCAN_MAX_RETRIES = int(os.environ.get('SCAN_MAX_RETRIES', '3'))
    SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', '60'))
    
    # Security Headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///gokushield_dev.db')

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        # Enforce strong security in production
        if not os.environ.get('SECRET_KEY'):
            raise ValueError("SECRET_KEY environment variable must be set in production")
        if not os.environ.get('JWT_SECRET_KEY'):
            raise ValueError("JWT_SECRET_KEY environment variable must be set in production")

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault('DB_TYPE', 'postgresql')
os.environ.setdefault('DATABASE_URL', 'sqlite:///:memory:')
os.environ.setdefault('REDIS_URL', 'redis://localhost:6379/15')
os.environ.setdefault('SECRET_KEY', 'gokushield-production-grade-secret-key-32-chars-min')
os.environ.setdefault('JWT_SECRET_KEY', 'gokushield-production-grade-jwt-secret-key-32-chars')

import pytest
from app import create_app
from models import db as _db


@pytest.fixture
def app():
    application = create_app('testing')
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db(app):
    return _db

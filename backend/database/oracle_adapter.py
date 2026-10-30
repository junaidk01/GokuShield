"""
Oracle Database Adapter for GoKushield AI v1.0
Provides compatibility layer for Oracle Autonomous Database
"""

import cx_Oracle
from sqlalchemy import create_engine, event
from sqlalchemy.pool import NullPool
import os

def create_oracle_engine(config):
    """Create Oracle database engine with optimized settings"""
    
    # Oracle connection string
    username = os.environ.get('ORACLE_USER', 'admin')
    password = os.environ.get('ORACLE_PASSWORD')
    host = os.environ.get('ORACLE_HOST', 'localhost')
    port = os.environ.get('ORACLE_PORT', '1521')
    service_name = os.environ.get('ORACLE_SERVICE', 'gokushield_high')
    
    # Wallet configuration for Oracle Autonomous Database
    wallet_location = os.environ.get('ORACLE_WALLET_DIR', '/opt/oracle/wallet')
    
    if os.path.exists(wallet_location):
        # Configure wallet for Autonomous Database
        cx_Oracle.init_oracle_client(config_dir=wallet_location)
        dsn = cx_Oracle.makedsn(host, port, service_name=service_name)
    else:
        # Standard connection
        dsn = cx_Oracle.makedsn(host, port, service_name=service_name)
    
    connection_string = f"oracle+cx_oracle://{username}:{password}@{dsn}"
    
    engine = create_engine(
        connection_string,
        poolclass=NullPool,  # Oracle manages connection pooling
        echo=config.get('DEBUG', False),
        max_identifier_length=128
    )
    
    # Add event listeners for Oracle-specific optimizations
    @event.listens_for(engine, "connect")
    def set_oracle_session_parameters(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("ALTER SESSION SET NLS_DATE_FORMAT = 'YYYY-MM-DD HH24:MI:SS'")
        cursor.execute("ALTER SESSION SET NLS_TIMESTAMP_FORMAT = 'YYYY-MM-DD HH24:MI:SS.FF'")
        cursor.close()
    
    return engine

def get_oracle_url():
    """Get Oracle connection URL"""
    username = os.environ.get('ORACLE_USER', 'admin')
    password = os.environ.get('ORACLE_PASSWORD')
    host = os.environ.get('ORACLE_HOST', 'localhost')
    port = os.environ.get('ORACLE_PORT', '1521')
    service_name = os.environ.get('ORACLE_SERVICE', 'gokushield_high')
    
    return f"oracle+cx_oracle://{username}:{password}@{host}:{port}/?service_name={service_name}"

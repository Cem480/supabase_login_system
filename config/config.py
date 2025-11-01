

import os
from datetime import timedelta
from dotenv import load_dotenv
load_dotenv()

class Config:
    """Base configuration"""
    
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production-123!'
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://postgres:postgres@localhost:5432/supabase_login'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    
    # JWT Configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ALGORITHM = 'HS256'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Session Configuration
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_COOKIE_NAME = 'supabase_session'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = False  # Set True in production with HTTPS
    
    # Security
    BCRYPT_LOG_ROUNDS = 12
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_SPECIAL = True
    
    # Rate Limiting
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URL = "memory://"
    RATELIMIT_DEFAULT = "200 per hour"
    LOGIN_RATE_LIMIT = "5 per minute"
    MAGIC_LINK_RATE_LIMIT = "3 per hour"
    REGISTER_RATE_LIMIT = "3 per hour"
    
    # Magic Link
    MAGIC_LINK_EXPIRY = timedelta(minutes=15)
    
    # OAuth Configuration
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
    GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')
    OAUTH_REDIRECT_URI = os.environ.get('OAUTH_REDIRECT_URI') or 'http://localhost:5000/api/auth/oauth/callback'
    
    # Email Configuration (for Magic Links)
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'noreply@supabase-login.com'
    
    # Application
    APP_NAME = 'Supabase Login System'
    APP_VERSION = '1.0.0'
    DEBUG = False
    TESTING = False


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SQLALCHEMY_ECHO = True
    SESSION_COOKIE_SECURE = False


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:postgres@localhost:5432/supabase_login_test'
    WTF_CSRF_ENABLED = False
    BCRYPT_LOG_ROUNDS = 4  # Faster for testing


class ProductionConfig(Config):
    """Production configuration"""
    SESSION_COOKIE_SECURE = True
    SQLALCHEMY_ECHO = False
    # Override with environment variables
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}


def get_config(env=None):
    """Get configuration based on environment"""
    if env is None:
        env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])

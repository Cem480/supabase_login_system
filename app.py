from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session as flask_session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import os
from datetime import datetime
from flask_mail import Mail
# Import configuration
from config.config import get_config

# Import models and services
from models.models import db, User, Session as UserSession, MagicLink, OAuthConnection, AuditLog
from services.auth_service import AuthService
from services.oauth_service import OAuthService


# ============================================================================
# APPLICATION FACTORY
# ============================================================================

def create_app(config_name=None):
    """
    Application Factory Pattern
    Creates and configures Flask application
    """
    app = Flask(__name__)
    
    # Load configuration
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    app.config.from_object(get_config(config_name))
    
    # Initialize extensions
    db.init_app(app)
    Session(app)
    
    mail = Mail(app)
    # Initialize rate limiter
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        storage_uri=app.config['RATELIMIT_STORAGE_URL'],
        default_limits=[app.config['RATELIMIT_DEFAULT']]
    )
    
    # Register blueprints
    register_routes(app, limiter)
    register_error_handlers(app)
    register_template_filters(app)
    # Create database tables
    with app.app_context():
        db.create_all()
        # Clean up expired sessions and magic links
        UserSession.cleanup_expired()
        MagicLink.cleanup_expired()
    
    return app



def login_required(f):
    """
    Decorator to protect routes that require authentication
    Validates JWT token from cookie
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get token from cookie
        token = request.cookies.get('auth_token')
        
        if not token:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        # Validate token
        user_dict, session_dict, error = AuthService.validate_token(token)
        
        if error:
            flash(f'Session expired: {error}', 'error')
            return redirect(url_for('login'))
        
        # Store user info in request context
        request.current_user = user_dict
        request.current_session = session_dict
        
        return f(*args, **kwargs)
    
    return decorated_function


def register_routes(app, limiter):
    """Register all application routes"""

    @app.route('/')
    def index():
        """Landing page"""
        # Check if user is already logged in
        token = request.cookies.get('auth_token')
        if token:
            user_dict, _, error = AuthService.validate_token(token)
            if not error:
                return redirect(url_for('dashboard'))
        
        return render_template('index.html')
    
    @app.route('/login', methods=['GET'])
    def login():
        """Login page"""
        # Check if already logged in
        token = request.cookies.get('auth_token')
        if token:
            user_dict, _, error = AuthService.validate_token(token)
            if not error:
                return redirect(url_for('dashboard'))
        
        return render_template('login.html')
    
    @app.route('/register', methods=['GET'])
    def register():
        """Registration page"""
        return render_template('register.html')
    
    @app.route('/magic-link', methods=['GET'])
    def magic_link_page():
        """Magic link request page"""
        return render_template('magic_link.html')
    
    # ========================================================================
    # AUTHENTICATION API ENDPOINTS
    # ========================================================================
    
    @app.route('/api/auth/register', methods=['POST'])
    @limiter.limit(lambda: app.config['REGISTER_RATE_LIMIT'])
    def api_register():
        """Register new user"""
        data = request.get_json()
        
        # Validate input
        email = data.get('email', '').strip()
        password = data.get('password', '')
        full_name = data.get('full_name', '').strip()
        
        if not email or not password:
            return jsonify({
                'success': False,
                'error': 'Email and password are required'
            }), 400
        
        # Register user
        user_dict, error = AuthService.register_user(email, password, full_name)
        
        if error:
            return jsonify({
                'success': False,
                'error': error
            }), 400
        
        # Auto-login after registration
        token, user_dict, error = AuthService.login_user(email, password, remember_me=False)
        
        if error:
            return jsonify({
                'success': False,
                'error': error
            }), 400
        
        # Create response with cookie
        response = jsonify({
            'success': True,
            'data': {
                'user': user_dict,
                'token': token
            },
            'message': 'Registration successful'
        })
        
        # Set auth cookie
        response.set_cookie(
            'auth_token',
            token,
            httponly=True,
            secure=app.config['SESSION_COOKIE_SECURE'],
            samesite='Lax',
            max_age=3600  # 1 hour
        )
        
        return response, 201
    
    @app.route('/api/auth/login', methods=['POST'])
    @limiter.limit(lambda: app.config['LOGIN_RATE_LIMIT'])
    def api_login():
        """Login user"""
        data = request.get_json()
        
        email = data.get('email', '').strip()
        password = data.get('password', '')
        remember_me = data.get('remember_me', False)
        
        if not email or not password:
            return jsonify({
                'success': False,
                'error': 'Email and password are required'
            }), 400
        
        # Authenticate user
        token, user_dict, error = AuthService.login_user(email, password, remember_me)
        
        if error:
            return jsonify({
                'success': False,
                'error': error
            }), 401
        
        # Create response with cookie
        response = jsonify({
            'success': True,
            'data': {
                'user': user_dict,
                'token': token
            },
            'message': 'Login successful'
        })
        
        # Set auth cookie
        max_age = 2592000 if remember_me else 3600  # 30 days or 1 hour
        response.set_cookie(
            'auth_token',
            token,
            httponly=True,
            secure=app.config['SESSION_COOKIE_SECURE'],
            samesite='Lax',
            max_age=max_age
        )
        
        return response, 200
    
    @app.route('/api/auth/logout', methods=['POST'])
    @login_required
    def api_logout():
        """Logout user"""
        token = request.cookies.get('auth_token')
        
        # Invalidate session
        AuthService.logout_user(token)
        
        # Create response
        response = jsonify({
            'success': True,
            'message': 'Logout successful'
        })
        
        # Clear auth cookie
        response.set_cookie('auth_token', '', expires=0)
        
        return response, 200
    
    @app.route('/api/auth/logout-all', methods=['POST'])
    @login_required
    def api_logout_all():
        """Logout user from all devices"""
        user_id = request.current_user['id']
        
        # Invalidate all sessions
        count = AuthService.logout_all_sessions(user_id)
        
        # Create response
        response = jsonify({
            'success': True,
            'message': f'Logged out from {count} devices',
            'count': count
        })
        
        # Clear auth cookie
        response.set_cookie('auth_token', '', expires=0)
        
        return response, 200
    
    @app.route('/api/auth/magic-link', methods=['POST'])
    @limiter.limit(lambda: app.config['MAGIC_LINK_RATE_LIMIT'])
    def api_magic_link():
        """Request magic link"""
        data = request.get_json()
        email = data.get('email', '').strip()
        
        if not email:
            return jsonify({
                'success': False,
                'error': 'Email is required'
            }), 400
        
        # Create magic link
        token, error = AuthService.create_magic_link(email)
        
        # Always return success for security (don't reveal if email exists)
        # In production, send email here
        magic_link_url = url_for('verify_magic_link', token=token, _external=True)
        
        # For development, log the URL
        app.logger.info(f'Magic link: {magic_link_url}')
        
        return jsonify({
            'success': True,
            'message': 'If an account exists with this email, a magic link has been sent',
            'dev_link': magic_link_url if app.debug else None  # Only in development
        }), 200
    
    @app.route('/api/auth/magic-link/verify', methods=['GET'])
    def verify_magic_link():
        """Verify magic link and login user"""
        token = request.args.get('token')
        
        if not token:
            flash('Invalid magic link', 'error')
            return redirect(url_for('login'))
        
        # Verify token and login
        jwt_token, user_dict, error = AuthService.verify_magic_link(token)
        
        if error:
            flash(f'Magic link error: {error}', 'error')
            return redirect(url_for('login'))
        
        # Create response
        response = redirect(url_for('dashboard'))
        
        # Set auth cookie
        response.set_cookie(
            'auth_token',
            jwt_token,
            httponly=True,
            secure=app.config['SESSION_COOKIE_SECURE'],
            samesite='Lax',
            max_age=3600
        )
        
        flash('Login successful!', 'success')
        return response

    @app.route('/api/auth/oauth/<provider>')
    def oauth_login(provider):
        """Initiate OAuth login"""
        if provider not in ['google', 'github']:
            flash('Invalid OAuth provider', 'error')
            return redirect(url_for('login'))
        
        # Get authorization URL
        auth_url, error = OAuthService.get_authorization_url(provider)
        
        if error:
            flash(error, 'error')
            return redirect(url_for('login'))
        
        return redirect(auth_url)
    
    @app.route('/api/auth/oauth/<provider>/callback')
    def oauth_callback(provider):
        """Handle OAuth callback"""
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')
        
        if error:
            flash(f'OAuth error: {error}', 'error')
            return redirect(url_for('login'))
        
        if not code or not state:
            flash('Invalid OAuth response', 'error')
            return redirect(url_for('login'))
        
        # Handle callback
        jwt_token, user_dict, error = OAuthService.handle_callback(provider, code, state)
        
        if error:
            flash(f'OAuth login failed: {error}', 'error')
            return redirect(url_for('login'))
        
        # Create response
        response = redirect(url_for('dashboard'))
        
        # Set auth cookie
        response.set_cookie(
            'auth_token',
            jwt_token,
            httponly=True,
            secure=app.config['SESSION_COOKIE_SECURE'],
            samesite='Lax',
            max_age=2592000  # 30 days for OAuth
        )
        
        flash(f'Welcome, {user_dict["email"]}!', 'success')
        return response

    @app.route('/dashboard')
    @login_required
    def dashboard():
        """Protected dashboard"""
        user = request.current_user
        
        # Get user's active sessions
        sessions = UserSession.query.filter_by(user_id=user['id']).all()
        sessions_data = [s.to_dict() for s in sessions]
        
        # Get OAuth connections
        oauth_conns = OAuthConnection.query.filter_by(user_id=user['id']).all()
        oauth_data = [o.to_dict() for o in oauth_conns]
        
        return render_template(
            'dashboard.html',
            user=user,
            sessions=sessions_data,
            oauth_connections=oauth_data
        )
    
    @app.route('/profile')
    @login_required
    def profile():
        """User profile page"""
        user = request.current_user
        return render_template('profile.html', user=user)

    @app.route('/api/user/profile', methods=['GET'])
    @login_required
    def api_get_profile():
        """Get current user profile"""
        return jsonify({
            'success': True,
            'data': {
                'user': request.current_user
            }
        }), 200
    
    @app.route('/api/user/sessions', methods=['GET'])
    @login_required
    def api_get_sessions():
        """Get user's active sessions"""
        user_id = request.current_user['id']
        sessions = UserSession.query.filter_by(user_id=user_id).all()
        
        return jsonify({
            'success': True,
            'data': {
                'sessions': [s.to_dict() for s in sessions]
            }
        }), 200
    
    @app.route('/api/user/sessions/<session_id>', methods=['DELETE'])
    @login_required
    def api_delete_session(session_id):
        """Revoke specific session"""
        user_id = request.current_user['id']
        
        session = UserSession.query.filter_by(id=session_id, user_id=user_id).first()
        
        if not session:
            return jsonify({
                'success': False,
                'error': 'Session not found'
            }), 404
        
        db.session.delete(session)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Session revoked'
        }), 200

def register_error_handlers(app):
    """Register error handlers"""
    
    @app.errorhandler(404)
    def not_found(error):
        """404 error handler"""
        if request.path.startswith('/api/'):
            return jsonify({
                'success': False,
                'error': 'Resource not found'
            }), 404
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        """500 error handler"""
        db.session.rollback()
        app.logger.error(f'Internal error: {str(error)}')
        
        if request.path.startswith('/api/'):
            return jsonify({
                'success': False,
                'error': 'Internal server error'
            }), 500
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(429)
    def rate_limit_error(error):
        """429 rate limit error handler"""
        if request.path.startswith('/api/'):
            return jsonify({
                'success': False,
                'error': 'Rate limit exceeded. Please try again later.'
            }), 429
        flash('Too many requests. Please try again later.', 'error')
        return redirect(url_for('index'))



def register_template_filters(app):
    """Register custom template filters"""
    
    @app.template_filter('datetime')
    def format_datetime(value):
        """Format datetime for display"""
        if value is None:
            return ''
        if isinstance(value, str):
            value = datetime.fromisoformat(value)
        return value.strftime('%Y-%m-%d %H:%M:%S')


if __name__ == '__main__':
    app = create_app()
    
    # Development server
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )

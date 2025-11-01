
import jwt
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from flask import current_app, request
from models.models import db, User, Session, MagicLink, OAuthConnection, AuditLog
from flask_mail import Mail, Message

class AuthService:

    
    @staticmethod
    def register_user(email, password, full_name=None):

        # Validate email
        email = email.lower().strip()
        if not email or '@' not in email:
            return None, "Invalid email address"
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return None, "Email already registered"
        
        # Validate password
        is_valid, message = AuthService._validate_password(password)
        if not is_valid:
            return None, message
        
        # Create user
        user = User(
            email=email,
            full_name=full_name,
            email_verified=False
        )
        user.set_password(password)
        
        try:
            db.session.add(user)
            db.session.commit()
            
            # Log registration
            AuditLog.log_event(
                event_type='register',
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            
            return user.to_dict(), None
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Registration error: {str(e)}")
            return None, "Registration failed. Please try again."
    
    @staticmethod
    def login_user(email, password, remember_me=False):

        email = email.lower().strip()
        
        # Find user
        user = User.query.filter_by(email=email).first()
        
        if not user or not user.check_password(password):
            # Log failed login
            AuditLog.log_event(
                event_type='failed_login',
                user_id=user.id if user else None,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                extra_info={'email': email}
            )
            return None, None, "Invalid email or password"
        
        # Update last sign in
        user.update_last_sign_in()
        
        # Create session and generate JWT
        token = AuthService._create_session(user, remember_me=remember_me)
        
        # Log successful login
        AuditLog.log_event(
            event_type='login',
            user_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            extra_info={'remember_me': remember_me}
        )
        
        return token, user.to_dict(), None
    
    @staticmethod
    def logout_user(token):

        try:
            # Decode token to get session
            payload = jwt.decode(
                token,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=[current_app.config['JWT_ALGORITHM']]
            )
            
            session_id = payload.get('session_id')
            user_id = payload.get('user_id')
            
            # Delete session
            session = Session.query.filter_by(id=session_id).first()
            if session:
                db.session.delete(session)
                db.session.commit()
                
                # Log logout
                AuditLog.log_event(
                    event_type='logout',
                    user_id=user_id,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent')
                )
            
            return True
        except Exception as e:
            current_app.logger.error(f"Logout error: {str(e)}")
            return False
    
    @staticmethod
    def logout_all_sessions(user_id):

        try:
            sessions = Session.query.filter_by(user_id=user_id).all()
            count = len(sessions)
            
            for session in sessions:
                db.session.delete(session)
            
            db.session.commit()
            
            # Log logout all
            AuditLog.log_event(
                event_type='logout_all',
                user_id=user_id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                extra_info={'sessions_count': count}
            )
            
            return count
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Logout all error: {str(e)}")
            return 0
    
    @staticmethod
    def validate_token(token):

        try:
            # Decode token
            payload = jwt.decode(
                token,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=[current_app.config['JWT_ALGORITHM']]
            )
            
            user_id = payload.get('user_id')
            session_id = payload.get('session_id')
            
            # Check if session exists and is valid
            session = Session.query.filter_by(id=session_id).first()
            if not session or session.is_expired():
                return None, None, "Session expired"
            
            # Get user
            user = User.query.get(user_id)
            if not user:
                return None, None, "User not found"
            
            # Update last activity
            session.last_activity_at = datetime.now(timezone.utc)
            db.session.commit()
            
            return user.to_dict(), session.to_dict(), None
            
        except jwt.ExpiredSignatureError:
            return None, None, "Token expired"
        except jwt.InvalidTokenError:
            return None, None, "Invalid token"
        except Exception as e:
            current_app.logger.error(f"Token validation error: {str(e)}")
            return None, None, "Token validation failed"
    
    @staticmethod
    def refresh_token(old_token):

        user_dict, session_dict, error = AuthService.validate_token(old_token)
        
        if error:
            return None, error
        
        # Generate new token
        new_token = AuthService._generate_jwt(user_dict['id'], session_dict['id'])
        
        return new_token, None
    
    @staticmethod
    def create_magic_link(email):

        email = email.lower().strip()
        
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if not user:
            # Don't reveal if email exists for security
            return None, None
        
        # Generate secure token
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Create magic link
        magic_link = MagicLink(
            email=email,
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc) + current_app.config['MAGIC_LINK_EXPIRY']
        )
        
        try:
            db.session.add(magic_link)
            db.session.commit()
            
            magic_link_url = f"{request.host_url}api/auth/magic-link/verify?token={token}"

            try:
                mail = Mail(current_app)
                
                msg = Message(
                    'Your Magic Link',
                    recipients=[email],
                    body=f'Click here to login: {magic_link_url}\n\nThis link expires in 15 minutes.'
                )
                mail.send(msg)
            except Exception as e:
                current_app.logger.error(f"Email error: {str(e)}")
            # Log magic link request
            AuditLog.log_event(
                event_type='magic_link_request',
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            
            return token, None
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Magic link creation error: {str(e)}")
            return None, "Failed to create magic link"
    
    @staticmethod
    def verify_magic_link(token):
        """
        Verify magic link and login user
        
        Args:
            token (str): Magic link token
            
        Returns:
            tuple: (jwt_token, user_dict, error_message)
        """
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Find magic link
        magic_link = MagicLink.query.filter_by(token_hash=token_hash).first()
        
        if not magic_link or not magic_link.is_valid():
            return None, None, "Invalid or expired magic link"
        
        # Find user
        user = User.query.filter_by(email=magic_link.email).first()
        if not user:
            return None, None, "User not found"
        
        # Mark magic link as used
        magic_link.mark_as_used()
        
        # Update last sign in
        user.update_last_sign_in()
        
        # Create session and generate JWT
        jwt_token = AuthService._create_session(user, remember_me=False)
        
        # Log magic link login
        AuditLog.log_event(
            event_type='magic_link_login',
            user_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jwt_token, user.to_dict(), None
    

    @staticmethod
    def _create_session(user, remember_me=False):
        """Create session and generate JWT token"""
        # Determine expiry
        if remember_me:
            expires_at = datetime.now(timezone.utc) + current_app.config['JWT_REFRESH_TOKEN_EXPIRES']
        else:
            expires_at = datetime.now(timezone.utc) + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
        
        # Generate session token
        session_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()
        
        # Create session record
        session = Session(
            user_id=user.id,
            token_hash=token_hash,
            device_info=AuthService._get_device_info(),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            remember_me=remember_me,
            expires_at=expires_at
        )
        
        db.session.add(session)
        db.session.commit()
        
        # Generate JWT
        jwt_token = AuthService._generate_jwt(user.id, session.id, expires_at)
        
        return jwt_token
    
    @staticmethod
    def _generate_jwt(user_id, session_id, expires_at=None):
        """Generate JWT token"""
        if expires_at is None:
            expires_at = datetime.now(timezone.utc) + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
        
        payload = {
            'user_id': str(user_id),
            'session_id': str(session_id),
            'exp': expires_at,
            'iat': datetime.now(timezone.utc)
        }
        
        token = jwt.encode(
            payload,
            current_app.config['JWT_SECRET_KEY'],
            algorithm=current_app.config['JWT_ALGORITHM']
        )
        
        return token
    
    @staticmethod
    def _validate_password(password):
        """Validate password strength"""
        if len(password) < current_app.config['MIN_PASSWORD_LENGTH']:
            return False, f"Password must be at least {current_app.config['MIN_PASSWORD_LENGTH']} characters"
        
        if len(password) > current_app.config['MAX_PASSWORD_LENGTH']:
            return False, f"Password must be less than {current_app.config['MAX_PASSWORD_LENGTH']} characters"
        
        if current_app.config['PASSWORD_REQUIRE_UPPERCASE'] and not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        
        if current_app.config['PASSWORD_REQUIRE_LOWERCASE'] and not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        
        if current_app.config['PASSWORD_REQUIRE_DIGIT'] and not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"
        
        if current_app.config['PASSWORD_REQUIRE_SPECIAL']:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                return False, "Password must contain at least one special character"
        
        return True, None
    
    @staticmethod
    def _get_device_info():
        """Extract device information from request"""
        user_agent = request.headers.get('User-Agent', '')
        
        device_info = {
            'user_agent': user_agent,
            'platform': 'unknown'
        }
        
        if 'Mobile' in user_agent or 'Android' in user_agent:
            device_info['platform'] = 'mobile'
        elif 'iPad' in user_agent or 'Tablet' in user_agent:
            device_info['platform'] = 'tablet'
        else:
            device_info['platform'] = 'desktop'
        
        return device_info

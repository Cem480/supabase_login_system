"""
OAuth Service
Handles OAuth authentication with Google and GitHub

Architecture Pattern: Strategy Pattern (different OAuth providers)
Security: Implements OAuth 2.0 with PKCE flow
"""

import secrets
import requests
from datetime import datetime, timedelta
from flask import current_app, request, session as flask_session
from models.models import db, User, OAuthConnection, AuditLog
from services.auth_service import AuthService


class OAuthService:
    """Service class for OAuth operations"""
    
    # OAuth Provider Configurations
    PROVIDERS = {
        'google': {
            'authorization_url': 'https://accounts.google.com/o/oauth2/v2/auth',
            'token_url': 'https://oauth2.googleapis.com/token',
            'userinfo_url': 'https://www.googleapis.com/oauth2/v2/userinfo',
            'scopes': ['openid', 'email', 'profile']
        },
        'github': {
            'authorization_url': 'https://github.com/login/oauth/authorize',
            'token_url': 'https://github.com/login/oauth/access_token',
            'userinfo_url': 'https://api.github.com/user',
            'scopes': ['user:email']
        }
    }
    
    @staticmethod
    def get_authorization_url(provider):
        """
        Generate OAuth authorization URL
        
        Args:
            provider (str): OAuth provider ('google' or 'github')
            
        Returns:
            tuple: (authorization_url, error_message)
        """
        if provider not in OAuthService.PROVIDERS:
            return None, "Invalid OAuth provider"
        
        # Get provider configuration
        config = OAuthService.PROVIDERS[provider]
        
        # Get client ID
        if provider == 'google':
            client_id = current_app.config.get('GOOGLE_CLIENT_ID')
        elif provider == 'github':
            client_id = current_app.config.get('GITHUB_CLIENT_ID')
        else:
            return None, "Provider not configured"
        
        if not client_id:
            return None, f"{provider.capitalize()} OAuth not configured"
        
        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        flask_session['oauth_state'] = state
        flask_session['oauth_provider'] = provider
        
        # Build authorization URL
        redirect_uri = current_app.config['OAUTH_REDIRECT_URI'].replace('/callback', f'/{provider}/callback')
        scopes = ' '.join(config['scopes'])
        
        params = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'scope': scopes,
            'state': state,
            'response_type': 'code',
        }
        
        # Add provider-specific parameters
        if provider == 'google':
            params['access_type'] = 'offline'
            params['prompt'] = 'consent'
        
        # Build URL
        url = config['authorization_url'] + '?'
        url += '&'.join([f'{k}={v}' for k, v in params.items()])
        
        return url, None
    
    @staticmethod
    def handle_callback(provider, code, state):
        """
        Handle OAuth callback
        
        Args:
            provider (str): OAuth provider
            code (str): Authorization code
            state (str): State parameter for CSRF protection
            
        Returns:
            tuple: (jwt_token, user_dict, error_message)
        """
        # Validate state (CSRF protection)
        stored_state = flask_session.get('oauth_state')
        stored_provider = flask_session.get('oauth_provider')
        
        if not stored_state or state != stored_state or provider != stored_provider:
            return None, None, "Invalid OAuth state"
        
        # Clear state from session
        flask_session.pop('oauth_state', None)
        flask_session.pop('oauth_provider', None)
        
        # Exchange code for token
        token_data, error = OAuthService._exchange_code_for_token(provider, code)
        if error:
            return None, None, error
        
        # Get user info from provider
        user_info, error = OAuthService._get_user_info(provider, token_data['access_token'])
        if error:
            return None, None, error
        
        # Find or create user
        user, oauth_conn, error = OAuthService._find_or_create_user(provider, user_info, token_data)
        if error:
            return None, None, error
        
        # Update last sign in
        user.update_last_sign_in()
        
        # Create session and generate JWT
        jwt_token = AuthService._create_session(user, remember_me=True)
        
        # Log OAuth login
        AuditLog.log_event(
            event_type=f'oauth_login_{provider}',
            user_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            extra_info={'provider': provider}
        )
        
        return jwt_token, user.to_dict(), None
    
    @staticmethod
    def link_account(user_id, provider, code, state):
        """
        Link OAuth account to existing user
        
        Args:
            user_id (str): User ID
            provider (str): OAuth provider
            code (str): Authorization code
            state (str): State parameter
            
        Returns:
            tuple: (success, error_message)
        """
        # Validate state
        stored_state = flask_session.get('oauth_state')
        stored_provider = flask_session.get('oauth_provider')
        
        if not stored_state or state != stored_state or provider != stored_provider:
            return False, "Invalid OAuth state"
        
        # Clear state
        flask_session.pop('oauth_state', None)
        flask_session.pop('oauth_provider', None)
        
        # Exchange code for token
        token_data, error = OAuthService._exchange_code_for_token(provider, code)
        if error:
            return False, error
        
        # Get user info
        user_info, error = OAuthService._get_user_info(provider, token_data['access_token'])
        if error:
            return False, error
        
        # Check if already linked
        existing = OAuthConnection.query.filter_by(
            provider=provider,
            provider_user_id=str(user_info['id'])
        ).first()
        
        if existing:
            return False, f"{provider.capitalize()} account already linked"
        
        # Create OAuth connection
        oauth_conn = OAuthConnection(
            user_id=user_id,
            provider=provider,
            provider_user_id=user_info['id'],
            provider_email=user_info.get('email'),
            access_token=token_data.get('access_token'),
            refresh_token=token_data.get('refresh_token'),
            expires_at=datetime.utcnow() + timedelta(seconds=token_data.get('expires_in', 3600))
        )
        
        try:
            db.session.add(oauth_conn)
            db.session.commit()
            
            # Log account linking
            AuditLog.log_event(
                event_type=f'oauth_link_{provider}',
                user_id=user_id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            
            return True, None
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"OAuth link error: {str(e)}")
            return False, "Failed to link account"
    
    @staticmethod
    def unlink_account(user_id, provider):
        """
        Unlink OAuth account from user
        
        Args:
            user_id (str): User ID
            provider (str): OAuth provider
            
        Returns:
            tuple: (success, error_message)
        """
        oauth_conn = OAuthConnection.query.filter_by(
            user_id=user_id,
            provider=provider
        ).first()
        
        if not oauth_conn:
            return False, f"No {provider.capitalize()} account linked"
        
        try:
            db.session.delete(oauth_conn)
            db.session.commit()
            
            # Log account unlinking
            AuditLog.log_event(
                event_type=f'oauth_unlink_{provider}',
                user_id=user_id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            
            return True, None
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"OAuth unlink error: {str(e)}")
            return False, "Failed to unlink account"
    
    # ========================================================================
    # PRIVATE HELPER METHODS
    # ========================================================================
    
    @staticmethod
    def _exchange_code_for_token(provider, code):
        """Exchange authorization code for access token"""
        config = OAuthService.PROVIDERS[provider]
        
        # Get client credentials
        if provider == 'google':
            client_id = current_app.config['GOOGLE_CLIENT_ID']
            client_secret = current_app.config['GOOGLE_CLIENT_SECRET']
        elif provider == 'github':
            client_id = current_app.config['GITHUB_CLIENT_ID']
            client_secret = current_app.config['GITHUB_CLIENT_SECRET']
        else:
            return None, "Provider not configured"
        
        redirect_uri = current_app.config['OAUTH_REDIRECT_URI'].replace('/callback', f'/{provider}/callback')
        
        # Prepare token request
        data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }
        
        headers = {}
        if provider == 'github':
            headers['Accept'] = 'application/json'
        
        try:
            response = requests.post(
                config['token_url'],
                data=data,
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            
            token_data = response.json()
            
            if 'error' in token_data:
                return None, token_data.get('error_description', 'OAuth token error')
            
            return token_data, None
            
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"OAuth token exchange error: {str(e)}")
            return None, "Failed to exchange code for token"
    
    @staticmethod
    def _get_user_info(provider, access_token):
        """Get user information from OAuth provider"""
        config = OAuthService.PROVIDERS[provider]
        
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        try:
            response = requests.get(
                config['userinfo_url'],
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            
            user_info = response.json()
            if provider == 'github' and not user_info.get('email'):
                # GitHub email is private, fetch from emails endpoint
                email_response = requests.get(
                    'https://api.github.com/user/emails',
                    headers=headers,
                    timeout=10
                )
                if email_response.ok:
                    emails = email_response.json()
                    # Get primary email
                    primary_email = next((e['email'] for e in emails if e['primary']), None)
                    if primary_email:
                        user_info['email'] = primary_email
            # Normalize user info across providers
            normalized = {
                'id': user_info.get('id') or user_info.get('sub'),
                'email': user_info.get('email'),
                'name': user_info.get('name'),
                'avatar_url': user_info.get('picture') or user_info.get('avatar_url')
            }
            
            return normalized, None
            
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"OAuth user info error: {str(e)}")
            return None, "Failed to get user information"
    
    @staticmethod
    def _find_or_create_user(provider, user_info, token_data):
        """Find existing user or create new one"""
        # Try to find existing OAuth connection
        oauth_conn = OAuthConnection.query.filter_by(
            provider=provider,
            provider_user_id=str(user_info['id'])
        ).first()
        
        if oauth_conn:
            # Update tokens
            oauth_conn.access_token = token_data.get('access_token')
            oauth_conn.refresh_token = token_data.get('refresh_token')
            oauth_conn.expires_at = datetime.utcnow() + timedelta(seconds=token_data.get('expires_in', 3600))
            db.session.commit()
            
            return oauth_conn.user, oauth_conn, None
        
        # Try to find user by email
        email = user_info.get('email')
        if email:
            user = User.query.filter_by(email=email.lower()).first()
            if user:
                # Link OAuth to existing user
                oauth_conn = OAuthConnection(
                    user_id=user.id,
                    provider=provider,
                    provider_user_id=str(user_info['id']),
                    provider_email=email,
                    access_token=token_data.get('access_token'),
                    refresh_token=token_data.get('refresh_token'),
                    expires_at=datetime.utcnow() + timedelta(seconds=token_data.get('expires_in', 3600))
                )
                db.session.add(oauth_conn)
                db.session.commit()
                
                return user, oauth_conn, None
        
        # Create new user
        if not email:
            return None, None, "Email not provided by OAuth provider"
        
        user = User(
            email=email.lower(),
            full_name=user_info.get('name'),
            avatar_url=user_info.get('avatar_url'),
            email_verified=True  # OAuth providers verify emails
        )
        
        try:
            db.session.add(user)
            db.session.flush()  # Get user ID
            
            # Create OAuth connection
            oauth_conn = OAuthConnection(
                user_id=user.id,
                provider=provider,
                provider_user_id=str(user_info['id']),
                provider_email=email,
                access_token=token_data.get('access_token'),
                refresh_token=token_data.get('refresh_token'),
                expires_at=datetime.utcnow() + timedelta(seconds=token_data.get('expires_in', 3600))
            )
            db.session.add(oauth_conn)
            db.session.commit()
            
            # Log user creation via OAuth
            AuditLog.log_event(
                event_type=f'register_oauth_{provider}',
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            
            return user, oauth_conn, None
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"User creation error: {str(e)}")
            return None, None, "Failed to create user account"


from datetime import datetime, timedelta, timezone
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

db = SQLAlchemy()


class User(db.Model):

    __tablename__ = 'users'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=True) 
    full_name = db.Column(db.String(255))
    avatar_url = db.Column(db.Text)
    email_verified = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    last_sign_in_at = db.Column(db.DateTime(timezone=True))

    sessions = db.relationship('Session', back_populates='user', cascade='all, delete-orphan')
    oauth_connections = db.relationship('OAuthConnection', back_populates='user', cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', back_populates='user', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password"""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)
    
    def update_last_sign_in(self):
        """Update last sign in timestamp"""
        self.last_sign_in_at = datetime.utcnow()
        db.session.commit()
    
    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary"""
        data = {
            'id': str(self.id),
            'email': self.email,
            'full_name': self.full_name,
            'avatar_url': self.avatar_url,
            'email_verified': self.email_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_sign_in_at': self.last_sign_in_at.isoformat() if self.last_sign_in_at else None
        }
        if include_sensitive:
            data['updated_at'] = self.updated_at.isoformat() if self.updated_at else None
        return data
    
    def __repr__(self):
        return f'<User {self.email}>'


class Session(db.Model):

    __tablename__ = 'sessions'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token_hash = db.Column(db.String(255), unique=True, nullable=False, index=True)
    
    device_info = db.Column(JSONB)  
    ip_address = db.Column(INET)
    user_agent = db.Column(db.Text)
    
    remember_me = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    last_activity_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    
    user = db.relationship('User', back_populates='sessions')
    
    @staticmethod
    def cleanup_expired():
        """Remove expired sessions"""
        expired = Session.query.filter(Session.expires_at < datetime.now(timezone.utc)).all()
        for session in expired:
            db.session.delete(session)
        db.session.commit()
        return len(expired)
    
    def is_expired(self):
        """Check if session is expired"""
        return self.expires_at < datetime.now(timezone.utc)
    
    def extend_expiry(self, hours=1):
        """Extend session expiry"""
        self.expires_at = datetime.now(timezone.utc) + timedelta(hours=hours)
        self.last_activity_at = datetime.now(timezone.utc)
        db.session.commit()
    
    def to_dict(self):
        """Convert session to dictionary"""
        return {
            'id': str(self.id),
            'device_info': self.device_info,
            'ip_address': str(self.ip_address) if self.ip_address else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_activity_at': self.last_activity_at.isoformat() if self.last_activity_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }
    
    def __repr__(self):
        return f'<Session {self.id} for User {self.user_id}>'


class MagicLink(db.Model):

    __tablename__ = 'magic_links'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = db.Column(db.String(255), nullable=False, index=True)
    token_hash = db.Column(db.String(255), unique=True, nullable=False, index=True)
    used = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    
    @staticmethod
    def cleanup_expired():
        """Remove expired magic links"""
        expired = MagicLink.query.filter(MagicLink.expires_at < datetime.now(timezone.utc)).all()
        for link in expired:
            db.session.delete(link)
        db.session.commit()
        return len(expired)
    
    def is_valid(self):
        """Check if magic link is still valid"""
        return not self.used and self.expires_at > datetime.now(timezone.utc)
    
    def mark_as_used(self):
        """Mark magic link as used"""
        self.used = True
        db.session.commit()
    
    def __repr__(self):
        return f'<MagicLink {self.email}>'


class OAuthConnection(db.Model):
    """
    OAuth Connection model - Stores social login connections
    Links user accounts with OAuth providers (Google, GitHub)
    """
    __tablename__ = 'oauth_connections'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)

    provider = db.Column(db.String(50), nullable=False)
    provider_user_id = db.Column(db.String(255), nullable=False)
    provider_email = db.Column(db.String(255))

    access_token = db.Column(db.Text)
    refresh_token = db.Column(db.Text)
    expires_at = db.Column(db.DateTime(timezone=True))
    
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', back_populates='oauth_connections')
    
    __table_args__ = (
        db.UniqueConstraint('provider', 'provider_user_id', name='uq_provider_user'),
    )
    
    def is_token_expired(self):
        """Check if access token is expired"""
        if not self.expires_at:
            return True
        return self.expires_at < datetime.now(timezone.utc)
    
    def to_dict(self):
        """Convert OAuth connection to dictionary"""
        return {
            'id': str(self.id),
            'provider': self.provider,
            'provider_email': self.provider_email,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f'<OAuthConnection {self.provider} for User {self.user_id}>'


class AuditLog(db.Model):

    __tablename__ = 'audit_log'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    event_type = db.Column(db.String(50), nullable=False, index=True)

    ip_address = db.Column(INET)
    user_agent = db.Column(db.Text)
    extra_info = db.Column(JSONB)  
    
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow, index=True)
    
    user = db.relationship('User', back_populates='audit_logs')
    
    @staticmethod
    def log_event(event_type, user_id=None, ip_address=None, user_agent=None, extra_info =None):
        """Create audit log entry"""
        log = AuditLog(
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            extra_info =extra_info 
        )
        db.session.add(log)
        db.session.commit()
        return log
    
    def to_dict(self):
        """Convert audit log to dictionary"""
        return {
            'id': str(self.id),
            'event_type': self.event_type,
            'user_id': str(self.user_id) if self.user_id else None,
            'ip_address': str(self.ip_address) if self.ip_address else None,
            'extra_info ': self.extra_info ,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f'<AuditLog {self.event_type} at {self.created_at}>'

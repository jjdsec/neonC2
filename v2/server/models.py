"""Database models for NeonC2 Server."""
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import uuid
import bcrypt
from datetime import datetime

# This will be initialized in app.py
db = SQLAlchemy()


class User(UserMixin, db.Model):
    """User model with UUID primary key."""
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def __init__(self, **kwargs):
        """Initialize user with UUID if not provided."""
        if 'id' not in kwargs:
            kwargs['id'] = str(uuid.uuid4())
        super(User, self).__init__(**kwargs)

    def set_password(self, password):
        """Hash and set the user's password."""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        """Check if the provided password matches the stored hash."""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def get_id(self):
        """Return the user ID as a string (required by Flask-Login for UUID)."""
        return str(self.id)

    def __repr__(self):
        return f'<User {self.username} ({self.id})>'


class Host(db.Model):
    """Host model for registered C2 clients."""
    __tablename__ = 'hosts'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname = db.Column(db.String(255), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6 max length
    os_type = db.Column(db.String(50), nullable=True)
    os_version = db.Column(db.String(100), nullable=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_idle = db.Column(db.Boolean, default=False, nullable=False)  # Mark as idle instead of deleting
    missed_cycles = db.Column(db.Integer, default=0, nullable=True)  # Track missed sync cycles
    hardware_id = db.Column(db.String(255), nullable=True, index=True)  # Hardware ID for matching across reboots
    idle_timeout_cycles = db.Column(db.Integer, default=5, nullable=False)  # Cycles before marking as idle
    sync_frequency = db.Column(db.Integer, default=5, nullable=False)  # Sync frequency in seconds
    host_metadata = db.Column(db.Text, nullable=True)  # JSON string for additional info (renamed from metadata as it's reserved)
    
    def __init__(self, **kwargs):
        """Initialize host with UUID if not provided."""
        if 'id' not in kwargs:
            kwargs['id'] = str(uuid.uuid4())
        super(Host, self).__init__(**kwargs)
    
    def to_dict(self):
        """Convert host to dictionary."""
        return {
            'id': self.id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'os_type': self.os_type,
            'os_version': self.os_version,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'is_active': self.is_active,
            'is_idle': self.is_idle,
            'missed_cycles': self.missed_cycles or 0,
            'hardware_id': self.hardware_id,
            'idle_timeout_cycles': self.idle_timeout_cycles,
            'sync_frequency': self.sync_frequency,
            'metadata': self.host_metadata
        }
    
    def __repr__(self):
        return f'<Host {self.hostname} ({self.ip_address})>'


class Command(db.Model):
    """Command model for storing commands to execute on hosts."""
    __tablename__ = 'commands'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    host_id = db.Column(db.String(36), db.ForeignKey('hosts.id'), nullable=False, index=True)
    command = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)  # pending, executing, completed, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    executed_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    result = db.Column(db.Text, nullable=True)
    error = db.Column(db.Text, nullable=True)
    exit_code = db.Column(db.Integer, nullable=True)
    
    # Relationship
    host = db.relationship('Host', backref='commands')
    
    def __init__(self, **kwargs):
        """Initialize command with UUID if not provided."""
        if 'id' not in kwargs:
            kwargs['id'] = str(uuid.uuid4())
        super(Command, self).__init__(**kwargs)
    
    def to_dict(self):
        """Convert command to dictionary."""
        return {
            'id': self.id,
            'host_id': self.host_id,
            'command': self.command,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'executed_at': self.executed_at.isoformat() if self.executed_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'result': self.result,
            'error': self.error,
            'exit_code': self.exit_code
        }
    
    def __repr__(self):
        return f'<Command {self.id[:8]}... for {self.host_id[:8]}... ({self.status})>'

"""
Naebak Messaging Service - Database Models

This module defines the database models for the messaging service, following
the specifications from naebak-almakhzan repository. The models support
real-time messaging between users with proper integration to the auth service.

Models:
- Chat: Represents a conversation between users
- Participant: Links users to chat conversations  
- Message: Represents individual messages within chats

Database Configuration:
- Type: PostgreSQL 14
- Instance: naebak-messages-instance
- Port: 5432
- Database: naebak_messages
- User: messages_user
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
from enum import Enum

db = SQLAlchemy()


class ChatType(Enum):
    """
    Enumeration for different types of chat conversations.
    
    DIRECT: One-to-one conversation between two users
    GROUP: Group conversation with multiple participants
    SUPPORT: Support conversation with admin/representative
    """
    DIRECT = "direct"
    GROUP = "group"
    SUPPORT = "support"


class MessageType(Enum):
    """
    Enumeration for different types of messages.
    
    TEXT: Regular text message
    IMAGE: Image attachment
    FILE: File attachment
    SYSTEM: System-generated message (user joined, left, etc.)
    """
    TEXT = "text"
    IMAGE = "image"
    FILE = "file"
    SYSTEM = "system"


class MessageStatus(Enum):
    """
    Enumeration for message delivery status.
    
    SENT: Message has been sent
    DELIVERED: Message has been delivered to recipient
    READ: Message has been read by recipient
    """
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"


class Chat(db.Model):
    """
    Chat model representing a conversation between users.
    
    This model supports direct messages between citizens and representatives,
    group chats, and support conversations. Each chat has a unique identifier
    and tracks metadata such as creation time and last activity.
    
    Attributes:
        id (str): Unique UUID identifier for the chat
        name (str): Optional name for group chats
        chat_type (ChatType): Type of chat (direct, group, support)
        created_at (datetime): When the chat was created
        updated_at (datetime): When the chat was last updated
        last_message_at (datetime): When the last message was sent
        is_active (bool): Whether the chat is currently active
        
    Relationships:
        participants: Users participating in this chat
        messages: Messages sent in this chat
    """
    __tablename__ = 'chats'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(255), nullable=True)
    chat_type = db.Column(db.Enum(ChatType), nullable=False, default=ChatType.DIRECT)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_message_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    
    # Relationships
    participants = db.relationship('Participant', backref='chat', lazy='dynamic', cascade='all, delete-orphan')
    messages = db.relationship('Message', backref='chat', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Chat {self.id}: {self.name or self.chat_type.value}>'
    
    def to_dict(self):
        """Convert chat object to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'name': self.name,
            'chat_type': self.chat_type.value,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'last_message_at': self.last_message_at.isoformat() if self.last_message_at else None,
            'is_active': self.is_active,
            'participant_count': self.participants.count(),
            'last_message': self.get_last_message(),
            'unread_count': self.get_unread_count()
        }
    
    def get_last_message(self):
        """Get the last message in this chat."""
        last_message = self.messages.order_by(Message.created_at.desc()).first()
        return last_message.to_dict() if last_message else None
    
    def get_unread_count(self, user_id=None):
        """Get count of unread messages for a specific user."""
        if not user_id:
            return 0
        
        participant = self.participants.filter_by(user_id=user_id).first()
        if not participant:
            return 0
            
        unread_count = self.messages.filter(
            Message.created_at > (participant.last_read_at or datetime.min),
            Message.sender_id != user_id
        ).count()
        
        return unread_count


class Participant(db.Model):
    """
    Participant model linking users to chat conversations.
    
    This model represents the many-to-many relationship between users and chats,
    storing additional metadata about the user's participation in the chat.
    References user IDs from the auth service.
    
    Attributes:
        id (int): Primary key
        chat_id (str): Foreign key to the chat
        user_id (int): ID of the participating user (from auth service)
        joined_at (datetime): When the user joined the chat
        last_read_at (datetime): When the user last read messages
        last_seen_at (datetime): When the user was last seen online
        is_admin (bool): Whether the user is an admin of this chat
        is_muted (bool): Whether the user has muted this chat
        notification_enabled (bool): Whether notifications are enabled
        
    Relationships:
        chat: The chat this participation belongs to
    """
    __tablename__ = 'participants'
    
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.String(36), db.ForeignKey('chats.id'), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)  # Reference to user from auth service
    joined_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_read_at = db.Column(db.DateTime, nullable=True)
    last_seen_at = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_muted = db.Column(db.Boolean, nullable=False, default=False)
    notification_enabled = db.Column(db.Boolean, nullable=False, default=True)
    
    # Unique constraint to prevent duplicate participants
    __table_args__ = (db.UniqueConstraint('chat_id', 'user_id', name='unique_chat_participant'),)
    
    def __repr__(self):
        return f'<Participant {self.user_id} in Chat {self.chat_id}>'
    
    def to_dict(self):
        """Convert participant object to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'chat_id': self.chat_id,
            'user_id': self.user_id,
            'joined_at': self.joined_at.isoformat(),
            'last_read_at': self.last_read_at.isoformat() if self.last_read_at else None,
            'last_seen_at': self.last_seen_at.isoformat() if self.last_seen_at else None,
            'is_admin': self.is_admin,
            'is_muted': self.is_muted,
            'notification_enabled': self.notification_enabled,
            'is_online': self.is_online()
        }
    
    def is_online(self):
        """Check if user is currently online (seen within last 5 minutes)."""
        if not self.last_seen_at:
            return False
        return (datetime.utcnow() - self.last_seen_at).total_seconds() < 300


class Message(db.Model):
    """
    Message model representing individual messages within chats.
    
    This model stores all messages sent in chats, including text messages,
    file attachments, and system messages. Messages are immutable once created
    but can be marked as deleted. Follows naebak platform standards.
    
    Attributes:
        id (str): Unique UUID identifier for the message
        chat_id (str): Foreign key to the chat
        sender_id (int): ID of the user who sent the message (from auth service)
        content (str): The message content (text, file path, etc.)
        message_type (MessageType): Type of message (text, image, file, system)
        status (MessageStatus): Delivery status of the message
        created_at (datetime): When the message was sent
        updated_at (datetime): When the message was last updated
        is_deleted (bool): Whether the message has been deleted
        reply_to_id (str): Optional reference to another message (for replies)
        
    Relationships:
        chat: The chat this message belongs to
        reply_to: The message this is replying to (if any)
        replies: Messages that reply to this message
    """
    __tablename__ = 'messages'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    chat_id = db.Column(db.String(36), db.ForeignKey('chats.id'), nullable=False)
    sender_id = db.Column(db.Integer, nullable=False)  # Reference to user from auth service
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.Enum(MessageType), nullable=False, default=MessageType.TEXT)
    status = db.Column(db.Enum(MessageStatus), nullable=False, default=MessageStatus.SENT)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)
    reply_to_id = db.Column(db.String(36), db.ForeignKey('messages.id'), nullable=True)
    
    # Self-referential relationship for message replies
    reply_to = db.relationship('Message', remote_side=[id], backref='replies')
    
    # Indexes for performance optimization
    __table_args__ = (
        db.Index('idx_chat_created', 'chat_id', 'created_at'),
        db.Index('idx_sender_created', 'sender_id', 'created_at'),
        db.Index('idx_chat_status', 'chat_id', 'status'),
    )
    
    def __repr__(self):
        return f'<Message {self.id} from {self.sender_id} in Chat {self.chat_id}>'
    
    def to_dict(self):
        """Convert message object to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'chat_id': self.chat_id,
            'sender_id': self.sender_id,
            'content': self.content if not self.is_deleted else '[تم حذف الرسالة]',
            'message_type': self.message_type.value,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'is_deleted': self.is_deleted,
            'reply_to_id': self.reply_to_id,
            'reply_to': self.reply_to.to_dict() if self.reply_to and not self.reply_to.is_deleted else None
        }
    
    def mark_as_read(self, user_id):
        """Mark message as read by a specific user."""
        if self.sender_id != user_id and self.status != MessageStatus.READ:
            self.status = MessageStatus.READ
            self.updated_at = datetime.utcnow()
            db.session.commit()


class MessageThread(db.Model):
    """
    Message thread model for organizing related messages.
    
    This model helps organize messages into threads for better conversation
    management, especially useful for support conversations and group chats.
    
    Attributes:
        id (str): Unique UUID identifier for the thread
        chat_id (str): Foreign key to the chat
        title (str): Thread title/subject
        created_by (int): User who created the thread
        created_at (datetime): When the thread was created
        is_closed (bool): Whether the thread is closed
        priority (str): Thread priority level
        
    Relationships:
        chat: The chat this thread belongs to
        messages: Messages in this thread
    """
    __tablename__ = 'message_threads'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    chat_id = db.Column(db.String(36), db.ForeignKey('chats.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    created_by = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_closed = db.Column(db.Boolean, nullable=False, default=False)
    priority = db.Column(db.String(20), nullable=False, default='medium')  # low, medium, high, urgent
    
    def __repr__(self):
        return f'<MessageThread {self.id}: {self.title}>'
    
    def to_dict(self):
        """Convert thread object to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'chat_id': self.chat_id,
            'title': self.title,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat(),
            'is_closed': self.is_closed,
            'priority': self.priority,
            'message_count': self.get_message_count()
        }
    
    def get_message_count(self):
        """Get the number of messages in this thread."""
        return Message.query.filter_by(chat_id=self.chat_id).count()


def init_db(app):
    """
    Initialize the database with the Flask application.
    
    This function configures the database connection according to naebak-almakhzan
    specifications and creates all tables if they don't exist.
    
    Database Configuration (from naebak-almakhzan):
    - Type: PostgreSQL 14
    - Instance: naebak-messages-instance
    - Host: 10.128.0.13
    - Port: 5432
    - Database: naebak_messages
    - User: messages_user
    
    Args:
        app: Flask application instance
    """
    db.init_app(app)
    
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Create additional indexes for performance
        try:
            # Index for chat participants lookup
            db.engine.execute('''
                CREATE INDEX IF NOT EXISTS idx_participants_user_chat 
                ON participants(user_id, chat_id)
            ''')
            
            # Index for message status tracking
            db.engine.execute('''
                CREATE INDEX IF NOT EXISTS idx_messages_status_created 
                ON messages(status, created_at)
            ''')
            
            # Index for unread messages
            db.engine.execute('''
                CREATE INDEX IF NOT EXISTS idx_messages_chat_sender_created 
                ON messages(chat_id, sender_id, created_at)
            ''')
            
            print("✅ Database initialized successfully with all indexes")
            
        except Exception as e:
            print(f"⚠️ Warning: Could not create some indexes: {e}")


def get_user_chats(user_id, page=1, per_page=20):
    """
    Get all chats for a specific user with pagination.
    
    Args:
        user_id (int): User ID from auth service
        page (int): Page number for pagination
        per_page (int): Number of chats per page
        
    Returns:
        dict: Paginated chat data
    """
    participant_chats = db.session.query(Chat).join(Participant).filter(
        Participant.user_id == user_id,
        Chat.is_active == True
    ).order_by(Chat.last_message_at.desc().nullslast()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return {
        'chats': [chat.to_dict() for chat in participant_chats.items],
        'pagination': {
            'page': participant_chats.page,
            'pages': participant_chats.pages,
            'per_page': participant_chats.per_page,
            'total': participant_chats.total,
            'has_next': participant_chats.has_next,
            'has_prev': participant_chats.has_prev
        }
    }

#!/usr/bin/env python3
"""
Naebak Messaging Service - Constants
===================================

Central constants and configuration values for the messaging service.
Includes message types, status codes, limits, and other system constants.

Categories:
- Message Types and Status
- Chat Types and Roles
- File and Media Constants
- API Response Codes
- System Limits
- WebSocket Events
- Error Messages
- Security Constants
"""

from enum import Enum, IntEnum
from datetime import timedelta

# =============================================================================
# MESSAGE CONSTANTS
# =============================================================================

class MessageType(Enum):
    """Message type enumeration"""
    TEXT = "text"
    IMAGE = "image"
    FILE = "file"
    AUDIO = "audio"
    VIDEO = "video"
    LOCATION = "location"
    CONTACT = "contact"
    STICKER = "sticker"
    SYSTEM = "system"
    NOTIFICATION = "notification"

class MessageStatus(Enum):
    """Message delivery status"""
    SENDING = "sending"
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"
    DELETED = "deleted"

class SystemMessageType(Enum):
    """System message types"""
    USER_JOINED = "user_joined"
    USER_LEFT = "user_left"
    USER_ADDED = "user_added"
    USER_REMOVED = "user_removed"
    CHAT_CREATED = "chat_created"
    CHAT_RENAMED = "chat_renamed"
    CHAT_ARCHIVED = "chat_archived"
    CHAT_DELETED = "chat_deleted"
    ROLE_CHANGED = "role_changed"
    SETTINGS_CHANGED = "settings_changed"

# =============================================================================
# CHAT CONSTANTS
# =============================================================================

class ChatType(Enum):
    """Chat type enumeration"""
    PRIVATE = "private"
    GROUP = "group"
    CHANNEL = "channel"
    SUPPORT = "support"
    ANNOUNCEMENT = "announcement"

class ParticipantRole(Enum):
    """Participant role in chat"""
    MEMBER = "member"
    MODERATOR = "moderator"
    ADMIN = "admin"
    OWNER = "owner"

class ChatStatus(Enum):
    """Chat status"""
    ACTIVE = "active"
    ARCHIVED = "archived"
    DELETED = "deleted"
    SUSPENDED = "suspended"

# =============================================================================
# USER CONSTANTS
# =============================================================================

class UserStatus(Enum):
    """User online status"""
    ONLINE = "online"
    OFFLINE = "offline"
    AWAY = "away"
    BUSY = "busy"
    INVISIBLE = "invisible"

class UserRole(Enum):
    """User system role"""
    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"

# =============================================================================
# FILE AND MEDIA CONSTANTS
# =============================================================================

class FileType(Enum):
    """File type categories"""
    IMAGE = "image"
    DOCUMENT = "document"
    AUDIO = "audio"
    VIDEO = "video"
    ARCHIVE = "archive"
    OTHER = "other"

# File size limits (in bytes)
FILE_SIZE_LIMITS = {
    FileType.IMAGE: 10 * 1024 * 1024,      # 10MB
    FileType.DOCUMENT: 50 * 1024 * 1024,   # 50MB
    FileType.AUDIO: 100 * 1024 * 1024,     # 100MB
    FileType.VIDEO: 500 * 1024 * 1024,     # 500MB
    FileType.ARCHIVE: 100 * 1024 * 1024,   # 100MB
    FileType.OTHER: 25 * 1024 * 1024,      # 25MB
}

# Allowed file extensions by type
ALLOWED_EXTENSIONS = {
    FileType.IMAGE: {
        'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'ico'
    },
    FileType.DOCUMENT: {
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'txt', 'rtf', 'odt', 'ods', 'odp', 'csv'
    },
    FileType.AUDIO: {
        'mp3', 'wav', 'ogg', 'flac', 'm4a', 'aac', 'wma'
    },
    FileType.VIDEO: {
        'mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm', '3gp'
    },
    FileType.ARCHIVE: {
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz'
    }
}

# MIME type mappings
MIME_TYPE_MAPPING = {
    # Images
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'png': 'image/png',
    'gif': 'image/gif',
    'webp': 'image/webp',
    'bmp': 'image/bmp',
    'svg': 'image/svg+xml',
    
    # Documents
    'pdf': 'application/pdf',
    'doc': 'application/msword',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xls': 'application/vnd.ms-excel',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'ppt': 'application/vnd.ms-powerpoint',
    'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'txt': 'text/plain',
    'csv': 'text/csv',
    
    # Audio
    'mp3': 'audio/mpeg',
    'wav': 'audio/wav',
    'ogg': 'audio/ogg',
    'flac': 'audio/flac',
    'm4a': 'audio/mp4',
    'aac': 'audio/aac',
    
    # Video
    'mp4': 'video/mp4',
    'avi': 'video/x-msvideo',
    'mkv': 'video/x-matroska',
    'mov': 'video/quicktime',
    'wmv': 'video/x-ms-wmv',
    'webm': 'video/webm',
    
    # Archives
    'zip': 'application/zip',
    'rar': 'application/x-rar-compressed',
    '7z': 'application/x-7z-compressed',
    'tar': 'application/x-tar',
    'gz': 'application/gzip'
}

# =============================================================================
# API RESPONSE CODES
# =============================================================================

class APIResponseCode(IntEnum):
    """Custom API response codes"""
    # Success codes (2xx)
    SUCCESS = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204
    
    # Client error codes (4xx)
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    CONFLICT = 409
    PAYLOAD_TOO_LARGE = 413
    UNSUPPORTED_MEDIA_TYPE = 415
    UNPROCESSABLE_ENTITY = 422
    RATE_LIMITED = 429
    
    # Server error codes (5xx)
    INTERNAL_ERROR = 500
    NOT_IMPLEMENTED = 501
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504

# =============================================================================
# SYSTEM LIMITS
# =============================================================================

class SystemLimits:
    """System-wide limits and constraints"""
    
    # Message limits
    MAX_MESSAGE_LENGTH = 4000
    MAX_MESSAGES_PER_CHAT_FETCH = 100
    MAX_SEARCH_RESULTS = 50
    
    # Chat limits
    MAX_CHAT_NAME_LENGTH = 100
    MAX_CHAT_DESCRIPTION_LENGTH = 500
    MAX_PARTICIPANTS_PER_GROUP = 1000
    MAX_PARTICIPANTS_PER_CHANNEL = 10000
    MAX_CHATS_PER_USER = 500
    
    # File limits
    MAX_FILENAME_LENGTH = 255
    MAX_FILE_SIZE_TOTAL = 1024 * 1024 * 1024  # 1GB
    MAX_FILES_PER_MESSAGE = 10
    
    # Rate limits
    MAX_MESSAGES_PER_MINUTE = 60
    MAX_FILES_PER_HOUR = 100
    MAX_API_REQUESTS_PER_MINUTE = 1000
    MAX_WEBSOCKET_CONNECTIONS_PER_USER = 5
    
    # Search limits
    MIN_SEARCH_QUERY_LENGTH = 2
    MAX_SEARCH_QUERY_LENGTH = 100
    SEARCH_RESULTS_PER_PAGE = 20
    
    # Pagination limits
    DEFAULT_PAGE_SIZE = 20
    MAX_PAGE_SIZE = 100
    
    # Cache limits
    RECENT_MESSAGES_CACHE_SIZE = 100
    USER_SESSION_CACHE_TTL = 3600  # 1 hour
    CHAT_METADATA_CACHE_TTL = 1800  # 30 minutes

# =============================================================================
# WEBSOCKET EVENTS
# =============================================================================

class WebSocketEvent:
    """WebSocket event names"""
    
    # Connection events
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    CONNECTION_SUCCESS = "connection_success"
    CONNECTION_ERROR = "connection_error"
    
    # Chat events
    JOIN_CHAT = "join_chat"
    LEAVE_CHAT = "leave_chat"
    JOINED_CHAT = "joined_chat"
    LEFT_CHAT = "left_chat"
    USER_JOINED_CHAT = "user_joined_chat"
    USER_LEFT_CHAT = "user_left_chat"
    
    # Message events
    SEND_MESSAGE = "send_message"
    NEW_MESSAGE = "new_message"
    MESSAGE_SENT = "message_sent"
    MESSAGE_DELIVERED = "message_delivered"
    MESSAGE_READ = "message_read"
    MESSAGE_EDITED = "message_edited"
    MESSAGE_DELETED = "message_deleted"
    
    # Typing events
    TYPING_START = "typing_start"
    TYPING_STOP = "typing_stop"
    USER_TYPING = "user_typing"
    
    # Presence events
    USER_ONLINE = "user_online"
    USER_OFFLINE = "user_offline"
    USER_STATUS_CHANGED = "user_status_changed"
    
    # Notification events
    NOTIFICATION = "notification"
    SYSTEM_NOTIFICATION = "system_notification"
    
    # Error events
    ERROR = "error"
    VALIDATION_ERROR = "validation_error"
    PERMISSION_ERROR = "permission_error"

# =============================================================================
# ERROR MESSAGES
# =============================================================================

class ErrorMessages:
    """Standard error messages"""
    
    # Authentication errors
    AUTH_REQUIRED = "Authentication required"
    AUTH_INVALID_TOKEN = "Invalid authentication token"
    AUTH_TOKEN_EXPIRED = "Authentication token has expired"
    AUTH_INSUFFICIENT_PERMISSIONS = "Insufficient permissions"
    
    # Validation errors
    VALIDATION_REQUIRED_FIELD = "This field is required"
    VALIDATION_INVALID_FORMAT = "Invalid format"
    VALIDATION_TOO_LONG = "Value is too long"
    VALIDATION_TOO_SHORT = "Value is too short"
    VALIDATION_INVALID_TYPE = "Invalid data type"
    
    # Message errors
    MESSAGE_EMPTY = "Message content cannot be empty"
    MESSAGE_TOO_LONG = f"Message exceeds maximum length of {SystemLimits.MAX_MESSAGE_LENGTH} characters"
    MESSAGE_NOT_FOUND = "Message not found"
    MESSAGE_EDIT_FORBIDDEN = "Cannot edit this message"
    MESSAGE_DELETE_FORBIDDEN = "Cannot delete this message"
    MESSAGE_EDIT_TIME_EXPIRED = "Message is too old to edit"
    
    # Chat errors
    CHAT_NOT_FOUND = "Chat not found"
    CHAT_ACCESS_DENIED = "Access to this chat is denied"
    CHAT_NAME_REQUIRED = "Chat name is required"
    CHAT_NAME_TOO_LONG = f"Chat name exceeds maximum length of {SystemLimits.MAX_CHAT_NAME_LENGTH} characters"
    CHAT_FULL = "Chat has reached maximum participant limit"
    CHAT_ALREADY_MEMBER = "User is already a member of this chat"
    CHAT_NOT_MEMBER = "User is not a member of this chat"
    
    # File errors
    FILE_NOT_PROVIDED = "No file provided"
    FILE_TOO_LARGE = "File size exceeds limit"
    FILE_TYPE_NOT_ALLOWED = "File type not allowed"
    FILE_UPLOAD_FAILED = "File upload failed"
    FILE_NOT_FOUND = "File not found"
    
    # Rate limiting errors
    RATE_LIMIT_EXCEEDED = "Rate limit exceeded. Please try again later"
    TOO_MANY_REQUESTS = "Too many requests. Please slow down"
    
    # System errors
    INTERNAL_ERROR = "Internal server error"
    SERVICE_UNAVAILABLE = "Service temporarily unavailable"
    DATABASE_ERROR = "Database operation failed"
    NETWORK_ERROR = "Network error occurred"
    
    # User errors
    USER_NOT_FOUND = "User not found"
    USER_BLOCKED = "User is blocked"
    USER_OFFLINE = "User is currently offline"

# =============================================================================
# SECURITY CONSTANTS
# =============================================================================

class SecurityConstants:
    """Security-related constants"""
    
    # Token settings
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_ALGORITHM = "HS256"
    
    # Password requirements
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGITS = True
    REQUIRE_SPECIAL_CHARS = True
    
    # Rate limiting
    DEFAULT_RATE_LIMIT = 100  # requests per minute
    BURST_RATE_LIMIT = 20     # requests per 10 seconds
    LOGIN_RATE_LIMIT = 5      # login attempts per minute
    
    # Session settings
    SESSION_TIMEOUT = 3600    # 1 hour in seconds
    MAX_SESSIONS_PER_USER = 5
    
    # Encryption settings
    ENCRYPTION_KEY_LENGTH = 32
    ENCRYPTION_ALGORITHM = "AES-256-GCM"
    HASH_ALGORITHM = "SHA-256"
    SALT_LENGTH = 16
    
    # Security headers
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin"
    }

# =============================================================================
# NOTIFICATION CONSTANTS
# =============================================================================

class NotificationType(Enum):
    """Notification types"""
    MESSAGE = "message"
    MENTION = "mention"
    REPLY = "reply"
    CHAT_INVITE = "chat_invite"
    SYSTEM = "system"
    ANNOUNCEMENT = "announcement"

class NotificationPriority(Enum):
    """Notification priority levels"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"

class NotificationChannel(Enum):
    """Notification delivery channels"""
    IN_APP = "in_app"
    PUSH = "push"
    EMAIL = "email"
    SMS = "sms"
    WEBHOOK = "webhook"

# =============================================================================
# DATABASE CONSTANTS
# =============================================================================

class DatabaseConstants:
    """Database-related constants"""
    
    # Table names
    USERS_TABLE = "users"
    CHATS_TABLE = "chats"
    MESSAGES_TABLE = "messages"
    PARTICIPANTS_TABLE = "participants"
    FILES_TABLE = "files"
    NOTIFICATIONS_TABLE = "notifications"
    
    # Index names
    MESSAGES_CHAT_ID_INDEX = "idx_messages_chat_id"
    MESSAGES_TIMESTAMP_INDEX = "idx_messages_timestamp"
    PARTICIPANTS_USER_ID_INDEX = "idx_participants_user_id"
    PARTICIPANTS_CHAT_ID_INDEX = "idx_participants_chat_id"
    
    # Connection settings
    CONNECTION_POOL_SIZE = 20
    CONNECTION_TIMEOUT = 30
    QUERY_TIMEOUT = 60
    
    # Pagination
    DEFAULT_LIMIT = 20
    MAX_LIMIT = 100

# =============================================================================
# CACHE CONSTANTS
# =============================================================================

class CacheConstants:
    """Cache-related constants"""
    
    # Cache keys
    USER_SESSION_KEY = "user_session:{user_id}"
    CHAT_METADATA_KEY = "chat_metadata:{chat_id}"
    RECENT_MESSAGES_KEY = "recent_messages:{chat_id}"
    USER_CHATS_KEY = "user_chats:{user_id}"
    ONLINE_USERS_KEY = "online_users"
    
    # TTL values (in seconds)
    USER_SESSION_TTL = 3600      # 1 hour
    CHAT_METADATA_TTL = 1800     # 30 minutes
    RECENT_MESSAGES_TTL = 600    # 10 minutes
    USER_CHATS_TTL = 300         # 5 minutes
    ONLINE_USERS_TTL = 60        # 1 minute
    
    # Cache sizes
    MAX_RECENT_MESSAGES = 100
    MAX_USER_SESSIONS = 1000
    MAX_CHAT_METADATA = 5000

# =============================================================================
# LOGGING CONSTANTS
# =============================================================================

class LogLevel(Enum):
    """Logging levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class LogCategory(Enum):
    """Log categories"""
    AUTHENTICATION = "auth"
    AUTHORIZATION = "authz"
    MESSAGE = "message"
    CHAT = "chat"
    FILE = "file"
    WEBSOCKET = "websocket"
    API = "api"
    SECURITY = "security"
    PERFORMANCE = "performance"
    ERROR = "error"

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_file_type_from_extension(extension):
    """Get file type from extension"""
    extension = extension.lower().lstrip('.')
    
    for file_type, extensions in ALLOWED_EXTENSIONS.items():
        if extension in extensions:
            return file_type
    
    return FileType.OTHER

def get_mime_type_from_extension(extension):
    """Get MIME type from extension"""
    extension = extension.lower().lstrip('.')
    return MIME_TYPE_MAPPING.get(extension, 'application/octet-stream')

def is_file_type_allowed(extension, file_type=None):
    """Check if file extension is allowed"""
    extension = extension.lower().lstrip('.')
    
    if file_type:
        return extension in ALLOWED_EXTENSIONS.get(file_type, set())
    
    # Check against all allowed extensions
    for extensions in ALLOWED_EXTENSIONS.values():
        if extension in extensions:
            return True
    
    return False

def get_max_file_size(file_type):
    """Get maximum file size for file type"""
    return FILE_SIZE_LIMITS.get(file_type, FILE_SIZE_LIMITS[FileType.OTHER])

def format_file_size(size_bytes):
    """Format file size in human-readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"

# =============================================================================
# CONFIGURATION VALIDATION
# =============================================================================

def validate_constants():
    """Validate that all constants are properly configured"""
    errors = []
    
    # Validate file size limits
    for file_type, size_limit in FILE_SIZE_LIMITS.items():
        if size_limit <= 0:
            errors.append(f"Invalid file size limit for {file_type}: {size_limit}")
    
    # Validate system limits
    if SystemLimits.MAX_MESSAGE_LENGTH <= 0:
        errors.append("MAX_MESSAGE_LENGTH must be positive")
    
    if SystemLimits.MAX_PARTICIPANTS_PER_GROUP <= 0:
        errors.append("MAX_PARTICIPANTS_PER_GROUP must be positive")
    
    # Validate security constants
    if SecurityConstants.MIN_PASSWORD_LENGTH < 4:
        errors.append("MIN_PASSWORD_LENGTH should be at least 4")
    
    if SecurityConstants.SESSION_TIMEOUT <= 0:
        errors.append("SESSION_TIMEOUT must be positive")
    
    return errors

# Run validation on import
_validation_errors = validate_constants()
if _validation_errors:
    import warnings
    for error in _validation_errors:
        warnings.warn(f"Constants validation error: {error}")

# =============================================================================
# EXPORT ALL CONSTANTS
# =============================================================================

__all__ = [
    # Enums
    'MessageType', 'MessageStatus', 'SystemMessageType',
    'ChatType', 'ParticipantRole', 'ChatStatus',
    'UserStatus', 'UserRole',
    'FileType', 'NotificationType', 'NotificationPriority', 'NotificationChannel',
    'APIResponseCode', 'LogLevel', 'LogCategory',
    
    # Classes
    'SystemLimits', 'SecurityConstants', 'DatabaseConstants', 'CacheConstants',
    'ErrorMessages', 'WebSocketEvent',
    
    # Dictionaries
    'FILE_SIZE_LIMITS', 'ALLOWED_EXTENSIONS', 'MIME_TYPE_MAPPING',
    
    # Utility functions
    'get_file_type_from_extension', 'get_mime_type_from_extension',
    'is_file_type_allowed', 'get_max_file_size', 'format_file_size',
    'validate_constants'
]

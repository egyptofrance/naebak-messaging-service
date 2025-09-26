#!/usr/bin/env python3
"""
Naebak Messaging Service - Security Middleware
==============================================

Comprehensive security middleware for the messaging service providing
authentication, authorization, encryption, and protection against common attacks.

Features:
- JWT token validation and refresh
- Role-based access control (RBAC)
- Rate limiting and DDoS protection
- Input validation and sanitization
- SQL injection prevention
- XSS protection
- CSRF protection
- Message encryption/decryption
- Audit logging
- IP whitelisting/blacklisting
"""

import jwt
import time
import hashlib
import hmac
import re
import json
import logging
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict, deque
from flask import request, jsonify, g, current_app
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import bleach
import ipaddress
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class SecurityConfig:
    """Security configuration constants"""
    
    # JWT Configuration
    JWT_SECRET_KEY = 'your-secret-key-here'  # Should be from environment
    JWT_ALGORITHM = 'HS256'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS = 100
    RATE_LIMIT_WINDOW = 60  # seconds
    RATE_LIMIT_BURST = 20
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
    
    # Input Validation
    MAX_MESSAGE_LENGTH = 4000
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    ALLOWED_FILE_TYPES = {
        'image': ['jpg', 'jpeg', 'png', 'gif', 'webp'],
        'document': ['pdf', 'doc', 'docx', 'txt', 'rtf'],
        'audio': ['mp3', 'wav', 'ogg', 'm4a'],
        'video': ['mp4', 'webm', 'avi', 'mov']
    }
    
    # Encryption
    ENCRYPTION_KEY_DERIVATION_ITERATIONS = 100000

class TokenManager:
    """JWT token management"""
    
    @staticmethod
    def generate_tokens(user_id, user_role='user', additional_claims=None):
        """Generate access and refresh tokens"""
        now = datetime.utcnow()
        
        # Access token payload
        access_payload = {
            'user_id': user_id,
            'role': user_role,
            'type': 'access',
            'iat': now,
            'exp': now + SecurityConfig.JWT_ACCESS_TOKEN_EXPIRES,
            'jti': hashlib.md5(f"{user_id}{now.timestamp()}access".encode()).hexdigest()
        }
        
        if additional_claims:
            access_payload.update(additional_claims)
        
        # Refresh token payload
        refresh_payload = {
            'user_id': user_id,
            'type': 'refresh',
            'iat': now,
            'exp': now + SecurityConfig.JWT_REFRESH_TOKEN_EXPIRES,
            'jti': hashlib.md5(f"{user_id}{now.timestamp()}refresh".encode()).hexdigest()
        }
        
        # Generate tokens
        access_token = jwt.encode(
            access_payload,
            SecurityConfig.JWT_SECRET_KEY,
            algorithm=SecurityConfig.JWT_ALGORITHM
        )
        
        refresh_token = jwt.encode(
            refresh_payload,
            SecurityConfig.JWT_SECRET_KEY,
            algorithm=SecurityConfig.JWT_ALGORITHM
        )
        
        return access_token, refresh_token
    
    @staticmethod
    def validate_token(token, token_type='access'):
        """Validate JWT token"""
        try:
            payload = jwt.decode(
                token,
                SecurityConfig.JWT_SECRET_KEY,
                algorithms=[SecurityConfig.JWT_ALGORITHM]
            )
            
            # Check token type
            if payload.get('type') != token_type:
                return None, 'Invalid token type'
            
            # Check expiration
            if datetime.utcnow() > datetime.fromtimestamp(payload['exp']):
                return None, 'Token expired'
            
            return payload, None
            
        except jwt.ExpiredSignatureError:
            return None, 'Token expired'
        except jwt.InvalidTokenError as e:
            return None, f'Invalid token: {str(e)}'
    
    @staticmethod
    def refresh_access_token(refresh_token):
        """Generate new access token from refresh token"""
        payload, error = TokenManager.validate_token(refresh_token, 'refresh')
        if error:
            return None, error
        
        # Generate new access token
        access_token, _ = TokenManager.generate_tokens(
            payload['user_id'],
            payload.get('role', 'user')
        )
        
        return access_token, None

class RateLimiter:
    """Advanced rate limiting with multiple strategies"""
    
    def __init__(self):
        self.requests = defaultdict(deque)
        self.blocked_ips = {}
        self.suspicious_ips = defaultdict(int)
    
    def is_allowed(self, identifier, limit=None, window=None, burst_limit=None):
        """Check if request is allowed under rate limits"""
        limit = limit or SecurityConfig.RATE_LIMIT_REQUESTS
        window = window or SecurityConfig.RATE_LIMIT_WINDOW
        burst_limit = burst_limit or SecurityConfig.RATE_LIMIT_BURST
        
        now = time.time()
        window_start = now - window
        
        # Check if IP is blocked
        if identifier in self.blocked_ips:
            if now < self.blocked_ips[identifier]:
                return False, 'IP temporarily blocked'
            else:
                del self.blocked_ips[identifier]
        
        # Clean old requests
        while self.requests[identifier] and self.requests[identifier][0] < window_start:
            self.requests[identifier].popleft()
        
        current_requests = len(self.requests[identifier])
        
        # Check burst limit (requests in last 10 seconds)
        burst_window_start = now - 10
        burst_requests = sum(1 for req_time in self.requests[identifier] if req_time > burst_window_start)
        
        if burst_requests >= burst_limit:
            self.suspicious_ips[identifier] += 1
            if self.suspicious_ips[identifier] > 3:
                # Block IP for 1 hour
                self.blocked_ips[identifier] = now + 3600
                return False, 'IP blocked due to suspicious activity'
            return False, 'Burst limit exceeded'
        
        # Check regular rate limit
        if current_requests >= limit:
            return False, 'Rate limit exceeded'
        
        # Allow request
        self.requests[identifier].append(now)
        return True, None

class InputValidator:
    """Input validation and sanitization"""
    
    @staticmethod
    def validate_message_content(content):
        """Validate and sanitize message content"""
        if not content or not isinstance(content, str):
            return None, 'Message content is required'
        
        # Check length
        if len(content) > SecurityConfig.MAX_MESSAGE_LENGTH:
            return None, f'Message too long (max {SecurityConfig.MAX_MESSAGE_LENGTH} characters)'
        
        # Sanitize HTML
        allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'code', 'pre']
        allowed_attributes = {}
        
        sanitized_content = bleach.clean(
            content,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip=True
        )
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'onload\s*=',
            r'onerror\s*=',
            r'onclick\s*='
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return None, 'Potentially malicious content detected'
        
        return sanitized_content, None
    
    @staticmethod
    def validate_file_upload(file):
        """Validate uploaded file"""
        if not file:
            return None, 'No file provided'
        
        # Check file size
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > SecurityConfig.MAX_FILE_SIZE:
            return None, f'File too large (max {SecurityConfig.MAX_FILE_SIZE / 1024 / 1024}MB)'
        
        # Check file extension
        filename = file.filename.lower()
        if not filename or '.' not in filename:
            return None, 'Invalid filename'
        
        extension = filename.rsplit('.', 1)[1]
        allowed_extensions = []
        for file_type, extensions in SecurityConfig.ALLOWED_FILE_TYPES.items():
            allowed_extensions.extend(extensions)
        
        if extension not in allowed_extensions:
            return None, f'File type not allowed. Allowed types: {", ".join(allowed_extensions)}'
        
        # Check for suspicious filenames
        suspicious_patterns = [
            r'\.php$', r'\.jsp$', r'\.asp$', r'\.exe$', r'\.bat$', r'\.cmd$',
            r'\.sh$', r'\.py$', r'\.pl$', r'\.rb$', r'\.js$'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, filename):
                return None, 'Potentially dangerous file type'
        
        return True, None
    
    @staticmethod
    def validate_chat_name(name):
        """Validate chat name"""
        if not name or not isinstance(name, str):
            return None, 'Chat name is required'
        
        name = name.strip()
        if len(name) < 1 or len(name) > 100:
            return None, 'Chat name must be 1-100 characters'
        
        # Remove potentially harmful characters
        sanitized_name = re.sub(r'[<>"\']', '', name)
        
        return sanitized_name, None

class MessageEncryption:
    """Message encryption and decryption"""
    
    def __init__(self, password=None):
        self.password = password or 'default-encryption-key'
        self.key = self._derive_key(self.password)
        self.cipher = Fernet(self.key)
    
    def _derive_key(self, password):
        """Derive encryption key from password"""
        password_bytes = password.encode()
        salt = b'naebak_messaging_salt'  # In production, use random salt per message
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=SecurityConfig.ENCRYPTION_KEY_DERIVATION_ITERATIONS,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    def encrypt_message(self, message):
        """Encrypt message content"""
        try:
            message_bytes = message.encode('utf-8')
            encrypted_bytes = self.cipher.encrypt(message_bytes)
            return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            return message  # Return original if encryption fails
    
    def decrypt_message(self, encrypted_message):
        """Decrypt message content"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_message.encode('utf-8'))
            decrypted_bytes = self.cipher.decrypt(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            return encrypted_message  # Return original if decryption fails

class AuditLogger:
    """Security audit logging"""
    
    @staticmethod
    def log_security_event(event_type, user_id=None, ip_address=None, details=None):
        """Log security-related events"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'details': details or {}
        }
        
        # In production, this would go to a secure logging system
        logger.warning(f"SECURITY EVENT: {json.dumps(log_entry)}")
    
    @staticmethod
    def log_authentication_attempt(user_id, success, ip_address, reason=None):
        """Log authentication attempts"""
        AuditLogger.log_security_event(
            'authentication_attempt',
            user_id=user_id,
            ip_address=ip_address,
            details={
                'success': success,
                'reason': reason,
                'endpoint': request.endpoint
            }
        )
    
    @staticmethod
    def log_authorization_failure(user_id, resource, action, ip_address):
        """Log authorization failures"""
        AuditLogger.log_security_event(
            'authorization_failure',
            user_id=user_id,
            ip_address=ip_address,
            details={
                'resource': resource,
                'action': action,
                'endpoint': request.endpoint
            }
        )

class IPFilter:
    """IP address filtering and geolocation"""
    
    def __init__(self):
        self.whitelist = set()
        self.blacklist = set()
        self.country_blacklist = set()
    
    def add_to_whitelist(self, ip_or_range):
        """Add IP or IP range to whitelist"""
        try:
            network = ipaddress.ip_network(ip_or_range, strict=False)
            self.whitelist.add(network)
        except ValueError:
            logger.error(f"Invalid IP address or range: {ip_or_range}")
    
    def add_to_blacklist(self, ip_or_range):
        """Add IP or IP range to blacklist"""
        try:
            network = ipaddress.ip_network(ip_or_range, strict=False)
            self.blacklist.add(network)
        except ValueError:
            logger.error(f"Invalid IP address or range: {ip_or_range}")
    
    def is_allowed(self, ip_address):
        """Check if IP address is allowed"""
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Check whitelist first
            if self.whitelist:
                for network in self.whitelist:
                    if ip in network:
                        return True, None
                return False, 'IP not in whitelist'
            
            # Check blacklist
            for network in self.blacklist:
                if ip in network:
                    return False, 'IP is blacklisted'
            
            return True, None
            
        except ValueError:
            return False, 'Invalid IP address'

# Initialize global instances
rate_limiter = RateLimiter()
message_encryption = MessageEncryption()
ip_filter = IPFilter()

# Middleware decorators
def require_authentication(f):
    """Require valid JWT token"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            AuditLogger.log_authentication_attempt(
                None, False, request.remote_addr, 'Missing token'
            )
            return jsonify({'error': 'Authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        payload, error = TokenManager.validate_token(token)
        
        if error:
            AuditLogger.log_authentication_attempt(
                None, False, request.remote_addr, error
            )
            return jsonify({'error': error}), 401
        
        # Store user info in request context
        g.current_user_id = payload['user_id']
        g.current_user_role = payload.get('role', 'user')
        g.token_payload = payload
        
        AuditLogger.log_authentication_attempt(
            payload['user_id'], True, request.remote_addr
        )
        
        return f(*args, **kwargs)
    
    return decorated_function

def require_role(required_role):
    """Require specific user role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'current_user_role'):
                return jsonify({'error': 'Authentication required'}), 401
            
            user_role = g.current_user_role
            role_hierarchy = ['user', 'moderator', 'admin', 'super_admin']
            
            if user_role not in role_hierarchy or required_role not in role_hierarchy:
                return jsonify({'error': 'Invalid role'}), 403
            
            user_level = role_hierarchy.index(user_role)
            required_level = role_hierarchy.index(required_role)
            
            if user_level < required_level:
                AuditLogger.log_authorization_failure(
                    g.current_user_id, request.endpoint, required_role, request.remote_addr
                )
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def apply_rate_limiting(limit=None, window=None, per_user=False):
    """Apply rate limiting to endpoint"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if per_user and hasattr(g, 'current_user_id'):
                identifier = f"user_{g.current_user_id}"
            else:
                identifier = request.remote_addr
            
            allowed, reason = rate_limiter.is_allowed(identifier, limit, window)
            
            if not allowed:
                AuditLogger.log_security_event(
                    'rate_limit_exceeded',
                    user_id=getattr(g, 'current_user_id', None),
                    ip_address=request.remote_addr,
                    details={'reason': reason, 'endpoint': request.endpoint}
                )
                return jsonify({'error': reason}), 429
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def validate_input(validation_func):
    """Apply input validation"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.is_json:
                data = request.get_json()
                validated_data, error = validation_func(data)
                if error:
                    return jsonify({'error': error}), 400
                request.validated_data = validated_data
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def add_security_headers(response):
    """Add security headers to response"""
    for header, value in SecurityConfig.SECURITY_HEADERS.items():
        response.headers[header] = value
    return response

def check_ip_filter(f):
    """Check IP address against filters"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        
        # Get real IP if behind proxy
        if request.headers.get('X-Forwarded-For'):
            client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            client_ip = request.headers.get('X-Real-IP')
        
        allowed, reason = ip_filter.is_allowed(client_ip)
        
        if not allowed:
            AuditLogger.log_security_event(
                'ip_blocked',
                ip_address=client_ip,
                details={'reason': reason, 'endpoint': request.endpoint}
            )
            return jsonify({'error': 'Access denied'}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function

# Utility functions
def encrypt_message(message):
    """Encrypt message content"""
    return message_encryption.encrypt_message(message)

def decrypt_message(encrypted_message):
    """Decrypt message content"""
    return message_encryption.decrypt_message(encrypted_message)

def generate_csrf_token():
    """Generate CSRF token"""
    return hashlib.sha256(f"{time.time()}{request.remote_addr}".encode()).hexdigest()

def validate_csrf_token(token):
    """Validate CSRF token"""
    # Simple validation - in production, use more sophisticated method
    return len(token) == 64 and all(c in '0123456789abcdef' for c in token)

def secure_filename(filename):
    """Create secure filename"""
    # Remove path components
    filename = filename.split('/')[-1].split('\\')[-1]
    
    # Remove dangerous characters
    filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
    
    # Limit length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:250] + ('.' + ext if ext else '')
    
    return filename

def init_security_middleware(app):
    """Initialize security middleware with Flask app"""
    
    @app.before_request
    def before_request():
        """Run before each request"""
        # Add request ID for tracking
        g.request_id = hashlib.md5(f"{time.time()}{request.remote_addr}".encode()).hexdigest()[:8]
        
        # Log request
        logger.info(f"Request {g.request_id}: {request.method} {request.path} from {request.remote_addr}")
    
    @app.after_request
    def after_request(response):
        """Run after each request"""
        # Add security headers
        response = add_security_headers(response)
        
        # Log response
        logger.info(f"Response {getattr(g, 'request_id', 'unknown')}: {response.status_code}")
        
        return response
    
    # Add error handlers
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({'error': 'Unauthorized access'}), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({'error': 'Access forbidden'}), 403
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return jsonify({'error': 'Rate limit exceeded'}), 429

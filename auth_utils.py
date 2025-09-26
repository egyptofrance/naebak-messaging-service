"""
Naebak Messaging Service - Authentication Utilities

This module provides authentication utilities for verifying JWT tokens
and integrating with the naebak auth service. It handles token validation,
user information retrieval, and permission checking.

Functions:
- verify_jwt_token: Verify and decode JWT tokens
- get_user_info: Get user information from auth service
- check_user_permissions: Check user permissions for messaging
- refresh_token: Refresh expired tokens
"""

import jwt
import requests
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import current_app, request
import os

# Configure logging
logger = logging.getLogger(__name__)

# Auth service configuration (from naebak-almakhzan specs)
AUTH_SERVICE_URL = os.getenv('AUTH_SERVICE_URL', 'http://localhost:8001')
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
JWT_ALGORITHM = 'HS256'

# Cache for user info to reduce API calls
user_info_cache = {}
cache_expiry = {}


def verify_jwt_token(token):
    """
    Verify and decode JWT token from auth service.
    
    Args:
        token (str): JWT token to verify
        
    Returns:
        dict: Decoded token data if valid, None if invalid
    """
    try:
        # Decode the token
        decoded_token = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )
        
        # Check if token is expired
        if 'exp' in decoded_token:
            if datetime.utcnow().timestamp() > decoded_token['exp']:
                logger.warning("Token has expired")
                return None
        
        # Validate required fields
        required_fields = ['user_id', 'email', 'user_type']
        for field in required_fields:
            if field not in decoded_token:
                logger.warning(f"Token missing required field: {field}")
                return None
        
        logger.info(f"Token verified successfully for user {decoded_token['user_id']}")
        return decoded_token
        
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        return None


def get_user_info(user_id, use_cache=True):
    """
    Get user information from auth service or cache.
    
    Args:
        user_id (int): User ID to get information for
        use_cache (bool): Whether to use cached data
        
    Returns:
        dict: User information if found, None if not found
    """
    try:
        # Check cache first if enabled
        if use_cache and user_id in user_info_cache:
            if user_id in cache_expiry and datetime.utcnow() < cache_expiry[user_id]:
                return user_info_cache[user_id]
        
        # Make request to auth service
        response = requests.get(
            f"{AUTH_SERVICE_URL}/api/v1/users/{user_id}",
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            timeout=5
        )
        
        if response.status_code == 200:
            user_data = response.json()
            
            if user_data.get('success'):
                user_info = user_data.get('data', {}).get('user', {})
                
                # Cache the user info for 5 minutes
                if use_cache:
                    user_info_cache[user_id] = user_info
                    cache_expiry[user_id] = datetime.utcnow() + timedelta(minutes=5)
                
                return user_info
            else:
                logger.warning(f"Auth service returned error for user {user_id}")
                return None
        else:
            logger.warning(f"Auth service returned status {response.status_code} for user {user_id}")
            return None
            
    except requests.RequestException as e:
        logger.error(f"Error connecting to auth service for user {user_id}: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Error getting user info for user {user_id}: {str(e)}")
        return None


def check_user_permissions(user_id, action, resource_id=None):
    """
    Check if user has permission to perform an action.
    
    Args:
        user_id (int): User ID to check permissions for
        action (str): Action to check (send_message, create_chat, etc.)
        resource_id (str): Optional resource ID (chat_id, etc.)
        
    Returns:
        bool: True if user has permission, False otherwise
    """
    try:
        user_info = get_user_info(user_id)
        if not user_info:
            return False
        
        user_type = user_info.get('user_type', '')
        is_verified = user_info.get('is_verified', False)
        
        # Basic permission checks
        if not is_verified:
            logger.warning(f"Unverified user {user_id} attempted action {action}")
            return False
        
        # Action-specific permission checks
        if action == 'send_message':
            # All verified users can send messages
            return True
            
        elif action == 'create_chat':
            # All verified users can create chats
            return True
            
        elif action == 'create_group_chat':
            # Only representatives can create group chats
            return user_type in ['مرشح', 'عضو حالي']
            
        elif action == 'moderate_chat':
            # Only representatives and admins can moderate
            return user_type in ['مرشح', 'عضو حالي'] or user_info.get('is_admin', False)
        
        # Default deny
        return False
        
    except Exception as e:
        logger.error(f"Error checking permissions for user {user_id}: {str(e)}")
        return False


def get_user_contacts(user_id):
    """
    Get list of users that this user can message.
    
    Args:
        user_id (int): User ID to get contacts for
        
    Returns:
        list: List of user contacts
    """
    try:
        user_info = get_user_info(user_id)
        if not user_info:
            return []
        
        user_type = user_info.get('user_type', '')
        governorate = user_info.get('governorate', '')
        
        # Build contacts based on user type
        contacts = []
        
        if user_type == 'مواطن':
            # Citizens can message representatives from their governorate
            response = requests.get(
                f"{AUTH_SERVICE_URL}/api/v1/users/representatives",
                params={
                    'governorate': governorate,
                    'is_verified': True
                },
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    contacts = data.get('data', {}).get('users', [])
        
        elif user_type in ['مرشح', 'عضو حالي']:
            # Representatives can message anyone in their governorate
            response = requests.get(
                f"{AUTH_SERVICE_URL}/api/v1/users",
                params={
                    'governorate': governorate,
                    'is_verified': True
                },
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    contacts = data.get('data', {}).get('users', [])
        
        return contacts
        
    except Exception as e:
        logger.error(f"Error getting contacts for user {user_id}: {str(e)}")
        return []


def validate_chat_participants(user_id, participant_ids):
    """
    Validate that a user can create a chat with specific participants.
    
    Args:
        user_id (int): User creating the chat
        participant_ids (list): List of participant user IDs
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        user_info = get_user_info(user_id)
        if not user_info:
            return False
        
        user_type = user_info.get('user_type', '')
        user_governorate = user_info.get('governorate', '')
        
        # Get info for all participants
        for participant_id in participant_ids:
            if participant_id == user_id:
                continue
                
            participant_info = get_user_info(participant_id)
            if not participant_info:
                return False
            
            participant_type = participant_info.get('user_type', '')
            participant_governorate = participant_info.get('governorate', '')
            
            # Validation rules based on user types
            if user_type == 'مواطن':
                # Citizens can only message representatives from same governorate
                if participant_type not in ['مرشح', 'عضو حالي']:
                    return False
                if participant_governorate != user_governorate:
                    return False
            
            elif user_type in ['مرشح', 'عضو حالي']:
                # Representatives can message anyone from same governorate
                if participant_governorate != user_governorate:
                    return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error validating chat participants: {str(e)}")
        return False


def require_auth(f):
    """
    Decorator to require authentication for API endpoints.
    
    Args:
        f: Function to decorate
        
    Returns:
        function: Decorated function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return {
                'success': False,
                'message': 'رمز المصادقة مطلوب',
                'error': 'Authorization header missing'
            }, 401
        
        try:
            # Extract token from "Bearer <token>"
            token = auth_header.split(' ')[1]
        except IndexError:
            return {
                'success': False,
                'message': 'تنسيق رمز المصادقة غير صحيح',
                'error': 'Invalid authorization header format'
            }, 401
        
        # Verify token
        user_data = verify_jwt_token(token)
        if not user_data:
            return {
                'success': False,
                'message': 'رمز المصادقة غير صحيح أو منتهي الصلاحية',
                'error': 'Invalid or expired token'
            }, 401
        
        # Add user data to request context
        request.current_user = user_data
        
        return f(*args, **kwargs)
    
    return decorated_function


def get_current_user():
    """
    Get current authenticated user from request context.
    
    Returns:
        dict: Current user data if authenticated, None otherwise
    """
    return getattr(request, 'current_user', None)


def clear_user_cache(user_id):
    """
    Clear cached user information.
    
    Args:
        user_id (int): User ID to clear cache for
    """
    if user_id in user_info_cache:
        del user_info_cache[user_id]
    if user_id in cache_expiry:
        del cache_expiry[user_id]


def refresh_token(token):
    """
    Refresh an expired JWT token.
    
    Args:
        token (str): Expired token to refresh
        
    Returns:
        str: New token if successful, None if failed
    """
    try:
        # Make request to auth service to refresh token
        response = requests.post(
            f"{AUTH_SERVICE_URL}/api/v1/auth/refresh",
            json={'token': token},
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                return data.get('data', {}).get('token')
        
        return None
        
    except Exception as e:
        logger.error(f"Error refreshing token: {str(e)}")
        return None


def validate_message_content(content, message_type='text'):
    """
    Validate message content based on type and platform rules.
    
    Args:
        content (str): Message content to validate
        message_type (str): Type of message (text, image, file)
        
    Returns:
        tuple: (is_valid, error_message)
    """
    try:
        if not content or not content.strip():
            return False, "محتوى الرسالة لا يمكن أن يكون فارغاً"
        
        if message_type == 'text':
            # Text message validation
            if len(content) > 2000:
                return False, "الرسالة طويلة جداً (الحد الأقصى 2000 حرف)"
            
            # Check for inappropriate content (basic check)
            inappropriate_words = ['spam', 'scam']  # Add more as needed
            content_lower = content.lower()
            for word in inappropriate_words:
                if word in content_lower:
                    return False, "الرسالة تحتوي على محتوى غير مناسب"
        
        elif message_type in ['image', 'file']:
            # File/image validation
            if not content.startswith(('http://', 'https://', '/uploads/')):
                return False, "رابط الملف غير صحيح"
        
        return True, None
        
    except Exception as e:
        logger.error(f"Error validating message content: {str(e)}")
        return False, "خطأ في التحقق من محتوى الرسالة"

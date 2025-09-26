"""
Naebak Messaging Service

A comprehensive Flask-based messaging service for real-time communication 
between users in the Naebak platform. This service handles direct messages, 
group chats, and support conversations with full WebSocket support.

Features:
- Real-time messaging with WebSocket support
- Direct messages between citizens and representatives
- Group chat functionality for representatives
- Support conversations with admins
- Message history and persistence with Redis caching
- User presence and typing indicators
- File and image sharing capabilities
- Rate limiting and security features
- Integration with naebak auth service

API Endpoints:
- POST /api/v1/chats - Create new chat
- GET /api/v1/chats - Get user's chats
- GET /api/v1/chats/{id}/messages - Get chat messages
- POST /api/v1/chats/{id}/messages - Send message
- WebSocket /socket.io - Real-time messaging

Database Models:
- Chat: Represents a conversation
- Participant: Links users to chats
- Message: Individual messages in chats
- MessageThread: Organizes related messages
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
from flask_jwt_extended import JWTManager
import os
from datetime import datetime
import logging

# Import our modules
from models import db, init_db, Chat, Participant, Message, MessageType, MessageStatus, ChatType, get_user_chats
from websocket_handlers import init_socketio
from auth_utils import require_auth, get_current_user, check_user_permissions, validate_chat_participants, validate_message_content
from redis_manager import get_redis_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app, origins="*")

# Configuration from naebak-almakhzan specifications
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'naebak-messaging-secret-key-2024')
app.config['DEBUG'] = os.getenv('DEBUG', 'False').lower() == 'true'

# Database configuration (PostgreSQL from naebak-almakhzan)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'postgresql://messages_user:messages_pass@10.128.0.13:5432/naebak_messages'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 120,
    'pool_pre_ping': True
}

# JWT configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'naebak-jwt-secret-2024')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False

# Initialize extensions
jwt = JWTManager(app)
init_db(app)
socketio = init_socketio(app)
redis_manager = get_redis_manager()

@app.route('/')
def health_check():
    """
    Health check endpoint to verify service is running.
    
    Returns:
        dict: Service status and comprehensive information
    """
    try:
        # Check database connection
        db_status = True
        try:
            db.session.execute('SELECT 1')
        except Exception:
            db_status = False
        
        # Check Redis connection
        redis_status = redis_manager.health_check()
        
        return {
            'service': 'naebak-messaging-service',
            'status': 'healthy' if db_status and all(redis_status.values()) else 'degraded',
            'version': '2.0.0',
            'timestamp': datetime.utcnow().isoformat(),
            'port': int(os.getenv('PORT', 8004)),
            'database': {
                'status': 'connected' if db_status else 'disconnected',
                'type': 'PostgreSQL'
            },
            'redis': {
                'cache_client': 'connected' if redis_status['cache_client'] else 'disconnected',
                'pubsub_client': 'connected' if redis_status['pubsub_client'] else 'disconnected'
            },
            'features': [
                'Real-time messaging via WebSocket',
                'Direct messages between users',
                'Group chats for representatives',
                'Support conversations',
                'Message persistence with PostgreSQL',
                'Redis caching and pub/sub',
                'File and image sharing',
                'Typing indicators',
                'User presence tracking',
                'Rate limiting',
                'JWT authentication integration'
            ],
            'websocket_endpoint': '/socket.io',
            'api_base': '/api/v1'
        }
    except Exception as e:
        logger.error(f"Health check error: {str(e)}")
        return {
            'service': 'naebak-messaging-service',
            'status': 'error',
            'error': str(e)
        }, 500

@app.route('/api/v1/chats', methods=['GET'])
@require_auth
def get_chats():
    """
    Get all chats for the authenticated user with pagination and filtering.
    
    Query Parameters:
        page (int): Page number for pagination (default: 1)
        per_page (int): Items per page (default: 20, max: 100)
        search (str): Search term for chat names
        chat_type (str): Filter by chat type (direct, group, support)
        
    Returns:
        dict: List of user's chats with pagination info and unread counts
    """
    try:
        current_user = get_current_user()
        user_id = current_user['user_id']
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        search = request.args.get('search', '').strip()
        chat_type = request.args.get('chat_type', '').strip()
        
        # Get chats from database with caching
        chats_data = get_user_chats(user_id, page, per_page)
        
        # Apply filters if provided
        if search or chat_type:
            filtered_chats = []
            for chat in chats_data['chats']:
                if search and search.lower() not in (chat.get('name', '') or '').lower():
                    continue
                if chat_type and chat.get('chat_type') != chat_type:
                    continue
                filtered_chats.append(chat)
            chats_data['chats'] = filtered_chats
        
        # Add cached data where available
        for chat in chats_data['chats']:
            chat_id = chat['id']
            
            # Get last message from cache
            cached_last_message = redis_manager.get_chat_last_message(chat_id)
            if cached_last_message:
                chat['last_message'] = cached_last_message
            
            # Get unread count
            chat['unread_count'] = Chat.query.get(chat_id).get_unread_count(user_id) if Chat.query.get(chat_id) else 0
        
        logger.info(f"Retrieved {len(chats_data['chats'])} chats for user {user_id}")
        
        return {
            'success': True,
            'data': chats_data,
            'message': f'تم جلب {len(chats_data["chats"])} محادثة بنجاح'
        }
        
    except Exception as e:
        logger.error(f"Error getting chats for user: {str(e)}")
        return {
            'success': False,
            'message': 'خطأ في جلب المحادثات',
            'error': str(e)
        }, 500

@app.route('/api/v1/chats', methods=['POST'])
@require_auth
def create_chat():
    """
    Create a new chat conversation.
    
    Request Body:
        participants (list): List of user IDs to include in chat
        name (str): Optional name for group chats
        chat_type (str): Type of chat (direct, group, support) - default: direct
        
    Returns:
        dict: Created chat information
    """
    try:
        current_user = get_current_user()
        user_id = current_user['user_id']
        
        data = request.get_json()
        if not data:
            return {
                'success': False,
                'message': 'بيانات الطلب مطلوبة'
            }, 400
        
        participants = data.get('participants', [])
        chat_name = data.get('name', '').strip()
        chat_type = data.get('chat_type', 'direct').strip()
        
        # Validate input
        if not participants:
            return {
                'success': False,
                'message': 'قائمة المشاركين مطلوبة'
            }, 400
        
        # Add current user to participants if not included
        if user_id not in participants:
            participants.append(user_id)
        
        # Validate chat type
        try:
            chat_type_enum = ChatType(chat_type)
        except ValueError:
            return {
                'success': False,
                'message': 'نوع المحادثة غير صحيح'
            }, 400
        
        # Check permissions
        if chat_type == 'group' and not check_user_permissions(user_id, 'create_group_chat'):
            return {
                'success': False,
                'message': 'غير مصرح بإنشاء محادثات جماعية'
            }, 403
        
        # Validate participants
        if not validate_chat_participants(user_id, participants):
            return {
                'success': False,
                'message': 'غير مصرح بإنشاء محادثة مع هؤلاء المشاركين'
            }, 403
        
        # Check if direct chat already exists
        if chat_type == 'direct' and len(participants) == 2:
            existing_chat = db.session.query(Chat).join(Participant).filter(
                Chat.chat_type == ChatType.DIRECT,
                Chat.is_active == True
            ).group_by(Chat.id).having(
                db.func.count(Participant.user_id) == 2
            ).first()
            
            if existing_chat:
                # Check if both users are participants
                participant_ids = [p.user_id for p in existing_chat.participants]
                if set(participants) == set(participant_ids):
                    return {
                        'success': True,
                        'message': 'المحادثة موجودة بالفعل',
                        'data': {
                            'chat': existing_chat.to_dict()
                        }
                    }
        
        # Create new chat
        new_chat = Chat(
            name=chat_name if chat_name else None,
            chat_type=chat_type_enum
        )
        db.session.add(new_chat)
        db.session.flush()  # Get the chat ID
        
        # Add participants
        for participant_id in participants:
            participant = Participant(
                chat_id=new_chat.id,
                user_id=participant_id,
                is_admin=(participant_id == user_id)  # Creator is admin
            )
            db.session.add(participant)
        
        db.session.commit()
        
        # Cache the new chat
        chat_data = new_chat.to_dict()
        redis_manager.increment_chat_stats(new_chat.id, 'users_joined')
        
        logger.info(f"Chat {new_chat.id} created by user {user_id} with {len(participants)} participants")
        
        return {
            'success': True,
            'message': 'تم إنشاء المحادثة بنجاح',
            'data': {
                'chat': chat_data
            }
        }, 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating chat: {str(e)}")
        return {
            'success': False,
            'message': 'خطأ في إنشاء المحادثة',
            'error': str(e)
        }, 500

@app.route('/api/v1/chats/<chat_id>/messages', methods=['GET'])
@require_auth
def get_messages(chat_id):
    """
    Get messages for a specific chat with pagination.
    
    Path Parameters:
        chat_id (str): Chat identifier
        
    Query Parameters:
        page (int): Page number for pagination (default: 1)
        per_page (int): Messages per page (default: 50, max: 100)
        before (str): Get messages before this timestamp (ISO format)
        
    Returns:
        dict: List of messages in the chat with pagination
    """
    try:
        current_user = get_current_user()
        user_id = current_user['user_id']
        
        # Verify user is participant in this chat
        participant = Participant.query.filter_by(
            chat_id=chat_id,
            user_id=user_id
        ).first()
        
        if not participant:
            return {
                'success': False,
                'message': 'غير مصرح بالوصول لهذه المحادثة'
            }, 403
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)
        before = request.args.get('before')
        
        # Try to get recent messages from cache first
        if page == 1 and not before:
            cached_messages = redis_manager.get_chat_recent_messages(chat_id, per_page)
            if cached_messages:
                return {
                    'success': True,
                    'data': {
                        'messages': cached_messages,
                        'pagination': {
                            'page': 1,
                            'per_page': per_page,
                            'total': len(cached_messages),
                            'from_cache': True
                        }
                    }
                }
        
        # Get messages from database
        query = Message.query.filter_by(
            chat_id=chat_id,
            is_deleted=False
        )
        
        if before:
            try:
                before_dt = datetime.fromisoformat(before.replace('Z', '+00:00'))
                query = query.filter(Message.created_at < before_dt)
            except ValueError:
                return {
                    'success': False,
                    'message': 'تنسيق التاريخ غير صحيح'
                }, 400
        
        messages_paginated = query.order_by(Message.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        messages = [message.to_dict() for message in reversed(messages_paginated.items)]
        
        # Update participant's last read timestamp
        participant.last_read_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Retrieved {len(messages)} messages for chat {chat_id}, user {user_id}")
        
        return {
            'success': True,
            'data': {
                'messages': messages,
                'pagination': {
                    'page': messages_paginated.page,
                    'pages': messages_paginated.pages,
                    'per_page': messages_paginated.per_page,
                    'total': messages_paginated.total,
                    'has_next': messages_paginated.has_next,
                    'has_prev': messages_paginated.has_prev
                }
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting messages for chat {chat_id}: {str(e)}")
        return {
            'success': False,
            'message': 'خطأ في جلب الرسائل',
            'error': str(e)
        }, 500

@app.route('/api/v1/chats/<chat_id>/messages', methods=['POST'])
@require_auth
def send_message(chat_id):
    """
    Send a message to a chat.
    
    Path Parameters:
        chat_id (str): Chat identifier
        
    Request Body:
        content (str): Message content
        message_type (str): Type of message (text, image, file) - default: text
        reply_to_id (str): Optional ID of message being replied to
        
    Returns:
        dict: Sent message information
    """
    try:
        current_user = get_current_user()
        user_id = current_user['user_id']
        
        # Check rate limiting
        if not redis_manager.check_rate_limit(user_id, 'send_message', 30):
            return {
                'success': False,
                'message': 'تم تجاوز الحد المسموح لإرسال الرسائل'
            }, 429
        
        # Verify user is participant in this chat
        participant = Participant.query.filter_by(
            chat_id=chat_id,
            user_id=user_id
        ).first()
        
        if not participant:
            return {
                'success': False,
                'message': 'غير مصرح بإرسال رسائل في هذه المحادثة'
            }, 403
        
        data = request.get_json()
        if not data:
            return {
                'success': False,
                'message': 'بيانات الرسالة مطلوبة'
            }, 400
        
        content = data.get('content', '').strip()
        message_type = data.get('message_type', 'text').strip()
        reply_to_id = data.get('reply_to_id')
        
        # Validate message content
        is_valid, error_message = validate_message_content(content, message_type)
        if not is_valid:
            return {
                'success': False,
                'message': error_message
            }, 400
        
        # Validate message type
        try:
            message_type_enum = MessageType(message_type)
        except ValueError:
            return {
                'success': False,
                'message': 'نوع الرسالة غير صحيح'
            }, 400
        
        # Validate reply_to_id if provided
        if reply_to_id:
            reply_message = Message.query.filter_by(
                id=reply_to_id,
                chat_id=chat_id,
                is_deleted=False
            ).first()
            if not reply_message:
                return {
                    'success': False,
                    'message': 'الرسالة المرجعية غير موجودة'
                }, 400
        
        # Create new message
        new_message = Message(
            chat_id=chat_id,
            sender_id=user_id,
            content=content,
            message_type=message_type_enum,
            reply_to_id=reply_to_id,
            status=MessageStatus.SENT
        )
        
        db.session.add(new_message)
        
        # Update chat's last message timestamp
        chat = Chat.query.get(chat_id)
        if chat:
            chat.last_message_at = datetime.utcnow()
            chat.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        # Cache the message
        message_data = new_message.to_dict()
        redis_manager.cache_message(message_data)
        redis_manager.increment_chat_stats(chat_id, 'messages_sent')
        
        # Broadcast via WebSocket (handled by WebSocket handlers)
        # The WebSocket handler will pick this up and broadcast to connected clients
        
        logger.info(f"Message {new_message.id} sent by user {user_id} in chat {chat_id}")
        
        return {
            'success': True,
            'message': 'تم إرسال الرسالة بنجاح',
            'data': {
                'message': message_data
            }
        }, 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error sending message to chat {chat_id}: {str(e)}")
        return {
            'success': False,
            'message': 'خطأ في إرسال الرسالة',
            'error': str(e)
        }, 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return {
        'success': False,
        'message': 'الصفحة غير موجودة',
        'error': 'Not found'
    }, 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return {
        'success': False,
        'message': 'خطأ داخلي في الخادم',
        'error': 'Internal server error'
    }, 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8004))
    logger.info(f"Starting Naebak Messaging Service on port {port}")
    
    # Run with SocketIO
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=app.config['DEBUG'],
        allow_unsafe_werkzeug=True
    )

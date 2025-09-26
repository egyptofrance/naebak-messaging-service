"""
Naebak Messaging Service - WebSocket Handlers

This module implements WebSocket event handlers for real-time messaging
functionality. It handles connection management, message broadcasting,
and real-time communication between users.

Events Handled:
- connect: User connects to the messaging service
- disconnect: User disconnects from the messaging service
- join_room: User joins a specific chat room
- leave_room: User leaves a specific chat room
- send_message: User sends a message to a chat
- typing: User is typing indicator
- mark_read: Mark messages as read

Integration with naebak-almakhzan specifications:
- Uses JWT authentication from auth service
- Follows API response patterns
- Integrates with PostgreSQL database
"""

from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask_jwt_extended import decode_token, JWTManager
from datetime import datetime
import json
import logging
from models import db, Chat, Participant, Message, MessageType, MessageStatus
from auth_utils import verify_jwt_token, get_user_info

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Store active connections
active_connections = {}
typing_users = {}


def init_socketio(app):
    """
    Initialize SocketIO with the Flask application.
    
    Args:
        app: Flask application instance
        
    Returns:
        SocketIO: Configured SocketIO instance
    """
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        async_mode='eventlet',
        logger=True,
        engineio_logger=True
    )
    
    # Register event handlers
    register_handlers(socketio)
    
    return socketio


def register_handlers(socketio):
    """
    Register all WebSocket event handlers.
    
    Args:
        socketio: SocketIO instance
    """
    
    @socketio.on('connect')
    def handle_connect(auth):
        """
        Handle user connection to WebSocket.
        
        Authenticates the user using JWT token and establishes connection.
        Updates user's last_seen_at timestamp.
        
        Args:
            auth (dict): Authentication data containing JWT token
        """
        try:
            # Verify JWT token
            if not auth or 'token' not in auth:
                logger.warning("Connection attempt without token")
                disconnect()
                return False
            
            token = auth['token']
            user_data = verify_jwt_token(token)
            
            if not user_data:
                logger.warning("Connection attempt with invalid token")
                disconnect()
                return False
            
            user_id = user_data['user_id']
            
            # Store connection info
            active_connections[request.sid] = {
                'user_id': user_id,
                'connected_at': datetime.utcnow(),
                'user_data': user_data
            }
            
            # Update user's last seen timestamp in all their chats
            update_user_last_seen(user_id)
            
            # Emit connection success
            emit('connected', {
                'success': True,
                'message': 'تم الاتصال بنجاح',
                'user_id': user_id,
                'timestamp': datetime.utcnow().isoformat()
            })
            
            # Join user to their personal room for direct notifications
            join_room(f"user_{user_id}")
            
            # Notify other users that this user is online
            notify_user_online(user_id)
            
            logger.info(f"User {user_id} connected successfully")
            
        except Exception as e:
            logger.error(f"Connection error: {str(e)}")
            emit('error', {
                'success': False,
                'message': 'خطأ في الاتصال',
                'error': str(e)
            })
            disconnect()
            return False
    
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """
        Handle user disconnection from WebSocket.
        
        Cleans up connection data and updates user's last seen timestamp.
        """
        try:
            if request.sid in active_connections:
                user_data = active_connections[request.sid]
                user_id = user_data['user_id']
                
                # Update last seen timestamp
                update_user_last_seen(user_id)
                
                # Remove from active connections
                del active_connections[request.sid]
                
                # Remove from typing users if present
                if user_id in typing_users:
                    del typing_users[user_id]
                
                # Leave personal room
                leave_room(f"user_{user_id}")
                
                # Notify other users that this user is offline
                notify_user_offline(user_id)
                
                logger.info(f"User {user_id} disconnected")
                
        except Exception as e:
            logger.error(f"Disconnect error: {str(e)}")
    
    
    @socketio.on('join_chat')
    def handle_join_chat(data):
        """
        Handle user joining a specific chat room.
        
        Args:
            data (dict): Contains chat_id to join
        """
        try:
            if request.sid not in active_connections:
                emit('error', {'message': 'غير مصرح بالوصول'})
                return
            
            user_id = active_connections[request.sid]['user_id']
            chat_id = data.get('chat_id')
            
            if not chat_id:
                emit('error', {'message': 'معرف المحادثة مطلوب'})
                return
            
            # Verify user is participant in this chat
            participant = Participant.query.filter_by(
                chat_id=chat_id,
                user_id=user_id
            ).first()
            
            if not participant:
                emit('error', {'message': 'غير مصرح بالانضمام لهذه المحادثة'})
                return
            
            # Join the chat room
            join_room(f"chat_{chat_id}")
            
            # Update last read timestamp
            participant.last_read_at = datetime.utcnow()
            db.session.commit()
            
            # Get recent messages
            recent_messages = Message.query.filter_by(
                chat_id=chat_id
            ).order_by(Message.created_at.desc()).limit(50).all()
            
            # Emit join success with recent messages
            emit('joined_chat', {
                'success': True,
                'chat_id': chat_id,
                'message': 'تم الانضمام للمحادثة',
                'recent_messages': [msg.to_dict() for msg in reversed(recent_messages)]
            })
            
            # Notify other participants that user joined
            emit('user_joined_chat', {
                'user_id': user_id,
                'chat_id': chat_id,
                'timestamp': datetime.utcnow().isoformat()
            }, room=f"chat_{chat_id}", include_self=False)
            
            logger.info(f"User {user_id} joined chat {chat_id}")
            
        except Exception as e:
            logger.error(f"Join chat error: {str(e)}")
            emit('error', {
                'message': 'خطأ في الانضمام للمحادثة',
                'error': str(e)
            })
    
    
    @socketio.on('leave_chat')
    def handle_leave_chat(data):
        """
        Handle user leaving a specific chat room.
        
        Args:
            data (dict): Contains chat_id to leave
        """
        try:
            if request.sid not in active_connections:
                return
            
            user_id = active_connections[request.sid]['user_id']
            chat_id = data.get('chat_id')
            
            if not chat_id:
                return
            
            # Leave the chat room
            leave_room(f"chat_{chat_id}")
            
            # Emit leave confirmation
            emit('left_chat', {
                'success': True,
                'chat_id': chat_id,
                'message': 'تم مغادرة المحادثة'
            })
            
            # Notify other participants that user left
            emit('user_left_chat', {
                'user_id': user_id,
                'chat_id': chat_id,
                'timestamp': datetime.utcnow().isoformat()
            }, room=f"chat_{chat_id}")
            
            logger.info(f"User {user_id} left chat {chat_id}")
            
        except Exception as e:
            logger.error(f"Leave chat error: {str(e)}")
    
    
    @socketio.on('send_message')
    def handle_send_message(data):
        """
        Handle sending a message to a chat.
        
        Args:
            data (dict): Message data including chat_id, content, message_type
        """
        try:
            if request.sid not in active_connections:
                emit('error', {'message': 'غير مصرح بالوصول'})
                return
            
            user_id = active_connections[request.sid]['user_id']
            chat_id = data.get('chat_id')
            content = data.get('content', '').strip()
            message_type = data.get('message_type', 'text')
            reply_to_id = data.get('reply_to_id')
            
            # Validate input
            if not chat_id or not content:
                emit('error', {'message': 'معرف المحادثة والمحتوى مطلوبان'})
                return
            
            # Verify user is participant in this chat
            participant = Participant.query.filter_by(
                chat_id=chat_id,
                user_id=user_id
            ).first()
            
            if not participant:
                emit('error', {'message': 'غير مصرح بإرسال رسائل في هذه المحادثة'})
                return
            
            # Create new message
            message = Message(
                chat_id=chat_id,
                sender_id=user_id,
                content=content,
                message_type=MessageType(message_type),
                reply_to_id=reply_to_id,
                status=MessageStatus.SENT
            )
            
            db.session.add(message)
            
            # Update chat's last message timestamp
            chat = Chat.query.get(chat_id)
            if chat:
                chat.last_message_at = datetime.utcnow()
                chat.updated_at = datetime.utcnow()
            
            db.session.commit()
            
            # Prepare message data for broadcasting
            message_data = message.to_dict()
            
            # Add sender info (you might want to cache this or get from auth service)
            message_data['sender_info'] = get_user_info(user_id)
            
            # Broadcast message to all participants in the chat
            emit('new_message', {
                'success': True,
                'message': message_data
            }, room=f"chat_{chat_id}")
            
            # Send push notifications to offline users
            send_push_notifications(chat_id, message, user_id)
            
            # Update message status to delivered
            message.status = MessageStatus.DELIVERED
            db.session.commit()
            
            logger.info(f"Message {message.id} sent by user {user_id} in chat {chat_id}")
            
        except Exception as e:
            logger.error(f"Send message error: {str(e)}")
            emit('error', {
                'message': 'خطأ في إرسال الرسالة',
                'error': str(e)
            })
    
    
    @socketio.on('typing')
    def handle_typing(data):
        """
        Handle typing indicator.
        
        Args:
            data (dict): Contains chat_id and typing status
        """
        try:
            if request.sid not in active_connections:
                return
            
            user_id = active_connections[request.sid]['user_id']
            chat_id = data.get('chat_id')
            is_typing = data.get('is_typing', False)
            
            if not chat_id:
                return
            
            # Update typing status
            if is_typing:
                if chat_id not in typing_users:
                    typing_users[chat_id] = set()
                typing_users[chat_id].add(user_id)
            else:
                if chat_id in typing_users:
                    typing_users[chat_id].discard(user_id)
                    if not typing_users[chat_id]:
                        del typing_users[chat_id]
            
            # Broadcast typing status to other participants
            emit('user_typing', {
                'user_id': user_id,
                'chat_id': chat_id,
                'is_typing': is_typing,
                'typing_users': list(typing_users.get(chat_id, []))
            }, room=f"chat_{chat_id}", include_self=False)
            
        except Exception as e:
            logger.error(f"Typing indicator error: {str(e)}")
    
    
    @socketio.on('mark_read')
    def handle_mark_read(data):
        """
        Handle marking messages as read.
        
        Args:
            data (dict): Contains chat_id and optionally message_id
        """
        try:
            if request.sid not in active_connections:
                return
            
            user_id = active_connections[request.sid]['user_id']
            chat_id = data.get('chat_id')
            message_id = data.get('message_id')
            
            if not chat_id:
                return
            
            # Update participant's last read timestamp
            participant = Participant.query.filter_by(
                chat_id=chat_id,
                user_id=user_id
            ).first()
            
            if participant:
                participant.last_read_at = datetime.utcnow()
                db.session.commit()
            
            # If specific message_id provided, mark that message as read
            if message_id:
                message = Message.query.get(message_id)
                if message and message.chat_id == chat_id:
                    message.mark_as_read(user_id)
            
            # Notify sender that message was read
            emit('messages_read', {
                'user_id': user_id,
                'chat_id': chat_id,
                'message_id': message_id,
                'read_at': datetime.utcnow().isoformat()
            }, room=f"chat_{chat_id}", include_self=False)
            
        except Exception as e:
            logger.error(f"Mark read error: {str(e)}")


def update_user_last_seen(user_id):
    """
    Update user's last seen timestamp in all their chats.
    
    Args:
        user_id (int): User ID to update
    """
    try:
        participants = Participant.query.filter_by(user_id=user_id).all()
        for participant in participants:
            participant.last_seen_at = datetime.utcnow()
        db.session.commit()
    except Exception as e:
        logger.error(f"Error updating last seen for user {user_id}: {str(e)}")


def notify_user_online(user_id):
    """
    Notify other users that a user came online.
    
    Args:
        user_id (int): User ID that came online
    """
    try:
        # Get all chats where this user is a participant
        user_chats = db.session.query(Chat.id).join(Participant).filter(
            Participant.user_id == user_id
        ).all()
        
        # Notify all participants in those chats
        for chat in user_chats:
            emit('user_online', {
                'user_id': user_id,
                'timestamp': datetime.utcnow().isoformat()
            }, room=f"chat_{chat.id}")
            
    except Exception as e:
        logger.error(f"Error notifying user online {user_id}: {str(e)}")


def notify_user_offline(user_id):
    """
    Notify other users that a user went offline.
    
    Args:
        user_id (int): User ID that went offline
    """
    try:
        # Get all chats where this user is a participant
        user_chats = db.session.query(Chat.id).join(Participant).filter(
            Participant.user_id == user_id
        ).all()
        
        # Notify all participants in those chats
        for chat in user_chats:
            emit('user_offline', {
                'user_id': user_id,
                'last_seen': datetime.utcnow().isoformat()
            }, room=f"chat_{chat.id}")
            
    except Exception as e:
        logger.error(f"Error notifying user offline {user_id}: {str(e)}")


def send_push_notifications(chat_id, message, sender_id):
    """
    Send push notifications to offline users in a chat.
    
    Args:
        chat_id (str): Chat ID
        message (Message): Message object
        sender_id (int): ID of message sender
    """
    try:
        # Get all participants except sender
        participants = Participant.query.filter(
            Participant.chat_id == chat_id,
            Participant.user_id != sender_id,
            Participant.notification_enabled == True
        ).all()
        
        # Check which users are offline
        offline_users = []
        for participant in participants:
            user_id = participant.user_id
            is_online = any(
                conn['user_id'] == user_id 
                for conn in active_connections.values()
            )
            
            if not is_online and not participant.is_muted:
                offline_users.append(user_id)
        
        # Send notifications to offline users
        if offline_users:
            # Here you would integrate with your notification service
            # For now, we'll just log it
            logger.info(f"Sending push notifications to {len(offline_users)} offline users")
            
    except Exception as e:
        logger.error(f"Error sending push notifications: {str(e)}")


def get_active_users():
    """
    Get list of currently active users.
    
    Returns:
        list: List of active user IDs
    """
    return [conn['user_id'] for conn in active_connections.values()]


def get_chat_active_users(chat_id):
    """
    Get list of active users in a specific chat.
    
    Args:
        chat_id (str): Chat ID
        
    Returns:
        list: List of active user IDs in the chat
    """
    try:
        # Get participants of the chat
        participants = Participant.query.filter_by(chat_id=chat_id).all()
        participant_ids = [p.user_id for p in participants]
        
        # Filter active connections for this chat's participants
        active_in_chat = [
            conn['user_id'] for conn in active_connections.values()
            if conn['user_id'] in participant_ids
        ]
        
        return active_in_chat
        
    except Exception as e:
        logger.error(f"Error getting active users for chat {chat_id}: {str(e)}")
        return []

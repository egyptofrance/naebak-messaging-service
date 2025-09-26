#!/usr/bin/env python3
"""
Naebak Messaging Service - Main Application
==========================================

Real-time messaging service with WebSocket support for the Naebak platform.
Handles chat messages, file sharing, and real-time communication between users.

Features:
- WebSocket real-time messaging
- File and media sharing
- Group conversations
- Message encryption
- Delivery status tracking
- Message history and search
- Typing indicators
- Online presence
"""

from flask import Flask, request, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
import redis
import json
import uuid
import datetime
from werkzeug.utils import secure_filename
import os
from config import Config
from models.message import Message, Chat, Participant
from models.user import User
from utils.encryption import encrypt_message, decrypt_message
from utils.file_handler import handle_file_upload, get_file_url
from utils.notifications import send_message_notification
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
CORS(app)
jwt = JWTManager(app)
redis_client = redis.Redis(host=app.config['REDIS_HOST'], port=app.config['REDIS_PORT'], db=0)

# File upload configuration
UPLOAD_FOLDER = 'uploads/messages'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mp3', 'doc', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# WebSocket Events
@socketio.on('connect')
@jwt_required()
def handle_connect():
    """Handle client connection"""
    try:
        user_id = get_jwt_identity()
        user = User.get_by_id(user_id)
        
        if user:
            # Update user online status
            redis_client.hset(f"user:{user_id}", "online", "true")
            redis_client.hset(f"user:{user_id}", "last_seen", datetime.datetime.utcnow().isoformat())
            
            # Join user to their personal room
            join_room(f"user_{user_id}")
            
            # Notify contacts about online status
            emit('user_online', {'user_id': user_id, 'username': user.username}, broadcast=True)
            
            logger.info(f"User {user_id} connected to messaging service")
            emit('connection_success', {'message': 'Connected successfully'})
        else:
            emit('connection_error', {'message': 'Invalid user'})
            
    except Exception as e:
        logger.error(f"Connection error: {str(e)}")
        emit('connection_error', {'message': 'Connection failed'})

@socketio.on('disconnect')
@jwt_required()
def handle_disconnect():
    """Handle client disconnection"""
    try:
        user_id = get_jwt_identity()
        
        # Update user offline status
        redis_client.hset(f"user:{user_id}", "online", "false")
        redis_client.hset(f"user:{user_id}", "last_seen", datetime.datetime.utcnow().isoformat())
        
        # Leave all rooms
        for room in rooms():
            leave_room(room)
        
        # Notify contacts about offline status
        emit('user_offline', {'user_id': user_id}, broadcast=True)
        
        logger.info(f"User {user_id} disconnected from messaging service")
        
    except Exception as e:
        logger.error(f"Disconnection error: {str(e)}")

@socketio.on('join_chat')
@jwt_required()
def handle_join_chat(data):
    """Join a chat room"""
    try:
        user_id = get_jwt_identity()
        chat_id = data.get('chat_id')
        
        # Verify user is participant in chat
        participant = Participant.get_by_chat_and_user(chat_id, user_id)
        if not participant:
            emit('error', {'message': 'Not authorized to join this chat'})
            return
        
        # Join the chat room
        join_room(f"chat_{chat_id}")
        
        # Update last seen for this chat
        participant.update_last_seen()
        
        # Notify other participants
        emit('user_joined_chat', {
            'user_id': user_id,
            'chat_id': chat_id,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }, room=f"chat_{chat_id}", include_self=False)
        
        emit('joined_chat', {'chat_id': chat_id})
        logger.info(f"User {user_id} joined chat {chat_id}")
        
    except Exception as e:
        logger.error(f"Join chat error: {str(e)}")
        emit('error', {'message': 'Failed to join chat'})

@socketio.on('leave_chat')
@jwt_required()
def handle_leave_chat(data):
    """Leave a chat room"""
    try:
        user_id = get_jwt_identity()
        chat_id = data.get('chat_id')
        
        # Leave the chat room
        leave_room(f"chat_{chat_id}")
        
        # Notify other participants
        emit('user_left_chat', {
            'user_id': user_id,
            'chat_id': chat_id,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }, room=f"chat_{chat_id}")
        
        emit('left_chat', {'chat_id': chat_id})
        logger.info(f"User {user_id} left chat {chat_id}")
        
    except Exception as e:
        logger.error(f"Leave chat error: {str(e)}")
        emit('error', {'message': 'Failed to leave chat'})

@socketio.on('send_message')
@jwt_required()
def handle_send_message(data):
    """Send a message to a chat"""
    try:
        user_id = get_jwt_identity()
        chat_id = data.get('chat_id')
        content = data.get('content', '').strip()
        message_type = data.get('type', 'text')
        reply_to = data.get('reply_to')
        
        if not content and message_type == 'text':
            emit('error', {'message': 'Message content cannot be empty'})
            return
        
        # Verify user is participant in chat
        participant = Participant.get_by_chat_and_user(chat_id, user_id)
        if not participant:
            emit('error', {'message': 'Not authorized to send messages to this chat'})
            return
        
        # Encrypt message content
        encrypted_content = encrypt_message(content)
        
        # Create message
        message = Message.create({
            'chat_id': chat_id,
            'sender_id': user_id,
            'content': encrypted_content,
            'message_type': message_type,
            'reply_to': reply_to,
            'timestamp': datetime.datetime.utcnow()
        })
        
        # Prepare message data for broadcast
        message_data = {
            'id': message.id,
            'chat_id': chat_id,
            'sender_id': user_id,
            'sender_username': User.get_by_id(user_id).username,
            'content': content,  # Send decrypted content to clients
            'message_type': message_type,
            'reply_to': reply_to,
            'timestamp': message.timestamp.isoformat(),
            'status': 'sent'
        }
        
        # Broadcast message to chat room
        emit('new_message', message_data, room=f"chat_{chat_id}")
        
        # Update chat last message
        chat = Chat.get_by_id(chat_id)
        chat.update_last_message(message.id)
        
        # Send push notifications to offline participants
        offline_participants = Participant.get_offline_by_chat(chat_id, exclude_user=user_id)
        for participant in offline_participants:
            send_message_notification(participant.user_id, message_data)
        
        # Store message in Redis for quick access
        redis_client.lpush(f"chat:{chat_id}:messages", json.dumps(message_data))
        redis_client.ltrim(f"chat:{chat_id}:messages", 0, 99)  # Keep last 100 messages
        
        logger.info(f"Message sent from user {user_id} to chat {chat_id}")
        
    except Exception as e:
        logger.error(f"Send message error: {str(e)}")
        emit('error', {'message': 'Failed to send message'})

@socketio.on('typing_start')
@jwt_required()
def handle_typing_start(data):
    """Handle typing indicator start"""
    try:
        user_id = get_jwt_identity()
        chat_id = data.get('chat_id')
        
        # Verify user is participant in chat
        participant = Participant.get_by_chat_and_user(chat_id, user_id)
        if not participant:
            return
        
        # Broadcast typing indicator
        emit('user_typing', {
            'user_id': user_id,
            'chat_id': chat_id,
            'typing': True
        }, room=f"chat_{chat_id}", include_self=False)
        
        # Set typing status in Redis with expiration
        redis_client.setex(f"typing:{chat_id}:{user_id}", 10, "true")
        
    except Exception as e:
        logger.error(f"Typing start error: {str(e)}")

@socketio.on('typing_stop')
@jwt_required()
def handle_typing_stop(data):
    """Handle typing indicator stop"""
    try:
        user_id = get_jwt_identity()
        chat_id = data.get('chat_id')
        
        # Verify user is participant in chat
        participant = Participant.get_by_chat_and_user(chat_id, user_id)
        if not participant:
            return
        
        # Broadcast typing stop
        emit('user_typing', {
            'user_id': user_id,
            'chat_id': chat_id,
            'typing': False
        }, room=f"chat_{chat_id}", include_self=False)
        
        # Remove typing status from Redis
        redis_client.delete(f"typing:{chat_id}:{user_id}")
        
    except Exception as e:
        logger.error(f"Typing stop error: {str(e)}")

@socketio.on('mark_read')
@jwt_required()
def handle_mark_read(data):
    """Mark messages as read"""
    try:
        user_id = get_jwt_identity()
        chat_id = data.get('chat_id')
        message_id = data.get('message_id')
        
        # Verify user is participant in chat
        participant = Participant.get_by_chat_and_user(chat_id, user_id)
        if not participant:
            return
        
        # Update last read message
        participant.update_last_read(message_id)
        
        # Notify sender about read status
        message = Message.get_by_id(message_id)
        if message and message.sender_id != user_id:
            emit('message_read', {
                'message_id': message_id,
                'chat_id': chat_id,
                'reader_id': user_id,
                'timestamp': datetime.datetime.utcnow().isoformat()
            }, room=f"user_{message.sender_id}")
        
    except Exception as e:
        logger.error(f"Mark read error: {str(e)}")

# REST API Endpoints
@app.route('/api/chats', methods=['GET'])
@jwt_required()
def get_user_chats():
    """Get all chats for the current user"""
    try:
        user_id = get_jwt_identity()
        chats = Chat.get_by_user(user_id)
        
        chat_list = []
        for chat in chats:
            chat_data = {
                'id': chat.id,
                'name': chat.name,
                'type': chat.chat_type,
                'created_at': chat.created_at.isoformat(),
                'last_message': None,
                'unread_count': chat.get_unread_count(user_id),
                'participants': [p.to_dict() for p in chat.participants]
            }
            
            if chat.last_message_id:
                last_message = Message.get_by_id(chat.last_message_id)
                if last_message:
                    chat_data['last_message'] = {
                        'content': decrypt_message(last_message.content),
                        'sender_username': User.get_by_id(last_message.sender_id).username,
                        'timestamp': last_message.timestamp.isoformat()
                    }
            
            chat_list.append(chat_data)
        
        return jsonify({'chats': chat_list}), 200
        
    except Exception as e:
        logger.error(f"Get chats error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve chats'}), 500

@app.route('/api/chats', methods=['POST'])
@jwt_required()
def create_chat():
    """Create a new chat"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        chat_name = data.get('name', '').strip()
        chat_type = data.get('type', 'private')
        participant_ids = data.get('participants', [])
        
        if not chat_name:
            return jsonify({'error': 'Chat name is required'}), 400
        
        # Add creator to participants
        if user_id not in participant_ids:
            participant_ids.append(user_id)
        
        # Create chat
        chat = Chat.create({
            'name': chat_name,
            'chat_type': chat_type,
            'created_by': user_id,
            'created_at': datetime.datetime.utcnow()
        })
        
        # Add participants
        for participant_id in participant_ids:
            Participant.create({
                'chat_id': chat.id,
                'user_id': participant_id,
                'joined_at': datetime.datetime.utcnow(),
                'role': 'admin' if participant_id == user_id else 'member'
            })
        
        return jsonify({
            'message': 'Chat created successfully',
            'chat': {
                'id': chat.id,
                'name': chat.name,
                'type': chat.chat_type
            }
        }), 201
        
    except Exception as e:
        logger.error(f"Create chat error: {str(e)}")
        return jsonify({'error': 'Failed to create chat'}), 500

@app.route('/api/chats/<int:chat_id>/messages', methods=['GET'])
@jwt_required()
def get_chat_messages(chat_id):
    """Get messages for a specific chat"""
    try:
        user_id = get_jwt_identity()
        
        # Verify user is participant in chat
        participant = Participant.get_by_chat_and_user(chat_id, user_id)
        if not participant:
            return jsonify({'error': 'Not authorized to view this chat'}), 403
        
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        
        # Get messages from database
        messages = Message.get_by_chat(chat_id, page=page, per_page=per_page)
        
        message_list = []
        for message in messages:
            message_data = {
                'id': message.id,
                'sender_id': message.sender_id,
                'sender_username': User.get_by_id(message.sender_id).username,
                'content': decrypt_message(message.content),
                'message_type': message.message_type,
                'reply_to': message.reply_to,
                'timestamp': message.timestamp.isoformat(),
                'edited': message.edited,
                'edited_at': message.edited_at.isoformat() if message.edited_at else None
            }
            message_list.append(message_data)
        
        return jsonify({'messages': message_list}), 200
        
    except Exception as e:
        logger.error(f"Get messages error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve messages'}), 500

@app.route('/api/messages/<int:message_id>', methods=['PUT'])
@jwt_required()
def edit_message(message_id):
    """Edit a message"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        new_content = data.get('content', '').strip()
        
        if not new_content:
            return jsonify({'error': 'Message content cannot be empty'}), 400
        
        # Get message
        message = Message.get_by_id(message_id)
        if not message:
            return jsonify({'error': 'Message not found'}), 404
        
        # Verify user is the sender
        if message.sender_id != user_id:
            return jsonify({'error': 'Not authorized to edit this message'}), 403
        
        # Check if message is too old to edit (24 hours)
        if (datetime.datetime.utcnow() - message.timestamp).total_seconds() > 86400:
            return jsonify({'error': 'Message is too old to edit'}), 400
        
        # Update message
        encrypted_content = encrypt_message(new_content)
        message.update({
            'content': encrypted_content,
            'edited': True,
            'edited_at': datetime.datetime.utcnow()
        })
        
        # Broadcast edit to chat room
        emit('message_edited', {
            'message_id': message_id,
            'chat_id': message.chat_id,
            'new_content': new_content,
            'edited_at': message.edited_at.isoformat()
        }, room=f"chat_{message.chat_id}", namespace='/')
        
        return jsonify({'message': 'Message updated successfully'}), 200
        
    except Exception as e:
        logger.error(f"Edit message error: {str(e)}")
        return jsonify({'error': 'Failed to edit message'}), 500

@app.route('/api/messages/<int:message_id>', methods=['DELETE'])
@jwt_required()
def delete_message(message_id):
    """Delete a message"""
    try:
        user_id = get_jwt_identity()
        
        # Get message
        message = Message.get_by_id(message_id)
        if not message:
            return jsonify({'error': 'Message not found'}), 404
        
        # Verify user is the sender or chat admin
        participant = Participant.get_by_chat_and_user(message.chat_id, user_id)
        if message.sender_id != user_id and participant.role != 'admin':
            return jsonify({'error': 'Not authorized to delete this message'}), 403
        
        # Soft delete message
        message.update({
            'deleted': True,
            'deleted_at': datetime.datetime.utcnow(),
            'deleted_by': user_id
        })
        
        # Broadcast deletion to chat room
        emit('message_deleted', {
            'message_id': message_id,
            'chat_id': message.chat_id,
            'deleted_by': user_id,
            'deleted_at': message.deleted_at.isoformat()
        }, room=f"chat_{message.chat_id}", namespace='/')
        
        return jsonify({'message': 'Message deleted successfully'}), 200
        
    except Exception as e:
        logger.error(f"Delete message error: {str(e)}")
        return jsonify({'error': 'Failed to delete message'}), 500

@app.route('/api/upload', methods=['POST'])
@jwt_required()
def upload_file():
    """Upload a file for messaging"""
    try:
        user_id = get_jwt_identity()
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to avoid conflicts
            timestamp = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S_')
            filename = timestamp + filename
            
            # Create upload directory if it doesn't exist
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Get file URL
            file_url = get_file_url(filename)
            
            return jsonify({
                'message': 'File uploaded successfully',
                'filename': filename,
                'url': file_url,
                'size': os.path.getsize(file_path)
            }), 200
        
        return jsonify({'error': 'File type not allowed'}), 400
        
    except Exception as e:
        logger.error(f"File upload error: {str(e)}")
        return jsonify({'error': 'Failed to upload file'}), 500

@app.route('/api/search', methods=['GET'])
@jwt_required()
def search_messages():
    """Search messages across user's chats"""
    try:
        user_id = get_jwt_identity()
        query = request.args.get('q', '').strip()
        chat_id = request.args.get('chat_id', type=int)
        
        if not query:
            return jsonify({'error': 'Search query is required'}), 400
        
        # Search messages
        messages = Message.search(user_id, query, chat_id)
        
        results = []
        for message in messages:
            results.append({
                'id': message.id,
                'chat_id': message.chat_id,
                'chat_name': Chat.get_by_id(message.chat_id).name,
                'sender_username': User.get_by_id(message.sender_id).username,
                'content': decrypt_message(message.content),
                'timestamp': message.timestamp.isoformat()
            })
        
        return jsonify({'results': results}), 200
        
    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        return jsonify({'error': 'Search failed'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Check Redis connection
        redis_client.ping()
        
        return jsonify({
            'status': 'healthy',
            'service': 'messaging',
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'version': '1.0.0'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token'}), 401

if __name__ == '__main__':
    # Create upload directory
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    # Run the application
    socketio.run(
        app,
        host=app.config.get('HOST', '0.0.0.0'),
        port=app.config.get('PORT', 5003),
        debug=app.config.get('DEBUG', False)
    )

#!/usr/bin/env python3
"""
خدمة الرسائل المبسطة - نائبك
============================

خدمة رسائل بسيطة بين المواطنين والنواب بدون تعقيدات.
- لا توجد مشاركة ملفات
- لا توجد مؤشرات قراءة
- لا يوجد تشفير معقد
- لا يوجد بحث في الرسائل
- لا يوجد WebSocket

الميزات المتاحة:
- إرسال رسائل نصية بسيطة
- عرض المحادثات
- حذف الرسائل
- API بسيط وواضح
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
import sqlite3
import json
import uuid
import datetime
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['CORS_HEADERS'] = 'Content-Type'

# Initialize extensions
CORS(app)
jwt = JWTManager(app)

# Database file
DATABASE = 'simple_messages.db'

def init_database():
    """Initialize SQLite database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Create conversations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            citizen_id TEXT NOT NULL,
            deputy_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(citizen_id, deputy_id)
        )
    ''')
    
    # Create messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL,
            sender_id TEXT NOT NULL,
            sender_type TEXT NOT NULL CHECK(sender_type IN ('citizen', 'deputy')),
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            deleted BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (conversation_id) REFERENCES conversations (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully")

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def get_or_create_conversation(citizen_id, deputy_id):
    """Get existing conversation or create new one"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Try to find existing conversation
    cursor.execute('''
        SELECT id FROM conversations 
        WHERE citizen_id = ? AND deputy_id = ?
    ''', (citizen_id, deputy_id))
    
    conversation = cursor.fetchone()
    
    if conversation:
        conversation_id = conversation['id']
    else:
        # Create new conversation
        cursor.execute('''
            INSERT INTO conversations (citizen_id, deputy_id)
            VALUES (?, ?)
        ''', (citizen_id, deputy_id))
        conversation_id = cursor.lastrowid
        conn.commit()
    
    conn.close()
    return conversation_id

# API Routes

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'simple-messaging',
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'version': '2.0.0',
        'features': {
            'file_upload': False,
            'read_receipts': False,
            'encryption': False,
            'search': False,
            'websocket': False,
            'simple_text_messaging': True
        }
    }), 200

@app.route('/api/conversations', methods=['GET'])
@jwt_required()
def get_conversations():
    """Get all conversations for current user"""
    try:
        user_id = get_jwt_identity()
        user_type = request.args.get('user_type', 'citizen')  # citizen or deputy
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if user_type == 'citizen':
            cursor.execute('''
                SELECT c.*, 
                       (SELECT content FROM messages m 
                        WHERE m.conversation_id = c.id 
                        AND m.deleted = FALSE
                        ORDER BY m.created_at DESC LIMIT 1) as last_message,
                       (SELECT created_at FROM messages m 
                        WHERE m.conversation_id = c.id 
                        AND m.deleted = FALSE
                        ORDER BY m.created_at DESC LIMIT 1) as last_message_time,
                       (SELECT COUNT(*) FROM messages m 
                        WHERE m.conversation_id = c.id 
                        AND m.deleted = FALSE) as message_count
                FROM conversations c 
                WHERE c.citizen_id = ?
                ORDER BY c.updated_at DESC
            ''', (user_id,))
        else:
            cursor.execute('''
                SELECT c.*, 
                       (SELECT content FROM messages m 
                        WHERE m.conversation_id = c.id 
                        AND m.deleted = FALSE
                        ORDER BY m.created_at DESC LIMIT 1) as last_message,
                       (SELECT created_at FROM messages m 
                        WHERE m.conversation_id = c.id 
                        AND m.deleted = FALSE
                        ORDER BY m.created_at DESC LIMIT 1) as last_message_time,
                       (SELECT COUNT(*) FROM messages m 
                        WHERE m.conversation_id = c.id 
                        AND m.deleted = FALSE) as message_count
                FROM conversations c 
                WHERE c.deputy_id = ?
                ORDER BY c.updated_at DESC
            ''', (user_id,))
        
        conversations = cursor.fetchall()
        conn.close()
        
        conversation_list = []
        for conv in conversations:
            conversation_list.append({
                'id': conv['id'],
                'citizen_id': conv['citizen_id'],
                'deputy_id': conv['deputy_id'],
                'last_message': conv['last_message'],
                'last_message_time': conv['last_message_time'],
                'message_count': conv['message_count'],
                'created_at': conv['created_at'],
                'updated_at': conv['updated_at']
            })
        
        return jsonify({
            'conversations': conversation_list,
            'count': len(conversation_list)
        }), 200
        
    except Exception as e:
        logger.error(f"Get conversations error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve conversations'}), 500

@app.route('/api/conversations/<int:conversation_id>/messages', methods=['GET'])
@jwt_required()
def get_messages(conversation_id):
    """Get messages for a specific conversation"""
    try:
        user_id = get_jwt_identity()
        
        # Verify user has access to this conversation
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM conversations 
            WHERE id = ? AND (citizen_id = ? OR deputy_id = ?)
        ''', (conversation_id, user_id, user_id))
        
        conversation = cursor.fetchone()
        if not conversation:
            return jsonify({'error': 'Conversation not found or access denied'}), 404
        
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        offset = (page - 1) * per_page
        
        # Get messages
        cursor.execute('''
            SELECT * FROM messages 
            WHERE conversation_id = ? AND deleted = FALSE
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        ''', (conversation_id, per_page, offset))
        
        messages = cursor.fetchall()
        conn.close()
        
        message_list = []
        for msg in messages:
            message_list.append({
                'id': msg['id'],
                'sender_id': msg['sender_id'],
                'sender_type': msg['sender_type'],
                'content': msg['content'],
                'created_at': msg['created_at']
            })
        
        # Reverse to show oldest first
        message_list.reverse()
        
        return jsonify({
            'messages': message_list,
            'conversation_id': conversation_id,
            'page': page,
            'per_page': per_page,
            'total_messages': len(message_list)
        }), 200
        
    except Exception as e:
        logger.error(f"Get messages error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve messages'}), 500

@app.route('/api/messages', methods=['POST'])
@jwt_required()
def send_message():
    """Send a new message"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        content = data.get('content', '').strip()
        recipient_id = data.get('recipient_id')
        sender_type = data.get('sender_type', 'citizen')  # citizen or deputy
        
        if not content:
            return jsonify({'error': 'Message content is required'}), 400
        
        if not recipient_id:
            return jsonify({'error': 'Recipient ID is required'}), 400
        
        if len(content) > 1000:
            return jsonify({'error': 'Message too long (max 1000 characters)'}), 400
        
        # Validate sender_type
        if sender_type not in ['citizen', 'deputy']:
            return jsonify({'error': 'Invalid sender type'}), 400
        
        # Determine conversation participants
        if sender_type == 'citizen':
            citizen_id = user_id
            deputy_id = recipient_id
        else:
            citizen_id = recipient_id
            deputy_id = user_id
        
        # Get or create conversation
        conversation_id = get_or_create_conversation(citizen_id, deputy_id)
        
        # Insert message
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO messages (conversation_id, sender_id, sender_type, content)
            VALUES (?, ?, ?, ?)
        ''', (conversation_id, user_id, sender_type, content))
        
        message_id = cursor.lastrowid
        
        # Update conversation timestamp
        cursor.execute('''
            UPDATE conversations 
            SET updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (conversation_id,))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Message sent: {user_id} ({sender_type}) -> {recipient_id}")
        
        return jsonify({
            'message': 'Message sent successfully',
            'message_id': message_id,
            'conversation_id': conversation_id,
            'content': content,
            'sender_type': sender_type
        }), 201
        
    except Exception as e:
        logger.error(f"Send message error: {str(e)}")
        return jsonify({'error': 'Failed to send message'}), 500

@app.route('/api/messages/<int:message_id>', methods=['DELETE'])
@jwt_required()
def delete_message(message_id):
    """Delete a message (soft delete)"""
    try:
        user_id = get_jwt_identity()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify user owns this message
        cursor.execute('''
            SELECT * FROM messages 
            WHERE id = ? AND sender_id = ? AND deleted = FALSE
        ''', (message_id, user_id))
        
        message = cursor.fetchone()
        if not message:
            return jsonify({'error': 'Message not found or access denied'}), 404
        
        # Soft delete
        cursor.execute('''
            UPDATE messages 
            SET deleted = TRUE 
            WHERE id = ?
        ''', (message_id,))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Message deleted: {message_id} by {user_id}")
        
        return jsonify({'message': 'Message deleted successfully'}), 200
        
    except Exception as e:
        logger.error(f"Delete message error: {str(e)}")
        return jsonify({'error': 'Failed to delete message'}), 500

@app.route('/api/stats', methods=['GET'])
@jwt_required()
def get_stats():
    """Get messaging statistics"""
    try:
        user_id = get_jwt_identity()
        user_type = request.args.get('user_type', 'citizen')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if user_type == 'citizen':
            # Stats for citizen
            cursor.execute('''
                SELECT COUNT(*) as total_conversations
                FROM conversations 
                WHERE citizen_id = ?
            ''', (user_id,))
            total_conversations = cursor.fetchone()['total_conversations']
            
            cursor.execute('''
                SELECT COUNT(*) as total_messages
                FROM messages m
                JOIN conversations c ON m.conversation_id = c.id
                WHERE c.citizen_id = ? AND m.deleted = FALSE
            ''', (user_id,))
            total_messages = cursor.fetchone()['total_messages']
            
            cursor.execute('''
                SELECT COUNT(*) as sent_messages
                FROM messages m
                JOIN conversations c ON m.conversation_id = c.id
                WHERE c.citizen_id = ? AND m.sender_id = ? AND m.deleted = FALSE
            ''', (user_id, user_id))
            sent_messages = cursor.fetchone()['sent_messages']
            
        else:
            # Stats for deputy
            cursor.execute('''
                SELECT COUNT(*) as total_conversations
                FROM conversations 
                WHERE deputy_id = ?
            ''', (user_id,))
            total_conversations = cursor.fetchone()['total_conversations']
            
            cursor.execute('''
                SELECT COUNT(*) as total_messages
                FROM messages m
                JOIN conversations c ON m.conversation_id = c.id
                WHERE c.deputy_id = ? AND m.deleted = FALSE
            ''', (user_id,))
            total_messages = cursor.fetchone()['total_messages']
            
            cursor.execute('''
                SELECT COUNT(*) as sent_messages
                FROM messages m
                JOIN conversations c ON m.conversation_id = c.id
                WHERE c.deputy_id = ? AND m.sender_id = ? AND m.deleted = FALSE
            ''', (user_id, user_id))
            sent_messages = cursor.fetchone()['sent_messages']
        
        conn.close()
        
        return jsonify({
            'total_conversations': total_conversations,
            'total_messages': total_messages,
            'sent_messages': sent_messages,
            'received_messages': total_messages - sent_messages,
            'user_type': user_type
        }), 200
        
    except Exception as e:
        logger.error(f"Get stats error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve statistics'}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request'}), 400

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    logger.info("=" * 50)
    logger.info("🚀 Starting Simple Messaging Service v2.0")
    logger.info("=" * 50)
    logger.info("✅ Features: Basic text messaging only")
    logger.info("✅ Database: SQLite (simple_messages.db)")
    logger.info("❌ No file uploads, encryption, or WebSocket")
    logger.info("❌ No read receipts or typing indicators")
    logger.info("❌ No message search functionality")
    logger.info("=" * 50)
    
    app.run(host='0.0.0.0', port=8002, debug=True)

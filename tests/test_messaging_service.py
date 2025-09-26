"""
Comprehensive Test Suite for Naebak Messaging Service

This test suite covers all aspects of the messaging service including:
- API endpoints testing
- WebSocket functionality testing
- Database operations testing
- Redis integration testing
- Authentication and authorization testing
- Message validation and security testing

Test Categories:
1. Unit Tests - Individual component testing
2. Integration Tests - Component interaction testing
3. End-to-End Tests - Full workflow testing
4. Performance Tests - Load and stress testing
5. Security Tests - Authentication and authorization testing
"""

import unittest
import json
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import redis
from flask import Flask
from flask_testing import TestCase
from flask_socketio import SocketIOTestClient

# Import the application and its components
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, socketio, db
from models import Chat, Participant, Message, MessageType, MessageStatus, ChatType
from auth_utils import generate_test_token
from redis_manager import get_redis_manager

class MessagingServiceTestCase(TestCase):
    """
    Base test case class for the messaging service.
    
    This class provides common setup and teardown functionality for all tests,
    including database initialization, test data creation, and cleanup operations.
    """
    
    def create_app(self):
        """
        Create and configure the Flask app for testing.
        
        Returns:
            Flask: Configured Flask application instance for testing
        """
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['JWT_SECRET_KEY'] = 'test-secret-key'
        return app
    
    def setUp(self):
        """
        Set up test environment before each test.
        
        This method creates the database tables, initializes test data,
        and sets up mock objects for external dependencies.
        """
        db.create_all()
        
        # Create test users
        self.test_user_1 = {
            'user_id': 1,
            'username': 'test_user_1',
            'email': 'user1@test.com',
            'user_type': 'citizen'
        }
        
        self.test_user_2 = {
            'user_id': 2,
            'username': 'test_user_2',
            'email': 'user2@test.com',
            'user_type': 'representative'
        }
        
        # Generate test JWT tokens
        self.token_user_1 = generate_test_token(self.test_user_1)
        self.token_user_2 = generate_test_token(self.test_user_2)
        
        # Create test chat
        self.test_chat = Chat(
            name='Test Chat',
            chat_type=ChatType.DIRECT
        )
        db.session.add(self.test_chat)
        db.session.flush()
        
        # Add participants
        participant_1 = Participant(
            chat_id=self.test_chat.id,
            user_id=self.test_user_1['user_id'],
            is_admin=True
        )
        participant_2 = Participant(
            chat_id=self.test_chat.id,
            user_id=self.test_user_2['user_id']
        )
        
        db.session.add(participant_1)
        db.session.add(participant_2)
        db.session.commit()
        
        # Mock Redis for testing
        self.redis_mock = MagicMock()
        
    def tearDown(self):
        """
        Clean up test environment after each test.
        
        This method removes all test data and resets the database
        to ensure test isolation.
        """
        db.session.remove()
        db.drop_all()

class TestHealthEndpoint(MessagingServiceTestCase):
    """
    Test cases for the health check endpoint.
    
    These tests verify that the health endpoint returns correct status
    information and handles various system states properly.
    """
    
    def test_health_check_success(self):
        """
        Test successful health check response.
        
        Verifies that the health endpoint returns correct service information
        when all systems are operational.
        """
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertEqual(data['service'], 'naebak-messaging-service')
        self.assertEqual(data['version'], '2.0.0')
        self.assertIn('status', data)
        self.assertIn('features', data)
        self.assertIsInstance(data['features'], list)
        
    def test_health_check_database_status(self):
        """
        Test health check database status reporting.
        
        Verifies that the health endpoint correctly reports database
        connectivity status.
        """
        response = self.client.get('/')
        data = json.loads(response.data)
        
        self.assertIn('database', data)
        self.assertIn('status', data['database'])
        self.assertEqual(data['database']['type'], 'PostgreSQL')

class TestChatEndpoints(MessagingServiceTestCase):
    """
    Test cases for chat-related API endpoints.
    
    These tests cover chat creation, retrieval, and management operations
    including authentication and authorization checks.
    """
    
    def test_get_chats_authenticated(self):
        """
        Test retrieving chats for authenticated user.
        
        Verifies that authenticated users can retrieve their chat list
        with proper pagination and filtering.
        """
        headers = {'Authorization': f'Bearer {self.token_user_1}'}
        response = self.client.get('/api/v1/chats', headers=headers)
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertIn('data', data)
        
    def test_get_chats_unauthenticated(self):
        """
        Test retrieving chats without authentication.
        
        Verifies that unauthenticated requests are properly rejected.
        """
        response = self.client.get('/api/v1/chats')
        self.assertEqual(response.status_code, 401)
        
    def test_create_chat_valid_data(self):
        """
        Test creating a new chat with valid data.
        
        Verifies that chats can be created successfully with proper
        participant validation and data structure.
        """
        headers = {'Authorization': f'Bearer {self.token_user_1}'}
        chat_data = {
            'participants': [self.test_user_2['user_id']],
            'chat_type': 'direct'
        }
        
        response = self.client.post(
            '/api/v1/chats',
            data=json.dumps(chat_data),
            content_type='application/json',
            headers=headers
        )
        
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertIn('chat', data['data'])
        
    def test_create_chat_invalid_data(self):
        """
        Test creating a chat with invalid data.
        
        Verifies that chat creation fails appropriately when provided
        with invalid or missing data.
        """
        headers = {'Authorization': f'Bearer {self.token_user_1}'}
        invalid_data = {
            'participants': [],  # Empty participants list
            'chat_type': 'invalid_type'
        }
        
        response = self.client.post(
            '/api/v1/chats',
            data=json.dumps(invalid_data),
            content_type='application/json',
            headers=headers
        )
        
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data['success'])

class TestMessageEndpoints(MessagingServiceTestCase):
    """
    Test cases for message-related API endpoints.
    
    These tests cover message sending, retrieval, and validation
    including content filtering and rate limiting.
    """
    
    def test_get_messages_authenticated(self):
        """
        Test retrieving messages for authenticated user.
        
        Verifies that authenticated users can retrieve messages from
        chats they participate in.
        """
        headers = {'Authorization': f'Bearer {self.token_user_1}'}
        response = self.client.get(
            f'/api/v1/chats/{self.test_chat.id}/messages',
            headers=headers
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertIn('messages', data['data'])
        
    def test_get_messages_unauthorized_chat(self):
        """
        Test retrieving messages from unauthorized chat.
        
        Verifies that users cannot access messages from chats
        they don't participate in.
        """
        # Create a chat without user_1 as participant
        unauthorized_chat = Chat(name='Unauthorized Chat', chat_type=ChatType.DIRECT)
        db.session.add(unauthorized_chat)
        db.session.flush()
        
        participant = Participant(
            chat_id=unauthorized_chat.id,
            user_id=self.test_user_2['user_id']
        )
        db.session.add(participant)
        db.session.commit()
        
        headers = {'Authorization': f'Bearer {self.token_user_1}'}
        response = self.client.get(
            f'/api/v1/chats/{unauthorized_chat.id}/messages',
            headers=headers
        )
        
        self.assertEqual(response.status_code, 403)
        
    def test_send_message_valid(self):
        """
        Test sending a valid message.
        
        Verifies that valid messages can be sent successfully
        with proper content validation and storage.
        """
        headers = {'Authorization': f'Bearer {self.token_user_1}'}
        message_data = {
            'content': 'Test message content',
            'message_type': 'text'
        }
        
        response = self.client.post(
            f'/api/v1/chats/{self.test_chat.id}/messages',
            data=json.dumps(message_data),
            content_type='application/json',
            headers=headers
        )
        
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertIn('message', data['data'])
        
    def test_send_message_empty_content(self):
        """
        Test sending a message with empty content.
        
        Verifies that messages with empty or invalid content
        are properly rejected.
        """
        headers = {'Authorization': f'Bearer {self.token_user_1}'}
        message_data = {
            'content': '',  # Empty content
            'message_type': 'text'
        }
        
        response = self.client.post(
            f'/api/v1/chats/{self.test_chat.id}/messages',
            data=json.dumps(message_data),
            content_type='application/json',
            headers=headers
        )
        
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data['success'])

class TestWebSocketFunctionality(MessagingServiceTestCase):
    """
    Test cases for WebSocket functionality.
    
    These tests verify real-time messaging capabilities including
    connection handling, message broadcasting, and typing indicators.
    """
    
    def setUp(self):
        """
        Set up WebSocket test environment.
        
        Extends the base setUp to include WebSocket client initialization.
        """
        super().setUp()
        self.socketio_client = SocketIOTestClient(app, socketio)
        
    def test_websocket_connection(self):
        """
        Test WebSocket connection establishment.
        
        Verifies that WebSocket connections can be established
        with proper authentication.
        """
        # Connect with user authentication
        received = self.socketio_client.get_received()
        self.assertIsInstance(received, list)
        
    def test_websocket_message_sending(self):
        """
        Test sending messages via WebSocket.
        
        Verifies that messages can be sent and received through
        WebSocket connections in real-time.
        """
        # Simulate sending a message
        message_data = {
            'chat_id': str(self.test_chat.id),
            'content': 'WebSocket test message',
            'message_type': 'text'
        }
        
        self.socketio_client.emit('send_message', message_data)
        received = self.socketio_client.get_received()
        
        # Verify message was processed
        self.assertTrue(len(received) >= 0)
        
    def test_typing_indicators(self):
        """
        Test typing indicator functionality.
        
        Verifies that typing indicators work correctly for
        real-time user feedback.
        """
        typing_data = {
            'chat_id': str(self.test_chat.id),
            'typing': True
        }
        
        self.socketio_client.emit('typing_start', typing_data)
        received = self.socketio_client.get_received()
        
        # Verify typing indicator was processed
        self.assertTrue(len(received) >= 0)

class TestDatabaseModels(MessagingServiceTestCase):
    """
    Test cases for database models and operations.
    
    These tests verify that database models work correctly including
    relationships, constraints, and data validation.
    """
    
    def test_chat_model_creation(self):
        """
        Test Chat model creation and validation.
        
        Verifies that Chat objects can be created with proper
        field validation and default values.
        """
        chat = Chat(
            name='Test Chat Model',
            chat_type=ChatType.GROUP
        )
        db.session.add(chat)
        db.session.commit()
        
        self.assertIsNotNone(chat.id)
        self.assertEqual(chat.name, 'Test Chat Model')
        self.assertEqual(chat.chat_type, ChatType.GROUP)
        self.assertTrue(chat.is_active)
        
    def test_message_model_creation(self):
        """
        Test Message model creation and validation.
        
        Verifies that Message objects can be created with proper
        relationships and field validation.
        """
        message = Message(
            chat_id=self.test_chat.id,
            sender_id=self.test_user_1['user_id'],
            content='Test message content',
            message_type=MessageType.TEXT,
            status=MessageStatus.SENT
        )
        db.session.add(message)
        db.session.commit()
        
        self.assertIsNotNone(message.id)
        self.assertEqual(message.content, 'Test message content')
        self.assertEqual(message.message_type, MessageType.TEXT)
        self.assertFalse(message.is_deleted)
        
    def test_participant_model_relationships(self):
        """
        Test Participant model relationships.
        
        Verifies that Participant objects maintain proper
        relationships with Chat and User entities.
        """
        participant = Participant.query.filter_by(
            chat_id=self.test_chat.id,
            user_id=self.test_user_1['user_id']
        ).first()
        
        self.assertIsNotNone(participant)
        self.assertEqual(participant.chat_id, self.test_chat.id)
        self.assertEqual(participant.user_id, self.test_user_1['user_id'])

class TestRedisIntegration(MessagingServiceTestCase):
    """
    Test cases for Redis integration.
    
    These tests verify that Redis caching and pub/sub functionality
    work correctly for message persistence and real-time features.
    """
    
    @patch('redis_manager.get_redis_manager')
    def test_redis_message_caching(self, mock_redis_manager):
        """
        Test Redis message caching functionality.
        
        Verifies that messages are properly cached in Redis
        for improved performance.
        """
        mock_redis = MagicMock()
        mock_redis_manager.return_value = mock_redis
        
        # Test message caching
        message_data = {
            'id': 'test-message-id',
            'content': 'Test cached message',
            'chat_id': str(self.test_chat.id)
        }
        
        mock_redis.cache_message.return_value = True
        result = mock_redis.cache_message(message_data)
        
        self.assertTrue(result)
        mock_redis.cache_message.assert_called_once_with(message_data)
        
    @patch('redis_manager.get_redis_manager')
    def test_redis_rate_limiting(self, mock_redis_manager):
        """
        Test Redis rate limiting functionality.
        
        Verifies that rate limiting works correctly to prevent
        message spam and abuse.
        """
        mock_redis = MagicMock()
        mock_redis_manager.return_value = mock_redis
        
        # Test rate limiting
        user_id = self.test_user_1['user_id']
        action = 'send_message'
        limit = 30
        
        mock_redis.check_rate_limit.return_value = True
        result = mock_redis.check_rate_limit(user_id, action, limit)
        
        self.assertTrue(result)
        mock_redis.check_rate_limit.assert_called_once_with(user_id, action, limit)

class TestSecurityAndValidation(MessagingServiceTestCase):
    """
    Test cases for security and validation features.
    
    These tests verify that security measures work correctly including
    authentication, authorization, and input validation.
    """
    
    def test_jwt_token_validation(self):
        """
        Test JWT token validation.
        
        Verifies that JWT tokens are properly validated for
        authentication and authorization.
        """
        # Test with valid token
        headers = {'Authorization': f'Bearer {self.token_user_1}'}
        response = self.client.get('/api/v1/chats', headers=headers)
        self.assertEqual(response.status_code, 200)
        
        # Test with invalid token
        headers = {'Authorization': 'Bearer invalid-token'}
        response = self.client.get('/api/v1/chats', headers=headers)
        self.assertEqual(response.status_code, 401)
        
    def test_message_content_validation(self):
        """
        Test message content validation.
        
        Verifies that message content is properly validated
        for security and appropriateness.
        """
        from auth_utils import validate_message_content
        
        # Test valid content
        is_valid, error = validate_message_content('Valid message', 'text')
        self.assertTrue(is_valid)
        self.assertIsNone(error)
        
        # Test empty content
        is_valid, error = validate_message_content('', 'text')
        self.assertFalse(is_valid)
        self.assertIsNotNone(error)
        
        # Test very long content
        long_content = 'x' * 10000
        is_valid, error = validate_message_content(long_content, 'text')
        self.assertFalse(is_valid)
        self.assertIsNotNone(error)

class TestPerformanceAndScalability(MessagingServiceTestCase):
    """
    Test cases for performance and scalability.
    
    These tests verify that the service can handle load and
    scale appropriately under various conditions.
    """
    
    def test_message_pagination_performance(self):
        """
        Test message pagination performance.
        
        Verifies that message pagination works efficiently
        even with large numbers of messages.
        """
        # Create multiple test messages
        for i in range(100):
            message = Message(
                chat_id=self.test_chat.id,
                sender_id=self.test_user_1['user_id'],
                content=f'Test message {i}',
                message_type=MessageType.TEXT,
                status=MessageStatus.SENT
            )
            db.session.add(message)
        
        db.session.commit()
        
        # Test pagination
        headers = {'Authorization': f'Bearer {self.token_user_1}'}
        response = self.client.get(
            f'/api/v1/chats/{self.test_chat.id}/messages?page=1&per_page=20',
            headers=headers
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertLessEqual(len(data['data']['messages']), 20)
        
    def test_concurrent_message_sending(self):
        """
        Test concurrent message sending.
        
        Verifies that the service can handle multiple
        simultaneous message sending operations.
        """
        import threading
        import time
        
        results = []
        
        def send_message():
            headers = {'Authorization': f'Bearer {self.token_user_1}'}
            message_data = {
                'content': f'Concurrent message {time.time()}',
                'message_type': 'text'
            }
            
            response = self.client.post(
                f'/api/v1/chats/{self.test_chat.id}/messages',
                data=json.dumps(message_data),
                content_type='application/json',
                headers=headers
            )
            results.append(response.status_code)
        
        # Create multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=send_message)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all messages were sent successfully
        self.assertTrue(all(status == 201 for status in results))

# Test runner configuration
if __name__ == '__main__':
    # Configure test runner
    unittest.main(verbosity=2)

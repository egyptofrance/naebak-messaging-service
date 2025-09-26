# Naebak Messaging Service API Documentation

## Overview

The Naebak Messaging Service provides real-time messaging capabilities for the Naebak platform, enabling secure communication between citizens, representatives, and administrators. The service supports both HTTP REST API and WebSocket connections for real-time messaging.

## Base URL

```
http://localhost:8004
```

## Authentication

All API endpoints require JWT authentication. Include the JWT token in the Authorization header:

```
Authorization: Bearer <jwt_token>
```

## API Endpoints

### Health Check

#### GET /

Check the health status of the messaging service.

**Response:**
```json
{
  "service": "naebak-messaging-service",
  "status": "healthy",
  "version": "2.0.0",
  "timestamp": "2024-01-01T12:00:00Z",
  "port": 8004,
  "database": {
    "status": "connected",
    "type": "PostgreSQL"
  },
  "redis": {
    "cache_client": "connected",
    "pubsub_client": "connected"
  },
  "features": [
    "Real-time messaging via WebSocket",
    "Direct messages between users",
    "Group chats for representatives",
    "Support conversations",
    "Message persistence with PostgreSQL",
    "Redis caching and pub/sub",
    "File and image sharing",
    "Typing indicators",
    "User presence tracking",
    "Rate limiting",
    "JWT authentication integration"
  ],
  "websocket_endpoint": "/socket.io",
  "api_base": "/api/v1"
}
```

### Chat Management

#### GET /api/v1/chats

Get all chats for the authenticated user.

**Query Parameters:**
- `page` (int, optional): Page number for pagination (default: 1)
- `per_page` (int, optional): Items per page (default: 20, max: 100)
- `search` (string, optional): Search term for chat names
- `chat_type` (string, optional): Filter by chat type (direct, group, support)

**Response:**
```json
{
  "success": true,
  "data": {
    "chats": [
      {
        "id": "chat-uuid",
        "name": "Chat Name",
        "chat_type": "direct",
        "is_active": true,
        "created_at": "2024-01-01T12:00:00Z",
        "updated_at": "2024-01-01T12:00:00Z",
        "last_message_at": "2024-01-01T12:00:00Z",
        "participants_count": 2,
        "unread_count": 5,
        "last_message": {
          "id": "message-uuid",
          "content": "Last message content",
          "sender_id": 123,
          "created_at": "2024-01-01T12:00:00Z"
        }
      }
    ],
    "pagination": {
      "page": 1,
      "pages": 5,
      "per_page": 20,
      "total": 100,
      "has_next": true,
      "has_prev": false
    }
  },
  "message": "تم جلب 20 محادثة بنجاح"
}
```

#### POST /api/v1/chats

Create a new chat conversation.

**Request Body:**
```json
{
  "participants": [123, 456],
  "name": "Chat Name",
  "chat_type": "direct"
}
```

**Response:**
```json
{
  "success": true,
  "message": "تم إنشاء المحادثة بنجاح",
  "data": {
    "chat": {
      "id": "chat-uuid",
      "name": "Chat Name",
      "chat_type": "direct",
      "is_active": true,
      "created_at": "2024-01-01T12:00:00Z",
      "updated_at": "2024-01-01T12:00:00Z",
      "participants": [
        {
          "user_id": 123,
          "is_admin": true,
          "joined_at": "2024-01-01T12:00:00Z"
        },
        {
          "user_id": 456,
          "is_admin": false,
          "joined_at": "2024-01-01T12:00:00Z"
        }
      ]
    }
  }
}
```

### Message Management

#### GET /api/v1/chats/{chat_id}/messages

Get messages for a specific chat.

**Path Parameters:**
- `chat_id` (string): Chat identifier

**Query Parameters:**
- `page` (int, optional): Page number for pagination (default: 1)
- `per_page` (int, optional): Messages per page (default: 50, max: 100)
- `before` (string, optional): Get messages before this timestamp (ISO format)

**Response:**
```json
{
  "success": true,
  "data": {
    "messages": [
      {
        "id": "message-uuid",
        "chat_id": "chat-uuid",
        "sender_id": 123,
        "content": "Message content",
        "message_type": "text",
        "status": "sent",
        "reply_to_id": null,
        "is_deleted": false,
        "created_at": "2024-01-01T12:00:00Z",
        "updated_at": "2024-01-01T12:00:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "pages": 10,
      "per_page": 50,
      "total": 500,
      "has_next": true,
      "has_prev": false
    }
  }
}
```

#### POST /api/v1/chats/{chat_id}/messages

Send a message to a chat.

**Path Parameters:**
- `chat_id` (string): Chat identifier

**Request Body:**
```json
{
  "content": "Message content",
  "message_type": "text",
  "reply_to_id": "message-uuid"
}
```

**Response:**
```json
{
  "success": true,
  "message": "تم إرسال الرسالة بنجاح",
  "data": {
    "message": {
      "id": "message-uuid",
      "chat_id": "chat-uuid",
      "sender_id": 123,
      "content": "Message content",
      "message_type": "text",
      "status": "sent",
      "reply_to_id": "replied-message-uuid",
      "is_deleted": false,
      "created_at": "2024-01-01T12:00:00Z",
      "updated_at": "2024-01-01T12:00:00Z"
    }
  }
}
```

### Participant Management

#### GET /api/v1/chats/{chat_id}/participants

Get participants of a chat.

**Path Parameters:**
- `chat_id` (string): Chat identifier

**Response:**
```json
{
  "success": true,
  "data": {
    "participants": [
      {
        "user_id": 123,
        "chat_id": "chat-uuid",
        "is_admin": true,
        "joined_at": "2024-01-01T12:00:00Z",
        "last_read_at": "2024-01-01T12:00:00Z"
      }
    ],
    "total": 2
  }
}
```

#### POST /api/v1/chats/{chat_id}/participants

Add a participant to a chat.

**Path Parameters:**
- `chat_id` (string): Chat identifier

**Request Body:**
```json
{
  "user_id": 789
}
```

**Response:**
```json
{
  "success": true,
  "message": "تم إضافة المشارك بنجاح",
  "data": {
    "participant": {
      "user_id": 789,
      "chat_id": "chat-uuid",
      "is_admin": false,
      "joined_at": "2024-01-01T12:00:00Z"
    }
  }
}
```

### User Search

#### GET /api/v1/users/search

Search for users to start conversations with.

**Query Parameters:**
- `q` (string): Search query (name, email)
- `user_type` (string, optional): Filter by user type
- `governorate` (string, optional): Filter by governorate
- `limit` (int, optional): Maximum results to return (default: 20, max: 50)

**Response:**
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "user_id": 123,
        "name": "User Name",
        "email": "user@example.com",
        "user_type": "citizen",
        "governorate": "Cairo"
      }
    ],
    "total": 1
  }
}
```

### Statistics

#### GET /api/v1/stats

Get messaging statistics for the current user.

**Response:**
```json
{
  "success": true,
  "data": {
    "stats": {
      "total_chats": 15,
      "total_messages_sent": 250,
      "unread_messages": 5,
      "active_chats": 8
    }
  }
}
```

## WebSocket Events

The messaging service supports real-time communication via WebSocket using Socket.IO.

### Connection

Connect to the WebSocket endpoint with authentication:

```javascript
const socket = io('http://localhost:8004', {
  auth: {
    token: 'jwt_token_here'
  }
});
```

### Events

#### Client to Server Events

##### join_chat
Join a chat room to receive real-time messages.

```javascript
socket.emit('join_chat', {
  chat_id: 'chat-uuid'
});
```

##### send_message
Send a message in real-time.

```javascript
socket.emit('send_message', {
  chat_id: 'chat-uuid',
  content: 'Message content',
  message_type: 'text'
});
```

##### typing_start
Indicate that the user started typing.

```javascript
socket.emit('typing_start', {
  chat_id: 'chat-uuid'
});
```

##### typing_stop
Indicate that the user stopped typing.

```javascript
socket.emit('typing_stop', {
  chat_id: 'chat-uuid'
});
```

#### Server to Client Events

##### message_received
Receive a new message in real-time.

```javascript
socket.on('message_received', (data) => {
  console.log('New message:', data.message);
});
```

##### user_typing
Receive typing indicator updates.

```javascript
socket.on('user_typing', (data) => {
  console.log(`User ${data.user_id} is typing: ${data.typing}`);
});
```

##### user_joined
Notification when a user joins a chat.

```javascript
socket.on('user_joined', (data) => {
  console.log(`User ${data.user_id} joined chat ${data.chat_id}`);
});
```

##### user_left
Notification when a user leaves a chat.

```javascript
socket.on('user_left', (data) => {
  console.log(`User ${data.user_id} left chat ${data.chat_id}`);
});
```

## Error Responses

All API endpoints return consistent error responses:

```json
{
  "success": false,
  "message": "Error message in Arabic",
  "error": "Technical error details"
}
```

### Common HTTP Status Codes

- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `429` - Too Many Requests (Rate Limited)
- `500` - Internal Server Error

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **Message sending**: 30 messages per minute per user
- **Chat creation**: 10 chats per hour per user
- **API requests**: 1000 requests per hour per user

When rate limits are exceeded, the API returns a `429` status code.

## Data Models

### Chat Types

- `direct` - One-to-one conversation between two users
- `group` - Group conversation with multiple participants
- `support` - Support conversation with administrators

### Message Types

- `text` - Plain text message
- `image` - Image attachment
- `file` - File attachment
- `system` - System-generated message

### Message Status

- `sent` - Message has been sent
- `delivered` - Message has been delivered to recipient
- `read` - Message has been read by recipient

## Security Considerations

1. **Authentication**: All endpoints require valid JWT tokens
2. **Authorization**: Users can only access chats they participate in
3. **Rate Limiting**: Prevents spam and abuse
4. **Input Validation**: All input is validated and sanitized
5. **Content Filtering**: Messages are filtered for inappropriate content
6. **Encryption**: Messages are encrypted in transit and at rest

## Integration Examples

### JavaScript/React Example

```javascript
import io from 'socket.io-client';

class MessagingService {
  constructor(token) {
    this.token = token;
    this.socket = io('http://localhost:8004', {
      auth: { token }
    });
    
    this.setupEventListeners();
  }
  
  setupEventListeners() {
    this.socket.on('message_received', (data) => {
      this.handleNewMessage(data.message);
    });
    
    this.socket.on('user_typing', (data) => {
      this.handleTypingIndicator(data);
    });
  }
  
  async getChats() {
    const response = await fetch('/api/v1/chats', {
      headers: {
        'Authorization': `Bearer ${this.token}`
      }
    });
    return response.json();
  }
  
  sendMessage(chatId, content) {
    this.socket.emit('send_message', {
      chat_id: chatId,
      content: content,
      message_type: 'text'
    });
  }
  
  joinChat(chatId) {
    this.socket.emit('join_chat', { chat_id: chatId });
  }
}
```

### Python Example

```python
import requests
import socketio

class NaebakMessagingClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.token = token
        self.headers = {'Authorization': f'Bearer {token}'}
        self.sio = socketio.Client()
        
    def get_chats(self, page=1, per_page=20):
        response = requests.get(
            f'{self.base_url}/api/v1/chats',
            headers=self.headers,
            params={'page': page, 'per_page': per_page}
        )
        return response.json()
    
    def send_message(self, chat_id, content):
        response = requests.post(
            f'{self.base_url}/api/v1/chats/{chat_id}/messages',
            headers=self.headers,
            json={'content': content, 'message_type': 'text'}
        )
        return response.json()
    
    def connect_websocket(self):
        self.sio.connect(self.base_url, auth={'token': self.token})
        
    @sio.event
    def message_received(self, data):
        print(f"New message: {data['message']['content']}")
```

## Support

For technical support or questions about the Messaging Service API, please contact the development team or refer to the project documentation.

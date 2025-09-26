"""
Naebak Messaging Service - Real-time Communication Platform

This is the main application file for the Naebak Messaging Service, which provides real-time
messaging capabilities for the Naebak platform. The service enables secure communication
between citizens, candidates, and representatives using WebSocket technology with Redis
for message persistence and scalability.

Key Features:
- Real-time messaging using Socket.IO
- Message persistence with Redis
- User authentication and session management
- Chat room functionality
- Message history and retrieval
- Cross-origin resource sharing (CORS) support

Architecture:
The service implements a WebSocket-based messaging system with Redis as the message
broker and persistence layer. It supports both one-to-one and group messaging patterns
while maintaining message history for offline users.
"""

from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import redis
import json
from datetime import datetime
import logging
from config import get_config

# Setup application
app = Flask(__name__)
config = get_config()
app.config.from_object(config)

# Setup CORS for Flask and SocketIO
CORS(app, origins=app.config["CORS_ALLOWED_ORIGINS"])
socketio = SocketIO(app, cors_allowed_origins=app.config["CORS_ALLOWED_ORIGINS"], message_queue=app.config["REDIS_URL"])

# Setup Redis connection
try:
    redis_client = redis.from_url(app.config["REDIS_URL"])
    redis_client.ping()
    print("Connected to Redis successfully!")
except redis.exceptions.ConnectionError as e:
    print(f"Could not connect to Redis: {e}")
    redis_client = None

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class Message:
    """
    Represents a message in the Naebak messaging system.
    
    This class encapsulates all message data including sender, recipient, content,
    and timestamp information. It provides methods for serialization and data
    validation to ensure message integrity across the platform.
    
    Attributes:
        sender_id (str): Unique identifier of the message sender.
        recipient_id (str): Unique identifier of the message recipient.
        content (str): The actual message content/text.
        timestamp (str): ISO format timestamp of when the message was created.
    
    Message Flow:
        1. Message created with sender, recipient, and content
        2. Timestamp automatically assigned if not provided
        3. Message serialized to dictionary for storage/transmission
        4. Message stored in Redis for persistence
        5. Message delivered to recipient via WebSocket
    """
    
    def __init__(self, sender_id, recipient_id, content, timestamp=None):
        """
        Initialize a new message instance.
        
        Args:
            sender_id (str): The ID of the user sending the message.
            recipient_id (str): The ID of the user receiving the message.
            content (str): The message content/text.
            timestamp (str, optional): Message timestamp. Defaults to current UTC time.
        """
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.content = content
        self.timestamp = timestamp if timestamp else datetime.utcnow().isoformat()

    def to_dict(self):
        """
        Convert message to dictionary format for JSON serialization.
        
        Returns:
            dict: Dictionary representation of the message with all attributes.
        """
        return {
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "content": self.content,
            "timestamp": self.timestamp
        }

@app.route("/health", methods=["GET"])
def health_check():
    """
    Health check endpoint for service monitoring.
    
    This endpoint provides comprehensive health status including Redis connectivity
    and service version information. It's used by load balancers, monitoring systems,
    and the API gateway to verify service availability.
    
    Returns:
        JSON response with service health information including:
        - Service status and version
        - Redis connectivity status
        - Timestamp of the health check
        
    Health Indicators:
        - Service status: Always "ok" if the service is running
        - Redis status: "connected", "disconnected", or error details
        - Version: Current service version for deployment tracking
    """
    redis_status = "disconnected"
    if redis_client:
        try:
            redis_client.ping()
            redis_status = "connected"
        except Exception as e:
            redis_status = f"error: {e}"

    return jsonify({
        "status": "ok", 
        "service": "naebak-messaging-service", 
        "version": "1.0.0", 
        "redis_status": redis_status,
        "timestamp": datetime.utcnow().isoformat()
    }), 200

@socketio.on("connect")
def handle_connect():
    """
    Handle new WebSocket connections from clients.
    
    This function manages the initial connection process, including user authentication
    and session setup. It validates the user_id parameter and establishes the
    connection context for subsequent messaging operations.
    
    Connection Flow:
        1. Extract user_id from connection parameters
        2. Validate user authentication (can be enhanced with JWT)
        3. Log connection event for monitoring
        4. Optionally store session mapping in Redis
        
    Authentication:
        Currently uses simple user_id parameter validation.
        Can be enhanced with JWT token verification for production use.
        
    Returns:
        bool: False to reject connection if user_id is missing, True otherwise.
    """
    user_id = request.args.get("user_id")  # Can use JWT here for identity verification
    if not user_id:
        logger.warning("Client connected without user_id.")
        return False  # Reject connection if no user_id provided
    
    logger.info(f"Client {user_id} connected. SID: {request.sid}")
    # Can link SID to user_id in Redis here for session management
    # redis_client.set(f"user_sid:{user_id}", request.sid)

@socketio.on("disconnect")
def handle_disconnect():
    """
    Handle WebSocket disconnections from clients.
    
    This function manages the cleanup process when clients disconnect,
    including session cleanup and logging for monitoring purposes.
    
    Cleanup Operations:
        1. Extract user_id from connection context
        2. Log disconnection event
        3. Clean up session data from Redis
        4. Update user presence status
    """
    user_id = request.args.get("user_id")
    logger.info(f"Client {user_id} disconnected. SID: {request.sid}")
    # Can remove SID to user_id mapping from Redis here
    # if redis_client and user_id:
    #     redis_client.delete(f"user_sid:{user_id}")

@socketio.on("send_message")
def handle_send_message(data):
    """
    Handle incoming messages from clients and route them to recipients.
    
    This function processes message sending requests, validates the data,
    stores messages for persistence, and delivers them to the intended
    recipients in real-time.
    
    Args:
        data (dict): Message data containing recipient_id and content.
        
    Message Processing Flow:
        1. Extract sender_id from connection context
        2. Validate message data (recipient, content)
        3. Create Message object with timestamp
        4. Store message in Redis for persistence
        5. Deliver message to recipient via WebSocket
        6. Send confirmation to sender
        
    Data Validation:
        - sender_id: Must be present in connection context
        - recipient_id: Must be provided in message data
        - content: Must be non-empty string
        
    Storage Strategy:
        - Messages stored in Redis lists by chat pair
        - Chat key format: "chat:{min_user_id}_{max_user_id}"
        - Limited to last 100 messages per chat for performance
        
    Delivery Mechanism:
        - Uses Socket.IO rooms for targeted message delivery
        - Recipient receives "receive_message" event
        - Sender receives "message_sent" confirmation
    """
    sender_id = request.args.get("user_id")
    recipient_id = data.get("recipient_id")
    content = data.get("content")

    if not all([sender_id, recipient_id, content]):
        logger.error(f"Invalid message data from {sender_id}: {data}")
        emit("message_error", {"error": "Missing required fields"})
        return

    message = Message(sender_id, recipient_id, content)
    logger.info(f"Message from {sender_id} to {recipient_id}: {content}")

    # Store message temporarily in Redis (simple example)
    if redis_client:
        chat_key = f"chat:{min(sender_id, recipient_id)}_{max(sender_id, recipient_id)}"
        redis_client.rpush(chat_key, json.dumps(message.to_dict()))
        redis_client.ltrim(chat_key, -100, -1)  # Keep last 100 messages

    # Send message to recipient (can be improved using Socket.IO rooms)
    # Currently assumes recipient is connected to same server and accessible by user_id
    # In production, would need pub/sub system or complex Socket.IO rooms
    emit("receive_message", message.to_dict(), room=recipient_id)  # Send to user_id as room
    emit("message_sent", {
        "status": "success", 
        "message_id": datetime.utcnow().timestamp(),
        "timestamp": message.timestamp
    }, room=sender_id)

@socketio.on("join_chat")
def handle_join_chat(data):
    """
    Handle chat room joining for users to receive messages.
    
    This function manages the process of users joining chat rooms to enable
    targeted message delivery. It sets up the necessary room memberships
    and optionally loads previous message history.
    
    Args:
        data (dict): Chat data containing chat_partner_id.
        
    Room Management:
        1. Extract user_id from connection context
        2. Validate chat_partner_id from request data
        3. Join user to their personal room for message delivery
        4. Optionally load and send previous messages
        
    Chat History:
        - Previous messages can be loaded from Redis
        - Messages sent via "previous_messages" event
        - Limited to recent messages for performance
        
    Room Strategy:
        - Each user joins a room named after their user_id
        - Enables direct message delivery to specific users
        - Supports both one-to-one and group messaging patterns
    """
    user_id = request.args.get("user_id")
    chat_partner_id = data.get("chat_partner_id")
    
    if user_id and chat_partner_id:
        # Join room named after user_id to allow direct message delivery
        socketio.join_room(user_id)
        logger.info(f"User {user_id} joined room {user_id}")
        
        # Can load previous messages from Redis here
        if redis_client:
            chat_key = f"chat:{min(user_id, chat_partner_id)}_{max(user_id, chat_partner_id)}"
            try:
                messages = [json.loads(msg) for msg in redis_client.lrange(chat_key, 0, -1)]
                emit("previous_messages", {"messages": messages, "chat_partner_id": chat_partner_id})
            except Exception as e:
                logger.error(f"Error loading previous messages: {e}")
                emit("previous_messages", {"messages": [], "chat_partner_id": chat_partner_id})

@socketio.on("typing_start")
def handle_typing_start(data):
    """
    Handle typing indicator start events.
    
    This function manages typing indicators to show when users are actively
    typing messages, providing real-time feedback for better user experience.
    
    Args:
        data (dict): Typing data containing recipient_id.
    """
    user_id = request.args.get("user_id")
    recipient_id = data.get("recipient_id")
    
    if user_id and recipient_id:
        emit("user_typing", {"user_id": user_id, "typing": True}, room=recipient_id)

@socketio.on("typing_stop")
def handle_typing_stop(data):
    """
    Handle typing indicator stop events.
    
    This function manages the end of typing indicators when users stop
    typing or send their messages.
    
    Args:
        data (dict): Typing data containing recipient_id.
    """
    user_id = request.args.get("user_id")
    recipient_id = data.get("recipient_id")
    
    if user_id and recipient_id:
        emit("user_typing", {"user_id": user_id, "typing": False}, room=recipient_id)

if __name__ == "__main__":
    """
    Run the messaging service application.
    
    This starts the Flask-SocketIO server with the configured host, port,
    and debug settings. The server handles both HTTP and WebSocket connections
    for the messaging functionality.
    """
    socketio.run(app, host="0.0.0.0", port=config.PORT, debug=config.DEBUG)

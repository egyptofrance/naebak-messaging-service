"""
Naebak Messaging Service - Redis Manager

This module handles Redis integration for message caching, pub/sub messaging,
and session management. It provides high-performance caching and real-time
message broadcasting capabilities.

Features:
- Message caching for fast retrieval
- Pub/Sub for real-time message broadcasting
- Session management for WebSocket connections
- Rate limiting for message sending
- Typing indicators management

Redis Configuration (from naebak-almakhzan):
- Host: 10.128.0.20
- Port: 6379
- Database: 0 (for caching), 1 (for pub/sub)
"""

import redis
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
import os
import pickle

# Configure logging
logger = logging.getLogger(__name__)

# Redis configuration
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None)
REDIS_DB_CACHE = 0
REDIS_DB_PUBSUB = 1

# Cache expiration times (in seconds)
MESSAGE_CACHE_TTL = 3600  # 1 hour
USER_SESSION_TTL = 1800   # 30 minutes
TYPING_INDICATOR_TTL = 10  # 10 seconds
RATE_LIMIT_TTL = 60       # 1 minute


class RedisManager:
    """
    Redis manager for handling all Redis operations in the messaging service.
    """
    
    def __init__(self):
        """Initialize Redis connections for different purposes."""
        self.cache_client = None
        self.pubsub_client = None
        self.pubsub = None
        self.connect()
    
    def connect(self):
        """Establish Redis connections."""
        try:
            # Cache client (database 0)
            self.cache_client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                password=REDIS_PASSWORD,
                db=REDIS_DB_CACHE,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
            
            # Pub/Sub client (database 1)
            self.pubsub_client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                password=REDIS_PASSWORD,
                db=REDIS_DB_PUBSUB,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
            
            # Test connections
            self.cache_client.ping()
            self.pubsub_client.ping()
            
            # Initialize pub/sub
            self.pubsub = self.pubsub_client.pubsub()
            
            logger.info("✅ Redis connections established successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to connect to Redis: {str(e)}")
            raise
    
    def disconnect(self):
        """Close Redis connections."""
        try:
            if self.pubsub:
                self.pubsub.close()
            if self.cache_client:
                self.cache_client.close()
            if self.pubsub_client:
                self.pubsub_client.close()
            logger.info("Redis connections closed")
        except Exception as e:
            logger.error(f"Error closing Redis connections: {str(e)}")
    
    # Message Caching Methods
    
    def cache_message(self, message_data: Dict[str, Any]) -> bool:
        """
        Cache a message for fast retrieval.
        
        Args:
            message_data (dict): Message data to cache
            
        Returns:
            bool: True if cached successfully, False otherwise
        """
        try:
            message_id = message_data.get('id')
            chat_id = message_data.get('chat_id')
            
            if not message_id or not chat_id:
                return False
            
            # Cache individual message
            message_key = f"message:{message_id}"
            self.cache_client.setex(
                message_key,
                MESSAGE_CACHE_TTL,
                json.dumps(message_data, ensure_ascii=False)
            )
            
            # Add to chat's recent messages list
            chat_messages_key = f"chat:{chat_id}:recent_messages"
            self.cache_client.lpush(chat_messages_key, message_id)
            self.cache_client.ltrim(chat_messages_key, 0, 49)  # Keep last 50 messages
            self.cache_client.expire(chat_messages_key, MESSAGE_CACHE_TTL)
            
            # Update chat's last message
            chat_last_message_key = f"chat:{chat_id}:last_message"
            self.cache_client.setex(
                chat_last_message_key,
                MESSAGE_CACHE_TTL,
                json.dumps(message_data, ensure_ascii=False)
            )
            
            logger.debug(f"Message {message_id} cached successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error caching message: {str(e)}")
            return False
    
    def get_cached_message(self, message_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a cached message by ID.
        
        Args:
            message_id (str): Message ID to retrieve
            
        Returns:
            dict: Message data if found, None otherwise
        """
        try:
            message_key = f"message:{message_id}"
            cached_data = self.cache_client.get(message_key)
            
            if cached_data:
                return json.loads(cached_data)
            return None
            
        except Exception as e:
            logger.error(f"Error getting cached message {message_id}: {str(e)}")
            return None
    
    def get_chat_recent_messages(self, chat_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Get recent messages for a chat from cache.
        
        Args:
            chat_id (str): Chat ID
            limit (int): Number of messages to retrieve
            
        Returns:
            list: List of recent messages
        """
        try:
            chat_messages_key = f"chat:{chat_id}:recent_messages"
            message_ids = self.cache_client.lrange(chat_messages_key, 0, limit - 1)
            
            messages = []
            for message_id in message_ids:
                message_data = self.get_cached_message(message_id)
                if message_data:
                    messages.append(message_data)
            
            return messages
            
        except Exception as e:
            logger.error(f"Error getting recent messages for chat {chat_id}: {str(e)}")
            return []
    
    def get_chat_last_message(self, chat_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the last message for a chat from cache.
        
        Args:
            chat_id (str): Chat ID
            
        Returns:
            dict: Last message data if found, None otherwise
        """
        try:
            chat_last_message_key = f"chat:{chat_id}:last_message"
            cached_data = self.cache_client.get(chat_last_message_key)
            
            if cached_data:
                return json.loads(cached_data)
            return None
            
        except Exception as e:
            logger.error(f"Error getting last message for chat {chat_id}: {str(e)}")
            return None
    
    # Pub/Sub Methods
    
    def publish_message(self, channel: str, message_data: Dict[str, Any]) -> bool:
        """
        Publish a message to a Redis channel.
        
        Args:
            channel (str): Channel name
            message_data (dict): Message data to publish
            
        Returns:
            bool: True if published successfully, False otherwise
        """
        try:
            message_json = json.dumps(message_data, ensure_ascii=False)
            self.pubsub_client.publish(channel, message_json)
            logger.debug(f"Message published to channel {channel}")
            return True
            
        except Exception as e:
            logger.error(f"Error publishing message to channel {channel}: {str(e)}")
            return False
    
    def subscribe_to_channel(self, channel: str):
        """
        Subscribe to a Redis channel.
        
        Args:
            channel (str): Channel name to subscribe to
        """
        try:
            self.pubsub.subscribe(channel)
            logger.debug(f"Subscribed to channel {channel}")
            
        except Exception as e:
            logger.error(f"Error subscribing to channel {channel}: {str(e)}")
    
    def unsubscribe_from_channel(self, channel: str):
        """
        Unsubscribe from a Redis channel.
        
        Args:
            channel (str): Channel name to unsubscribe from
        """
        try:
            self.pubsub.unsubscribe(channel)
            logger.debug(f"Unsubscribed from channel {channel}")
            
        except Exception as e:
            logger.error(f"Error unsubscribing from channel {channel}: {str(e)}")
    
    def get_message_from_pubsub(self, timeout: int = 1):
        """
        Get a message from pub/sub subscription.
        
        Args:
            timeout (int): Timeout in seconds
            
        Returns:
            dict: Message data if available, None otherwise
        """
        try:
            message = self.pubsub.get_message(timeout=timeout)
            if message and message['type'] == 'message':
                return json.loads(message['data'])
            return None
            
        except Exception as e:
            logger.error(f"Error getting message from pub/sub: {str(e)}")
            return None
    
    # Session Management Methods
    
    def store_user_session(self, user_id: int, session_data: Dict[str, Any]) -> bool:
        """
        Store user session data.
        
        Args:
            user_id (int): User ID
            session_data (dict): Session data to store
            
        Returns:
            bool: True if stored successfully, False otherwise
        """
        try:
            session_key = f"user_session:{user_id}"
            session_json = json.dumps(session_data, ensure_ascii=False)
            self.cache_client.setex(session_key, USER_SESSION_TTL, session_json)
            
            # Add to active users set
            self.cache_client.sadd("active_users", user_id)
            self.cache_client.expire("active_users", USER_SESSION_TTL)
            
            logger.debug(f"Session stored for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing session for user {user_id}: {str(e)}")
            return False
    
    def get_user_session(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Get user session data.
        
        Args:
            user_id (int): User ID
            
        Returns:
            dict: Session data if found, None otherwise
        """
        try:
            session_key = f"user_session:{user_id}"
            session_data = self.cache_client.get(session_key)
            
            if session_data:
                return json.loads(session_data)
            return None
            
        except Exception as e:
            logger.error(f"Error getting session for user {user_id}: {str(e)}")
            return None
    
    def remove_user_session(self, user_id: int) -> bool:
        """
        Remove user session data.
        
        Args:
            user_id (int): User ID
            
        Returns:
            bool: True if removed successfully, False otherwise
        """
        try:
            session_key = f"user_session:{user_id}"
            self.cache_client.delete(session_key)
            
            # Remove from active users set
            self.cache_client.srem("active_users", user_id)
            
            logger.debug(f"Session removed for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error removing session for user {user_id}: {str(e)}")
            return False
    
    def get_active_users(self) -> List[int]:
        """
        Get list of active users.
        
        Returns:
            list: List of active user IDs
        """
        try:
            active_users = self.cache_client.smembers("active_users")
            return [int(user_id) for user_id in active_users]
            
        except Exception as e:
            logger.error(f"Error getting active users: {str(e)}")
            return []
    
    # Typing Indicators Methods
    
    def set_typing_indicator(self, chat_id: str, user_id: int, is_typing: bool) -> bool:
        """
        Set typing indicator for a user in a chat.
        
        Args:
            chat_id (str): Chat ID
            user_id (int): User ID
            is_typing (bool): Whether user is typing
            
        Returns:
            bool: True if set successfully, False otherwise
        """
        try:
            typing_key = f"typing:{chat_id}"
            
            if is_typing:
                # Add user to typing set with expiration
                self.cache_client.sadd(typing_key, user_id)
                self.cache_client.expire(typing_key, TYPING_INDICATOR_TTL)
            else:
                # Remove user from typing set
                self.cache_client.srem(typing_key, user_id)
            
            logger.debug(f"Typing indicator set for user {user_id} in chat {chat_id}: {is_typing}")
            return True
            
        except Exception as e:
            logger.error(f"Error setting typing indicator: {str(e)}")
            return False
    
    def get_typing_users(self, chat_id: str) -> List[int]:
        """
        Get list of users currently typing in a chat.
        
        Args:
            chat_id (str): Chat ID
            
        Returns:
            list: List of user IDs currently typing
        """
        try:
            typing_key = f"typing:{chat_id}"
            typing_users = self.cache_client.smembers(typing_key)
            return [int(user_id) for user_id in typing_users]
            
        except Exception as e:
            logger.error(f"Error getting typing users for chat {chat_id}: {str(e)}")
            return []
    
    # Rate Limiting Methods
    
    def check_rate_limit(self, user_id: int, action: str, limit: int = 10) -> bool:
        """
        Check if user has exceeded rate limit for an action.
        
        Args:
            user_id (int): User ID
            action (str): Action being performed
            limit (int): Maximum number of actions per minute
            
        Returns:
            bool: True if within limit, False if exceeded
        """
        try:
            rate_limit_key = f"rate_limit:{user_id}:{action}"
            current_count = self.cache_client.get(rate_limit_key)
            
            if current_count is None:
                # First action, set counter
                self.cache_client.setex(rate_limit_key, RATE_LIMIT_TTL, 1)
                return True
            
            current_count = int(current_count)
            if current_count >= limit:
                logger.warning(f"Rate limit exceeded for user {user_id} action {action}")
                return False
            
            # Increment counter
            self.cache_client.incr(rate_limit_key)
            return True
            
        except Exception as e:
            logger.error(f"Error checking rate limit: {str(e)}")
            return True  # Allow action on error
    
    # Chat Statistics Methods
    
    def increment_chat_stats(self, chat_id: str, stat_type: str) -> bool:
        """
        Increment chat statistics.
        
        Args:
            chat_id (str): Chat ID
            stat_type (str): Type of statistic (messages_sent, users_joined, etc.)
            
        Returns:
            bool: True if incremented successfully, False otherwise
        """
        try:
            stats_key = f"chat_stats:{chat_id}:{stat_type}"
            self.cache_client.incr(stats_key)
            self.cache_client.expire(stats_key, 86400)  # 24 hours
            
            # Also increment daily stats
            today = datetime.now().strftime('%Y-%m-%d')
            daily_stats_key = f"daily_stats:{today}:{stat_type}"
            self.cache_client.incr(daily_stats_key)
            self.cache_client.expire(daily_stats_key, 86400 * 7)  # 7 days
            
            return True
            
        except Exception as e:
            logger.error(f"Error incrementing chat stats: {str(e)}")
            return False
    
    def get_chat_stats(self, chat_id: str) -> Dict[str, int]:
        """
        Get chat statistics.
        
        Args:
            chat_id (str): Chat ID
            
        Returns:
            dict: Chat statistics
        """
        try:
            stats = {}
            stat_types = ['messages_sent', 'users_joined', 'users_left']
            
            for stat_type in stat_types:
                stats_key = f"chat_stats:{chat_id}:{stat_type}"
                count = self.cache_client.get(stats_key)
                stats[stat_type] = int(count) if count else 0
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting chat stats for {chat_id}: {str(e)}")
            return {}
    
    # Utility Methods
    
    def clear_chat_cache(self, chat_id: str) -> bool:
        """
        Clear all cached data for a chat.
        
        Args:
            chat_id (str): Chat ID
            
        Returns:
            bool: True if cleared successfully, False otherwise
        """
        try:
            # Get all keys related to this chat
            pattern = f"*{chat_id}*"
            keys = self.cache_client.keys(pattern)
            
            if keys:
                self.cache_client.delete(*keys)
            
            logger.debug(f"Cache cleared for chat {chat_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error clearing cache for chat {chat_id}: {str(e)}")
            return False
    
    def health_check(self) -> Dict[str, bool]:
        """
        Perform health check on Redis connections.
        
        Returns:
            dict: Health status of Redis connections
        """
        health = {
            'cache_client': False,
            'pubsub_client': False
        }
        
        try:
            # Test cache client
            self.cache_client.ping()
            health['cache_client'] = True
        except Exception as e:
            logger.error(f"Cache client health check failed: {str(e)}")
        
        try:
            # Test pub/sub client
            self.pubsub_client.ping()
            health['pubsub_client'] = True
        except Exception as e:
            logger.error(f"Pub/sub client health check failed: {str(e)}")
        
        return health


# Global Redis manager instance
redis_manager = RedisManager()


def get_redis_manager() -> RedisManager:
    """
    Get the global Redis manager instance.
    
    Returns:
        RedisManager: Global Redis manager instance
    """
    return redis_manager

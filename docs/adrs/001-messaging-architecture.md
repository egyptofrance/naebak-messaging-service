# ADR-001: Real-time Messaging Architecture and WebSocket Strategy

**Status:** Accepted

**Context:**

The Naebak platform requires a robust real-time messaging system to facilitate communication between citizens, candidates, and political representatives. We needed to design a system that could handle real-time message delivery, maintain message history, support multiple conversation types, and scale to accommodate the platform's user base. Several approaches were considered, including traditional HTTP polling, Server-Sent Events (SSE), and WebSocket-based solutions.

**Decision:**

We have decided to implement a real-time messaging service using Flask-SocketIO with Redis as the message broker and persistence layer, providing bidirectional real-time communication with message history and scalability features.

## **Core Architecture Design:**

**WebSocket-Based Communication** serves as the foundation for real-time messaging, enabling instant bidirectional communication between clients and the server. Socket.IO provides additional features like automatic reconnection, room management, and fallback mechanisms for environments where WebSocket connections are not available.

**Redis Message Persistence** handles both message storage and real-time message brokering across multiple server instances. Redis lists store conversation history while Redis pub/sub capabilities enable message distribution in a horizontally scaled environment.

**Room-Based Message Delivery** organizes users into Socket.IO rooms for efficient message routing. Each user joins a room named after their user ID, enabling direct message delivery without broadcasting to all connected clients.

## **Message Flow Architecture:**

**Connection Management** handles user authentication and session establishment through WebSocket connections. Users connect with their user ID, which serves as both authentication and routing information for message delivery.

**Message Processing Pipeline** validates incoming messages, creates message objects with timestamps, stores them in Redis for persistence, and delivers them to recipients through their respective rooms. The pipeline ensures message integrity and delivery confirmation.

**Chat History Management** maintains conversation history in Redis using chat-specific keys that combine participant IDs. This approach enables efficient retrieval of previous messages when users join conversations.

## **Scalability and Performance:**

**Horizontal Scaling Support** enables multiple messaging service instances to work together using Redis as a shared message queue. Socket.IO's Redis adapter ensures messages are delivered correctly across different server instances.

**Message Persistence Strategy** stores messages in Redis lists with automatic trimming to maintain performance. Each conversation is limited to the last 100 messages in memory, with older messages archived or moved to permanent storage as needed.

**Connection Pooling** optimizes Redis connections and Socket.IO performance by reusing connections and managing connection lifecycle efficiently. This reduces overhead and improves response times under high load.

## **Real-time Features:**

**Instant Message Delivery** provides immediate message transmission between connected users without polling or delays. Messages are delivered as soon as they are received and validated by the server.

**Typing Indicators** enhance user experience by showing when other participants are actively typing messages. This feature uses lightweight events that don't require persistence.

**Presence Management** tracks user online status and connection state, enabling features like "last seen" timestamps and online indicators for better user experience.

## **Security and Authentication:**

**Connection Authentication** validates user identity during WebSocket connection establishment. Currently uses user ID parameters but can be enhanced with JWT token validation for production security.

**Message Validation** ensures all messages contain required fields (sender, recipient, content) and validates data integrity before processing. Invalid messages are rejected with appropriate error responses.

**Room Access Control** restricts message delivery to authorized recipients only. Users can only receive messages in rooms they have explicitly joined, preventing unauthorized message access.

## **Data Structure and Storage:**

**Message Object Model** defines a consistent structure for all messages including sender ID, recipient ID, content, and timestamp. This standardization enables easy serialization and cross-service compatibility.

**Chat Key Strategy** uses deterministic naming for conversation storage based on participant IDs. The format "chat:{min_user_id}_{max_user_id}" ensures consistent key generation regardless of message direction.

**Conversation History** maintains chronological message order using Redis lists, enabling efficient retrieval of recent messages and pagination for older message history.

## **Error Handling and Reliability:**

**Connection Recovery** handles network interruptions and connection drops gracefully through Socket.IO's automatic reconnection features. Messages sent during disconnections are queued and delivered upon reconnection.

**Message Delivery Confirmation** provides feedback to senders about message delivery status, enabling client applications to handle failed deliveries and retry mechanisms.

**Redis Failover** includes error handling for Redis connectivity issues, ensuring the service remains operational even when message persistence is temporarily unavailable.

**Consequences:**

**Positive:**

*   **Real-time Communication**: Instant message delivery provides excellent user experience for political engagement and citizen communication.
*   **Scalability**: Redis-based architecture supports horizontal scaling to accommodate growing user base and message volume.
*   **Message Persistence**: Conversation history enables users to review previous discussions and maintain context across sessions.
*   **Cross-platform Compatibility**: Socket.IO provides broad client support across web browsers, mobile applications, and desktop clients.
*   **Development Efficiency**: Flask-SocketIO simplifies WebSocket implementation while providing robust features for production use.

**Negative:**

*   **Resource Usage**: WebSocket connections consume more server resources compared to stateless HTTP requests, requiring careful capacity planning.
*   **Complexity**: Real-time systems introduce additional complexity in error handling, connection management, and state synchronization.
*   **Redis Dependency**: Heavy reliance on Redis for both persistence and message brokering creates a critical dependency that requires high availability setup.

**Implementation Notes:**

The current implementation prioritizes simplicity and rapid development while maintaining scalability options. Future enhancements could include message encryption for sensitive political communications, advanced moderation features for content filtering, and integration with external notification systems. The modular design allows for these improvements without major architectural changes while maintaining the core real-time messaging capabilities.

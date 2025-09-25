from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import redis
import json
from datetime import datetime
import logging
from config import get_config

# إعداد التطبيق
app = Flask(__name__)
config = get_config()
app.config.from_object(config)

# إعداد CORS لـ Flask و SocketIO
CORS(app, origins=app.config["CORS_ALLOWED_ORIGINS"])
socketio = SocketIO(app, cors_allowed_origins=app.config["CORS_ALLOWED_ORIGINS"], message_queue=app.config["REDIS_URL"])

# إعداد Redis
try:
    redis_client = redis.from_url(app.config["REDIS_URL"])
    redis_client.ping()
    print("Connected to Redis successfully!")
except redis.exceptions.ConnectionError as e:
    print(f"Could not connect to Redis: {e}")
    redis_client = None

# إعداد Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# نموذج لرسالة (كما هو موضح في LEADER.md)
class Message:
    def __init__(self, sender_id, recipient_id, content, timestamp=None):
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.content = content
        self.timestamp = timestamp if timestamp else datetime.utcnow().isoformat()

    def to_dict(self):
        return {
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "content": self.content,
            "timestamp": self.timestamp
        }

@app.route("/health", methods=["GET"])
def health_check():
    """فحص صحة الخدمة"""
    redis_status = "disconnected"
    if redis_client:
        try:
            redis_client.ping()
            redis_status = "connected"
        except Exception as e:
            redis_status = f"error: {e}"

    return jsonify({"status": "ok", "service": "naebak-messaging-service", "version": "1.0.0", "redis_status": redis_status}), 200

@socketio.on("connect")
def handle_connect():
    user_id = request.args.get("user_id") # يمكن استخدام JWT هنا للتحقق من الهوية
    if not user_id:
        logger.warning("Client connected without user_id.")
        return False # رفض الاتصال إذا لم يكن هناك user_id
    
    logger.info(f"Client {user_id} connected. SID: {request.sid}")
    # يمكن ربط SID بالـ user_id في Redis هنا
    # redis_client.set(f"user_sid:{user_id}", request.sid)

@socketio.on("disconnect")
def handle_disconnect():
    user_id = request.args.get("user_id")
    logger.info(f"Client {user_id} disconnected. SID: {request.sid}")
    # يمكن إزالة ربط SID بالـ user_id من Redis هنا

@socketio.on("send_message")
def handle_send_message(data):
    sender_id = request.args.get("user_id")
    recipient_id = data.get("recipient_id")
    content = data.get("content")

    if not all([sender_id, recipient_id, content]):
        logger.error(f"Invalid message data from {sender_id}: {data}")
        return

    message = Message(sender_id, recipient_id, content)
    logger.info(f"Message from {sender_id} to {recipient_id}: {content}")

    # حفظ الرسالة مؤقتًا في Redis (مثال بسيط)
    if redis_client:
        chat_key = f"chat:{min(sender_id, recipient_id)}_{max(sender_id, recipient_id)}"
        redis_client.rpush(chat_key, json.dumps(message.to_dict()))
        redis_client.ltrim(chat_key, -100, -1) # الاحتفاظ بآخر 100 رسالة

    # إرسال الرسالة للمستقبل (يمكن تحسين هذا باستخدام غرف SocketIO)
    # حاليًا، نفترض أن المستقبل متصل بنفس السيرفر ويمكن الوصول إليه بـ user_id
    # في بيئة إنتاج، ستحتاج إلى نظام pub/sub أو غرف SocketIO معقدة
    emit("receive_message", message.to_dict(), room=recipient_id) # إرسال للـ user_id كـ room
    emit("message_sent", {"status": "success", "message_id": datetime.utcnow().timestamp()}, room=sender_id)

@socketio.on("join_chat")
def handle_join_chat(data):
    user_id = request.args.get("user_id")
    chat_partner_id = data.get("chat_partner_id")
    if user_id and chat_partner_id:
        # الانضمام إلى غرفة باسم user_id للسماح بإرسال الرسائل مباشرة إليه
        socketio.join_room(user_id)
        logger.info(f"User {user_id} joined room {user_id}")
        # يمكن تحميل الرسائل السابقة من Redis هنا
        # chat_key = f"chat:{min(user_id, chat_partner_id)}_{max(user_id, chat_partner_id)}"
        # messages = [json.loads(msg) for msg in redis_client.lrange(chat_key, 0, -1)]
        # emit("previous_messages", messages)

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=config.PORT, debug=config.DEBUG)


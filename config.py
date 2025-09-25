import os

class Config:
    PORT = 8004
    FLASK_ENV = os.environ.get("FLASK_ENV", "development")
    DEBUG = os.environ.get("DEBUG", "True").lower() == "true"
    SECRET_KEY = os.environ.get("SECRET_KEY", "super-secret-messaging-key")

    # Redis Configuration for message storage/caching
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

    # CORS settings for SocketIO
    CORS_ALLOWED_ORIGINS = os.environ.get("CORS_ALLOWED_ORIGINS", "*").split(",")

class DevelopmentConfig(Config):
    DEBUG = True
    FLASK_ENV = "development"

class ProductionConfig(Config):
    DEBUG = False
    FLASK_ENV = "production"

def get_config():
    if os.environ.get("FLASK_ENV") == "production":
        return ProductionConfig
    return DevelopmentConfig


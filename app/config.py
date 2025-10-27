import os

class Config:
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/mydb")
    APP_SECRET = os.getenv("APP_SECRET", "dev_secret_change_this")
    DEBUG = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")
    ALLOWED_ALGORITHMS = ["HS256", "HS384", "HS512"]

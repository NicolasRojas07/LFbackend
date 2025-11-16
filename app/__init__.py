from flask import Flask
from flask_cors import CORS
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import traceback
import ssl
from pymongo import MongoClient
import certifi
from app.config import Config
from app.routes.jwt_routes import bp as jwt_bp
from app import extensions

def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Initialize Flask-PyMongo with the app
    if not app.config.get("MONGO_URI"):
        # Fail fast with a clear message if MONGO_URI is missing
        raise RuntimeError("MONGO_URI is not set. Configure it via environment variables.")

    # Initialize direct PyMongo client - MongoDB optional for basic JWT operations
    uri = app.config.get("MONGO_URI", "")
    
    if uri:
        try:
            extensions.client = MongoClient(
                uri,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
                socketTimeoutMS=5000
            )
            extensions.db = extensions.client.get_database()
            
            # Test connection
            extensions.db.command('ping')
            print("✓ MongoDB connection successful")
        except Exception as e:
            print(f"⚠ MongoDB connection FAILED: {type(e).__name__}: {str(e)[:100]}")
            print("  → MongoDB endpoints (/api/jwt/tests, /save-test) will return 503")
            print("  → Other JWT endpoints continue to work normally")
            extensions.db = None
            extensions.client = None
    else:
        print("⚠ MONGO_URI not set - MongoDB endpoints disabled")
        extensions.db = None
        extensions.client = None

    app.register_blueprint(jwt_bp)

    @app.route("/")
    def index():
        return {"message": "Backend is running! Go to /health endpoint."}, 200

    @app.route("/health")
    def health():
        return {"status": "ok"}, 200

    @app.errorhandler(404)
    def not_found(e):
        return {"error": "Not found"}, 404

    @app.errorhandler(500)
    def server_error(e):
        return {
            "error": "Internal server error",
            "detail": str(e),
            "trace": traceback.format_exc()
        }, 500

    return app

from flask import Flask
from flask_cors import CORS
import traceback
from pymongo import MongoClient
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

    # Initialize direct PyMongo client
    uri = app.config.get("MONGO_URI", "")
    if not uri:
        raise RuntimeError("MONGO_URI is not set. Configure it via environment variables.")
    
    try:
        # MongoDB connection - works with Railway MongoDB and MongoDB Atlas
        extensions.client = MongoClient(
            uri,
            serverSelectionTimeoutMS=10000,
            connectTimeoutMS=10000,
            socketTimeoutMS=10000
        )
        
        # Extract database name from URI or use default
        if '/' in uri and '?' in uri:
            # Format: mongodb://host:port/dbname?options
            db_name = uri.split('/')[-1].split('?')[0]
        elif uri.count('/') >= 3:
            # Format: mongodb://host:port/dbname
            db_name = uri.split('/')[-1]
        else:
            # No database in URI, use default
            db_name = 'jwtdb'
        
        if not db_name or db_name == '':
            db_name = 'jwtdb'
            
        extensions.db = extensions.client[db_name]
        
        # Test connection
        extensions.db.command('ping')
        print(f"✓ MongoDB connection successful to database: {db_name}")
    except Exception as e:
        print(f"✗ MongoDB connection FAILED: {type(e).__name__}: {str(e)[:200]}")
        print("  → Recommended: Use Render's managed MongoDB instead of Atlas")
        print("  → Create a MongoDB instance in Render dashboard and use its internal URI")
        raise RuntimeError(f"MongoDB connection required but failed: {type(e).__name__}")

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

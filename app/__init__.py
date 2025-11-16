from flask import Flask
from flask_cors import CORS
import traceback
from app.config import Config
from app.routes.jwt_routes import bp as jwt_bp
from app.extensions import mongo

def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Initialize Flask-PyMongo with the app
    if not app.config.get("MONGO_URI"):
        # Fail fast with a clear message if MONGO_URI is missing
        raise RuntimeError("MONGO_URI is not set. Configure it via environment variables.")
    mongo.init_app(app)

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

# app/__init__.py
from flask import Flask
from .config import Config
from .extensions import mongo
from .routes.jwt_routes import bp as jwt_bp
from flask_cors import CORS
import traceback

def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    mongo.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    app.register_blueprint(jwt_bp)

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

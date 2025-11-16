import os
from flask import Flask
from flask_cors import CORS
import traceback
import ssl
from pymongo import MongoClient
from app.config import Config
from app.extensions import mongo
from app.routes.jwt_routes import bp as jwt_bp


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    mongo_uri = os.environ.get("MONGO_URI", app.config.get("MONGO_URI"))
    if not mongo_uri:
        raise ValueError("MONGO_URI no está definido. Revisa las variables de entorno.")

    client = MongoClient(
        mongo_uri,
        tls=True,
        tlsAllowInvalidCertificates=True,
        tlsVersion=ssl.PROTOCOL_TLSv1_2
    )

    mongo.init_app(app, mongo_client=client)

    CORS(app, resources={r"/api/*": {"origins": "*"}})

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

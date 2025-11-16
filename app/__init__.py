from flask import Flask
from flask_cors import CORS
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
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

    # If using MongoDB Atlas SRV, disable OCSP endpoint check unless already set
    # Skip adding if tlsAllowInvalidCertificates is present to avoid invalid combos
    uri = app.config.get("MONGO_URI", "")
    try:
        parsed = urlparse(uri)
        if parsed.scheme == "mongodb+srv" and parsed.hostname and parsed.hostname.endswith("mongodb.net"):
            qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
            keys_lower = {k.lower() for k in qs.keys()}
            if (
                "tlsdisableocspendpointcheck" not in keys_lower
                and "tlsallowinvalidcertificates" not in keys_lower
            ):
                qs["tlsDisableOCSPEndpointCheck"] = "true"
                new_query = urlencode(qs)
                app.config["MONGO_URI"] = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                ))
    except Exception:
        pass

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

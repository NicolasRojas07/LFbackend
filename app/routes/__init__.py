from .jwt_routes import bp as jwt_bp

def register_routes(app):
    app.register_blueprint(jwt_bp)

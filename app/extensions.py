from flask_pymongo import PyMongo
import certifi
import ssl

# Flask-PyMongo instance with explicit TLS 1.2+ context to avoid handshake errors
mongo = PyMongo(
    tlsCAFile=certifi.where(),
    tls=True,
    tlsAllowInvalidHostnames=False,
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=5000,
    socketTimeoutMS=5000
)

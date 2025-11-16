from flask_pymongo import PyMongo
import certifi

# Flask-PyMongo instance; provide CA bundle and shorter timeouts to avoid worker timeouts
mongo = PyMongo(
    tlsCAFile=certifi.where(),
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=5000,
    socketTimeoutMS=5000
)

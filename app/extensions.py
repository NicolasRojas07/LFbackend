from flask_pymongo import PyMongo
import certifi

# Flask-PyMongo instance; provide CA bundle to avoid TLS handshake issues
mongo = PyMongo(tlsCAFile=certifi.where())

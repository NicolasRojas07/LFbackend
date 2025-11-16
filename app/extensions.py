import ssl
from flask_pymongo import PyMongo
from pymongo import MongoClient
from app.config import Config

mongo = PyMongo()

client = MongoClient(
    Config.MONGO_URI,
    tls=True,
    tlsAllowInvalidCertificates=True, 
    tlsVersion=ssl.PROTOCOL_TLSv1_2
)

mongo.cx = client

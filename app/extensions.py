import ssl
from flask_pymongo import PyMongo
from app.config import Config
from pymongo import MongoClient

client = MongoClient(
    Config.MONGO_URI,
    tls=True,
    tlsAllowInvalidCertificates=True,  
    tlsVersion=ssl.PROTOCOL_TLSv1_2
)

from flask_pymongo import PyMongo

mongo = PyMongo()
mongo.cx = client 

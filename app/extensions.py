import ssl
from pymongo import MongoClient
from app.config import Config

client = MongoClient(
    Config.MONGO_URI,
    tls=True,
    tlsAllowInvalidCertificates=True, 
    tlsVersion=ssl.PROTOCOL_TLSv1_2
)

db = client.get_database()

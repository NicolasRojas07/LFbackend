import os
from pymongo import MongoClient
import ssl

class Config:
    MONGO_URI = os.getenv(
        "MONGO_URI",
        "mongodb+srv://nicolas:2002@jwtcluster.fm231vs.mongodb.net/mydb"
    )
    APP_SECRET = os.getenv("APP_SECRET", "dev_secret_change_this")
    DEBUG = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")
    ALLOWED_ALGORITHMS = ["HS256", "HS384", "HS512"]

    client = MongoClient(
        MONGO_URI,
        tls=True,
        tlsAllowInvalidCertificates=True,
        tlsVersion=ssl.PROTOCOL_TLSv1_2
    )
    
    db = client.get_database()

from pymongo import MongoClient
import ssl
import certifi

# Direct PyMongo client to be initialized in create_app
client = None
db = None

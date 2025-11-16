from flask_pymongo import PyMongo

# Flask-PyMongo instance; initialized in create_app via mongo.init_app(app)
mongo = PyMongo()

import os
from app import create_app

os.environ["MONGO_URI"] = "mongodb://localhost:27017/mydb"

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)

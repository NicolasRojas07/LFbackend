import os
print(">>> Render is using MONGO_URI =", os.environ.get("MONGO_URI"))

from app import create_app

app = create_app()

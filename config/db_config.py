# config/db_config.py
from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

# MongoDB Atlas connection
MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    raise ValueError("MONGO_URI not found in environment variables.")

client = MongoClient(MONGO_URI, maxPoolSize=20, connect=True)

# Choose your database
db = client["face_attendance_system"]

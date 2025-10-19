from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
import requests
from config.db_config import db
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from flask_jwt_extended import create_access_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from models.face_db_model import save_face_data, get_student_by_id, normalize_student

# ---------------------------
# Blueprint + Config
# ---------------------------
face_bp = Blueprint("face", __name__)
executor = ThreadPoolExecutor(max_workers=4)
limiter = Limiter(key_func=get_remote_address, default_limits=[])

# ✅ Hugging Face AI microservice base URL (change to your actual deployed Space)
HF_AI_URL = "https://meuorii-face-recognition-attendance.hf.space"
students_collection = db["students"] 

# ---------------------------
# Register Face (via Hugging Face)
# ---------------------------
@face_bp.route("/register-auto", methods=["POST"])
def register_auto():
    try:
        data = request.get_json(silent=True) or {}
        student_id = data.get("student_id")

        if not student_id or not data.get("image"):
            return jsonify({"success": False, "error": "Missing student_id or image"}), 400

        # 🔗 Forward to Hugging Face Space
        res = requests.post(f"{HF_AI_URL}/register-auto", json=data, timeout=60)
        if res.status_code != 200:
            print(f"⚠️ HF service returned {res.status_code}: {res.text}")
            return jsonify({"success": False, "error": "Hugging Face service error"}), res.status_code

        hf_result = res.json()

        if hf_result.get("success") and hf_result.get("embeddings"):
            angle_embeddings = hf_result["embeddings"]

            # 🔍 Fetch or create student record
            student_doc = students_collection.find_one({"student_id": student_id})
            if not student_doc:
                students_collection.insert_one({
                    "student_id": student_id,
                    "First_Name": data.get("First_Name"),
                    "Last_Name": data.get("Last_Name"),
                    "Course": data.get("Course"),
                    "Email": data.get("Email"),
                    "Contact_Number": data.get("Contact_Number"),
                    "Subjects": data.get("Subjects", []),
                    "registered": False,
                    "created_at": datetime.utcnow()
                })
                print(f"🆕 Created new record for {student_id}")
                student_doc = students_collection.find_one({"student_id": student_id})

            # 🧠 Build update payload
            update_fields = {
                "student_id": student_id,
                "First_Name": student_doc.get("First_Name", data.get("First_Name")),
                "Last_Name": student_doc.get("Last_Name", data.get("Last_Name")),
                "Course": student_doc.get("Course", data.get("Course")),
                "Email": student_doc.get("Email", data.get("Email")),
                "Contact_Number": student_doc.get("Contact_Number", data.get("Contact_Number")),
                "Subjects": student_doc.get("Subjects", data.get("Subjects")),
                "registered": True,
                "embeddings": angle_embeddings
            }

            # 💾 Save to DB
            if save_face_data(student_id, update_fields):
                print(f"✅ Saved embeddings and student info for {student_id} → {list(angle_embeddings.keys())}")
            else:
                print(f"⚠️ Failed to save embeddings for {student_id}")

        else:
            print(f"⚠️ Registration failed or no embeddings returned for {student_id}")
            return jsonify({"success": False, "error": "No embeddings found"}), 400

        return jsonify(hf_result), 200

    except requests.exceptions.Timeout:
        print("⏱️ Timeout contacting Hugging Face service.")
        return jsonify({"success": False, "error": "AI service timeout"}), 504
    except Exception as e:
        import traceback
        print("❌ /register-auto error:", str(e))
        print(traceback.format_exc())
        return jsonify({"success": False, "error": f"Internal server error: {str(e)}"}), 500


# ---------------------------
# Face Login (via Hugging Face)
# ---------------------------
@face_bp.route("/login", methods=["POST"])
def face_login():
    """Perform face login using Hugging Face AI model"""
    try:
        data = request.get_json(silent=True) or {}
        base64_image = data.get("image")
        if not base64_image:
            return jsonify({"error": "Missing image"}), 400

        # 🧠 Load all registered embeddings from MongoDB
        from models.face_db_model import load_registered_faces
        registered_faces = []
        all_students = load_registered_faces()

        for s in all_students:
            student_id = s.get("student_id")
            embeddings = s.get("embeddings", {})
            for angle, vector in embeddings.items():
                if vector and isinstance(vector, list):
                    registered_faces.append({
                        "user_id": student_id,
                        "embedding": vector,
                        "angle": angle
                    })

        if not registered_faces:
            print("⚠️ No registered faces found in DB.")
            return jsonify({"error": "No registered faces found"}), 400

        # 🔗 Forward to Hugging Face with both image + embeddings
        payload = {
            "image": base64_image,
            "registered_faces": registered_faces
        }

        res = requests.post(f"{HF_AI_URL}/recognize", json=payload, timeout=90)
        if res.status_code != 200:
            return jsonify({"error": "Hugging Face service error"}), res.status_code

        hf_result = res.json()

        # ⚠️ If recognition failed
        if not hf_result.get("success"):
            return jsonify(hf_result), 400

        # ✅ Successful match → fetch from DB
        student_id = hf_result.get("student_id")
        raw_student = get_student_by_id(student_id)
        if not raw_student:
            return jsonify({"error": "Student not found"}), 404

        student = normalize_student(raw_student)

        # 🎟️ Generate token
        token = create_access_token(
            identity=student.get("student_id"),
            expires_delta=timedelta(hours=12)
        )

        return jsonify({
            "token": token,
            "student": {
                "student_id": student.get("student_id", ""),
                "First_name": student.get("First_name", ""),
                "Last_name": student.get("Last_name", ""),
                "Course": student.get("Course", ""),
                "Section": student.get("Section", "")
            },
            "match_score": hf_result.get("match_score"),
            "anti_spoof_confidence": hf_result.get("anti_spoof_confidence"),
        }), 200

    except Exception as e:
        print("❌ /login error:", str(e))
        return jsonify({"error": "Internal server error"}), 500

@face_bp.route("/get_registered_faces", methods=["GET"])
def get_registered_faces():
    """Return all students that have stored embeddings"""
    try:
        from models.face_db_model import load_registered_faces
        faces = load_registered_faces()

        if not faces:
            return jsonify([]), 200  # no faces yet is not an error

        return jsonify(faces), 200
    except Exception as e:
        print("❌ /get_registered_faces error:", str(e))
        return jsonify({"error": "Failed to load registered faces"}), 500
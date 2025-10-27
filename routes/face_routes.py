from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
import requests
import numpy as np
from config.db_config import db
from concurrent.futures import ThreadPoolExecutor
from flask_jwt_extended import create_access_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from models.face_db_model import save_face_data, get_student_by_id, normalize_student, get_student_by_id

# ---------------------------
# Blueprint + Config
# ---------------------------
face_bp = Blueprint("face_bp", __name__)
executor = ThreadPoolExecutor(max_workers=4)
limiter = Limiter(key_func=get_remote_address, default_limits=[])

# ✅ Hugging Face AI microservice base URL
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

        # 🔗 Send image to Hugging Face for embedding extraction
        res = requests.post(f"{HF_AI_URL}/register-auto", json=data, timeout=120)
        if res.status_code != 200:
            print(f"⚠️ HF service returned {res.status_code}: {res.text}")
            return jsonify({"success": False, "error": "Hugging Face service error"}), res.status_code

        hf_result = res.json()

        # ✅ Normal success flow
        if hf_result.get("success") and hf_result.get("embeddings"):
            raw_embeddings = hf_result["embeddings"]

            # 🔹 Normalize all embeddings
            normalized_embeddings = {}
            for angle, vec in raw_embeddings.items():
                v = np.array(vec, dtype=np.float32)
                norm = np.linalg.norm(v)
                if norm == 0:
                    continue
                v = v / norm
                normalized_embeddings[angle] = v.tolist()

            # 🔍 Find or create student record
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

            # 🔄 Update with new normalized embeddings
            update_fields = {
                "student_id": student_id,
                "First_Name": data.get("First_Name") or student_doc.get("First_Name"),
                "Last_Name": data.get("Last_Name") or student_doc.get("Last_Name"),
                "Middle_Name": data.get("Middle_Name") or student_doc.get("Middle_Name"),
                "Course": data.get("Course") or student_doc.get("Course"),
                "Email": data.get("Email") or student_doc.get("Email"),
                "Contact_Number": data.get("Contact_Number") or student_doc.get("Contact_Number"),
                "Subjects": data.get("Subjects") or student_doc.get("Subjects"),
                "Section": data.get("Section") or student_doc.get("Section"),
                "registered": True,
                "embeddings": normalized_embeddings,
            }

            if save_face_data(student_id, update_fields):
                print(f"✅ Saved normalized embeddings for {student_id} → {list(normalized_embeddings.keys())}")
            else:
                print(f"⚠️ Failed to save embeddings for {student_id}")

        else:
            warning_msg = hf_result.get("warning") or hf_result.get("error") or "No embeddings returned"
            print(f"⚠️ HF warning for {student_id}: {warning_msg}")
            return jsonify({
                "success": False,
                "warning": warning_msg,
                "angle": hf_result.get("angle", "unknown")
            }), 200

        return jsonify(hf_result), 200

    except requests.exceptions.Timeout:
        print("⏱️ Timeout contacting Hugging Face.")
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

        excluded_ids = ["23-1-1-0520", "22-1-1-0558", "23-1-1-0052"]  # Replace with correct IDs
        print(f"🧩 Excluding these student IDs from recognition: {excluded_ids}")

        for s in all_students:
            student_id = s.get("student_id")

            # Skip excluded IDs
            if student_id in excluded_ids:
                print(f"⏭️ Skipping excluded student ID: {student_id}")
                continue

            embeddings = s.get("embeddings", {})
            for angle, vector in embeddings.items():
                if vector and isinstance(vector, list):
                    registered_faces.append({
                        "user_id": student_id,
                        "embedding": vector,
                        "angle": angle
                    })

        if not registered_faces:
            print("⚠️ No registered faces found in DB after filtering.")
            return jsonify({"error": "No registered faces found"}), 400

        # 🔗 Send image + embeddings to Hugging Face AI microservice
        payload = {
            "image": base64_image,
            "registered_faces": registered_faces
        }

        res = requests.post(f"{HF_AI_URL}/recognize", json=payload, timeout=90)
        if res.status_code != 200:
            print(f"❌ HF recognize error {res.status_code}: {res.text}")
            return jsonify({"error": "Hugging Face service error"}), res.status_code

        hf_result = res.json()

        # ⚠️ Recognition failed
        if not hf_result.get("success"):
            print(f"🚫 Recognition failed: {hf_result}")
            return jsonify({
                "error": hf_result.get("error", "Face not recognized"),
                "match_score": hf_result.get("match_score"),
                "anti_spoof_confidence": hf_result.get("anti_spoof_confidence")
            }), 400

        # ✅ Successful match → fetch student
        student_id = hf_result.get("student_id")
        raw_student = get_student_by_id(student_id)
        if not raw_student:
            print(f"⚠️ Student {student_id} not found in DB.")
            return jsonify({"error": "Student not found"}), 404

        student = normalize_student(raw_student)

        # 🎟️ Generate JWT token (12-hour validity)
        token = create_access_token(
            identity=student.get("student_id"),
            expires_delta=timedelta(hours=12)
        )

        print(
            f"✅ Face matched: {student_id} | "
            f"Score={hf_result.get('match_score'):.4f} | "
            f"AntiSpoof={hf_result.get('anti_spoof_confidence'):.2f}"
        )

        return jsonify({
            "token": token,
            "student": {
                "student_id": student.get("student_id", ""),
                "first_name": student.get("first_name", ""),
                "last_name": student.get("last_name", ""),
                "course": student.get("course", ""),
                "section": student.get("section", "")
            },
            "match_score": hf_result.get("match_score"),
            "anti_spoof_confidence": hf_result.get("anti_spoof_confidence"),
        }), 200

    except Exception as e:
        import traceback
        print("❌ /login error:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500


# ---------------------------
# Get All Registered Faces
# ---------------------------
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

# ---------------------------
# Public API for Attendance App
# ---------------------------
@face_bp.route("/api/faces", methods=["GET"])
def get_all_faces():
    """Return all registered student embeddings"""
    faces = load_registered_faces()
    return jsonify(faces), 200

@face_bp.route("/api/student/<student_id>", methods=["GET"])
def get_student(student_id):
    """Return specific student by ID"""
    student = get_student_by_id(student_id)
    if not student:
        return jsonify({"error": "Student not found"}), 404

    normalized = {
        "student_id": student.get("student_id"),
        "first_name": student.get("first_name") or student.get("First_Name"),
        "last_name": student.get("last_name") or student.get("Last_Name"),
        "course": student.get("course") or student.get("Course"),
        "section": student.get("section") or student.get("Section"),
    }
    return jsonify(normalized), 200


from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
import requests
import numpy as np
from config.db_config import db
from concurrent.futures import ThreadPoolExecutor
from flask_jwt_extended import create_access_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from models.face_db_model import save_face_data, get_student_by_id, normalize_student, load_registered_faces

# ============================================================
# 🧩 CONFIGURATION
# ============================================================
face_bp = Blueprint("face_bp", __name__)
executor = ThreadPoolExecutor(max_workers=4)
limiter = Limiter(key_func=get_remote_address, default_limits=[])

# 🔗 Hugging Face microservice endpoint
HF_AI_URL = "https://meuorii-face-recognition-attendance.hf.space"
students_collection = db["students"]

# ============================================================
# 🧠 REGISTER FACE (Hugging Face)
# ============================================================
@face_bp.route("/register-auto", methods=["POST"])
def register_auto():
    import time
    start_time = time.time()

    try:
        data = request.get_json(silent=True) or {}
        student_id = data.get("student_id")
        if not student_id or not data.get("image"):
            return jsonify({"success": False, "error": "Missing student_id or image"}), 400

        # -------------------------------
        # 1️⃣ Call Hugging Face service
        # -------------------------------
        hf_start = time.time()
        res = requests.post(f"{HF_AI_URL}/register-auto", json=data, timeout=60)
        hf_elapsed = time.time() - hf_start
        print(f"⏱️ HF_AI_URL latency = {hf_elapsed:.2f}s")

        if res.status_code != 200:
            print(f"⚠️ HF service returned {res.status_code}: {res.text}")
            return jsonify({"success": False, "error": "Hugging Face service error"}), res.status_code

        hf_result = res.json()
        if not hf_result.get("success") or not hf_result.get("embeddings"):
            warning_msg = hf_result.get("warning") or hf_result.get("error") or "No embeddings returned"
            print(f"⚠️ HF warning for {student_id}: {warning_msg}")
            return jsonify({
                "success": False,
                "warning": warning_msg,
                "angle": hf_result.get("angle", "unknown")
            }), 200

        # -------------------------------
        # 2️⃣ Normalize embeddings
        # -------------------------------
        raw_embeddings = hf_result["embeddings"]
        normalized_embeddings = {}
        for angle, vec in raw_embeddings.items():
            v = np.array(vec, dtype=np.float32)
            norm = np.linalg.norm(v)
            if norm == 0:
                continue
            normalized_embeddings[angle] = (v / norm).tolist()

        # -------------------------------
        # 3️⃣ Upsert student (1 Mongo op)
        # -------------------------------
        mongo_start = time.time()
        student_doc = students_collection.find_one_and_update(
            {"student_id": student_id},
            {
                "$setOnInsert": {
                    "student_id": student_id,
                    "First_Name": data.get("First_Name"),
                    "Last_Name": data.get("Last_Name"),
                    "Course": data.get("Course"),
                    "Email": data.get("Email"),
                    "Contact_Number": data.get("Contact_Number"),
                    "Subjects": data.get("Subjects", []),
                    "registered": False,
                    "created_at": datetime.utcnow()
                }
            },
            upsert=True,
            return_document=True
        )

        # Prepare updated fields
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
            "updated_at": datetime.utcnow()
        }

        # -------------------------------
        # 4️⃣ Async save to DB (non-blocking)
        # -------------------------------
        executor.submit(save_face_data, student_id, update_fields)
        print(f"🧵 Async save queued for {student_id} ({list(normalized_embeddings.keys())})")

        mongo_elapsed = time.time() - mongo_start
        total_elapsed = time.time() - start_time
        print(f"✅ /register-auto {student_id} → done in {total_elapsed:.2f}s "
              f"(HF={hf_elapsed:.2f}s | MongoQueue={mongo_elapsed:.2f}s)")

        # Respond immediately
        return jsonify({
            "success": True,
            "student_id": student_id,
            "angle": hf_result.get("angle", "unknown"),
            "message": "Registration data queued for saving.",
        }), 200

    except requests.exceptions.Timeout:
        print("⏱️ Timeout contacting Hugging Face.")
        return jsonify({"success": False, "error": "AI service timeout"}), 504
    except Exception as e:
        import traceback
        print("❌ /register-auto error:", str(e))
        print(traceback.format_exc())
        return jsonify({"success": False, "error": f"Internal server error: {str(e)}"}), 500


# ============================================================
# 🔐 FACE LOGIN (Hugging Face)
# ============================================================
@face_bp.route("/login", methods=["POST"])
def face_login():
    """Authenticate student using Hugging Face recognition API."""
    try:
        data = request.get_json(silent=True) or {}
        base64_image = data.get("image")
        if not base64_image:
            return jsonify({"error": "Missing image"}), 400

        registered_faces = []
        all_students = load_registered_faces()

        # Excluded student IDs (for testing or safety)
        excluded_ids = ["23-1-1-0520", "22-1-1-0558", "23-1-1-0052"]
        print(f"🧩 Excluding student IDs: {excluded_ids}")

        for s in all_students:
            sid = s.get("student_id")
            if sid in excluded_ids:
                continue
            embeddings = s.get("embeddings", {})
            for angle, vector in embeddings.items():
                if isinstance(vector, list) and vector:
                    registered_faces.append({
                        "user_id": sid,
                        "embedding": vector,
                        "angle": angle
                    })

        if not registered_faces:
            print("⚠️ No registered faces found in DB after filtering.")
            return jsonify({"error": "No registered faces found"}), 400

        # 🔗 Send image + embeddings to Hugging Face
        payload = {"image": base64_image, "registered_faces": registered_faces}
        res = requests.post(f"{HF_AI_URL}/recognize", json=payload, timeout=90)
        if res.status_code != 200:
            return jsonify({"error": "Hugging Face service error"}), res.status_code

        hf_result = res.json()

        # 🚫 Recognition failed
        if not hf_result.get("success"):
            return jsonify({
                "error": hf_result.get("error", "Face not recognized"),
                "match_score": hf_result.get("match_score"),
                "anti_spoof_confidence": hf_result.get("anti_spoof_confidence")
            }), 400

        # ✅ Successful match
        sid = hf_result.get("student_id")
        raw_student = get_student_by_id(sid)
        if not raw_student:
            return jsonify({"error": "Student not found"}), 404

        student = normalize_student(raw_student)

        # 🎟️ Generate JWT token (12-hour validity)
        token = create_access_token(
            identity=student.get("student_id"),
            expires_delta=timedelta(hours=12)
        )

        print(f"✅ Match: {sid} | Score={hf_result.get('match_score'):.4f} | AntiSpoof={hf_result.get('anti_spoof_confidence'):.2f}")

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
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# ============================================================
# 🌐 PUBLIC API (for Attendance App)
# ============================================================
@face_bp.route("/api/faces", methods=["GET"])
def get_all_faces():
    """Return all registered student embeddings."""
    faces = load_registered_faces()
    return jsonify(faces or []), 200


@face_bp.route("/api/student/<student_id>", methods=["GET"])
def get_student(student_id):
    """Return specific student by ID."""
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

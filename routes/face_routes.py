from flask import Blueprint, jsonify, request, current_app
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

def cache_registered_faces():
    """Cache all registered embeddings in memory for faster login."""
    all_students = load_registered_faces()
    current_app.config["CACHED_FACES"] = [
        {"user_id": s["student_id"], "embedding": vec, "angle": angle}
        for s in all_students
        for angle, vec in s.get("embeddings", {}).items()
        if isinstance(vec, list) and vec
    ]
    print(f"🧠 Cached {len(current_app.config['CACHED_FACES'])} embeddings in memory.")
    
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
    """Authenticate student using Hugging Face recognition API (cached + faster)."""
    import time
    start_time = time.time()

    try:
        data = request.get_json(silent=True) or {}
        base64_image = data.get("image")
        if not base64_image:
            return jsonify({"error": "Missing image"}), 400

        # =====================================================
        # 🧠 Use in-memory cache of embeddings if available
        # =====================================================
        registered_faces = current_app.config.get("CACHED_FACES")

        if not registered_faces:
            print("⚠️ No cached faces found — loading from MongoDB...")
            load_start = time.time()
            all_students = load_registered_faces()
            registered_faces = [
                {"user_id": s["student_id"], "embedding": vec, "angle": angle}
                for s in all_students
                for angle, vec in s.get("embeddings", {}).items()
                if isinstance(vec, list) and vec
            ]
            current_app.config["CACHED_FACES"] = registered_faces
            print(f"🧠 Cached {len(registered_faces)} embeddings "
                  f"in {time.time() - load_start:.2f}s")

        # =====================================================
        # 🚫 Exclude testing IDs
        # =====================================================
        excluded_ids = {"23-1-1-0520", "22-1-1-0558", "23-1-1-0052"}
        filtered_faces = [f for f in registered_faces if f["user_id"] not in excluded_ids]

        if not filtered_faces:
            return jsonify({"error": "No registered faces found"}), 400

        # =====================================================
        # 🔗 Send image + embeddings to Hugging Face
        # =====================================================
        payload = {"image": base64_image, "registered_faces": filtered_faces}

        hf_start = time.time()
        res = requests.post(f"{HF_AI_URL}/recognize", json=payload, timeout=60)
        hf_elapsed = time.time() - hf_start
        print(f"⏱️ HF recognize latency = {hf_elapsed:.2f}s "
              f"for {len(filtered_faces)} embeddings")

        if res.status_code != 200:
            return jsonify({"error": "Hugging Face service error"}), res.status_code

        hf_result = res.json()

        # 🚫 Recognition failed
        if not hf_result.get("success"):
            print(f"🚫 Recognition failed: {hf_result.get('error', 'Unknown')}")
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

        total_elapsed = time.time() - start_time
        print(f"✅ Match: {sid} | Score={hf_result.get('match_score'):.4f} | "
              f"AntiSpoof={hf_result.get('anti_spoof_confidence'):.2f} "
              f"| Total={total_elapsed:.2f}s")

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

    except requests.exceptions.Timeout:
        print("⏱️ Timeout contacting Hugging Face.")
        return jsonify({"error": "AI service timeout"}), 504
    except Exception as e:
        import traceback
        print("❌ /login error:", str(e))
        print(traceback.format_exc())
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

# ============================================================
# 🌐 PUBLIC API (for Attendance App)
# ============================================================
@face_bp.route("/api/faces", methods=["GET"])
def get_all_faces():
    """Return all registered student embeddings from students collection."""
    try:
        students_collection = db["students"]
        faces = []

        # 🔍 Find only students that have embeddings
        for s in students_collection.find({"embeddings": {"$exists": True, "$ne": {}}}):
            faces.append({
                "student_id": s.get("student_id"),
                "first_name": s.get("first_name") or s.get("First_Name"),
                "last_name": s.get("last_name") or s.get("Last_Name"),
                "embeddings": s.get("embeddings", {})
            })

        if not faces:
            print("⚠️ No registered student embeddings found in database.")
            return jsonify({"error": "No registered student embeddings found"}), 404

        print(f"✅ Loaded {len(faces)} registered student embeddings.")
        return jsonify(faces), 200

    except Exception as e:
        import traceback
        print("❌ Error in /api/faces:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500



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

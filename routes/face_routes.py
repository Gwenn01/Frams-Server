from flask import Blueprint, jsonify, request, current_app
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from flask_jwt_extended import create_access_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import ReturnDocument
import numpy as np
import requests
import time
import traceback
from bson import ObjectId

from config.db_config import db
from models.face_db_model import (
    save_face_data,
    get_student_by_id,
    normalize_student,
    load_registered_faces,
    save_face_data_for_instructor
)
from models.attendance_model import log_attendance as log_attendance_model, already_logged_today

# ============================================================
# 🧩 CONFIGURATION
# ============================================================
face_bp = Blueprint("face_bp", __name__)
executor = ThreadPoolExecutor(max_workers=4)
limiter = Limiter(key_func=get_remote_address, default_limits=[])

# 🔗 Hugging Face microservice endpoint
HF_AI_URL = "https://meuorii-face-recognition-attendance.hf.space"
students_collection = db["students"]
classes_collection = db["classes"]
attendance_collection = db["attendance_logs"]

# 🌏 Philippine timezone
PH_TZ = timezone(timedelta(hours=8))
CACHE_TTL = 300  # 5 minutes


# ============================================================
# 🧠 Helper: Cache Management
# ============================================================
def refresh_face_cache(excluded_ids=None):
    """Reload embeddings from MongoDB and store in cache."""
    excluded_ids = excluded_ids or set()
    current_app.logger.info("♻️ Refreshing face embeddings cache from MongoDB...")
    all_students = load_registered_faces()
    registered_faces = [
        {"user_id": s["student_id"], "embedding": vec, "angle": angle}
        for s in all_students
        if s.get("student_id") not in excluded_ids
        for angle, vec in s.get("embeddings", {}).items()
        if isinstance(vec, list) and vec
    ]
    current_app.config["CACHED_FACES"] = registered_faces
    current_app.config["CACHED_FACES_LAST_UPDATE"] = time.time()
    current_app.logger.info(f"✅ Cache refreshed with {len(registered_faces)} embeddings.")
    return registered_faces


def get_cached_faces(excluded_ids=None):
    """Return cached embeddings or refresh if expired."""
    registered_faces = current_app.config.get("CACHED_FACES")
    last_update = current_app.config.get("CACHED_FACES_LAST_UPDATE", 0)
    cache_age = time.time() - last_update

    if not registered_faces or cache_age > CACHE_TTL:
        return refresh_face_cache(excluded_ids)
    return registered_faces

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
    start_time = time.time()
    try:
        data = request.get_json(silent=True) or {}
        student_id = data.get("student_id")

        # ✅ Validate input
        if not student_id or not data.get("image"):
            return jsonify({
                "success": False,
                "error": "Missing student_id or image"
            }), 400

        # ✅ Extract and normalize Course early
        course = (data.get("Course") or data.get("course") or "").strip().upper() or "UNKNOWN"
        data["course"] = course  # ✅ make sure course stays in payload
        current_app.logger.info(f"📘 Preserved course for {student_id}: {course}")

        # 1️⃣ Call Hugging Face microservice
        hf_start = time.time()
        res = requests.post(f"{HF_AI_URL}/register-auto", json=data, timeout=60)
        hf_elapsed = time.time() - hf_start

        if res.status_code != 200:
            current_app.logger.warning(f"⚠️ HF service error {res.status_code}: {res.text}")
            return jsonify({
                "success": False,
                "error": "Hugging Face service error"
            }), res.status_code

        hf_result = res.json()
        if not hf_result.get("success") or not hf_result.get("embeddings"):
            warning_msg = (
                hf_result.get("warning") or
                hf_result.get("error") or
                "No embeddings returned"
            )
            return jsonify({
                "success": False,
                "warning": warning_msg,
                "angle": hf_result.get("angle", "unknown"),
            }), 200

        # 2️⃣ Normalize embeddings
        normalized_embeddings = {}
        for angle, vec in hf_result["embeddings"].items():
            v = np.array(vec, dtype=np.float32)
            norm = np.linalg.norm(v)
            if norm > 0:
                normalized_embeddings[angle] = (v / norm).tolist()

        # 3️⃣ Upsert student record (ReturnDocument.AFTER ensures new doc)
        student_doc = students_collection.find_one_and_update(
            {"student_id": student_id},
            {
                "$setOnInsert": {
                    "student_id": student_id,
                    "First_Name": data.get("First_Name"),
                    "Middle_Name": data.get("Middle_Name"),
                    "Last_Name": data.get("Last_Name"),
                    "Suffix": data.get("Suffix"),
                    "Course": course,
                    "registered": False,
                    "created_at": datetime.utcnow(),
                }
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,  # ✅ ensures updated doc is returned
        )

        # 4️⃣ Prepare update fields for async save
        update_fields = {
            "student_id": student_id,
            "First_Name": data.get("First_Name") or student_doc.get("First_Name"),
            "Middle_Name": data.get("Middle_Name") or student_doc.get("Middle_Name"),
            "Last_Name": data.get("Last_Name") or student_doc.get("Last_Name"),
            "Suffix": data.get("Suffix") or student_doc.get("Suffix"),
            "Course": course,
            "registered": True,
            "embeddings": normalized_embeddings,
            "updated_at": datetime.utcnow(),
        }

        # ✅ Ensure Course consistency in DB
        students_collection.update_one(
            {"student_id": student_id},
            {"$set": {"Course": course}}
        )

        # ✅ Save asynchronously
        executor.submit(save_face_data, student_id, update_fields)

        total_elapsed = time.time() - start_time
        current_app.logger.info(
            f"✅ /register-auto {student_id} done in {total_elapsed:.2f}s (HF={hf_elapsed:.2f}s)"
        )

        return jsonify({
            "success": True,
            "student_id": student_id,
            "Course": course,
            "angle": hf_result.get("angle", "unknown"),
            "message": "Registration successful and saved.",
        }), 200

    except requests.exceptions.Timeout:
        return jsonify({
            "success": False,
            "error": "AI service timeout"
        }), 504

    except Exception as e:
        current_app.logger.error(
            f"❌ /register-auto error: {str(e)}\n{traceback.format_exc()}"
        )
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

# ============================================================
# 🔐 FACE LOGIN
# ============================================================
@face_bp.route("/login", methods=["POST"])
def face_login():
    """Authenticate student using Hugging Face recognition API."""
    start_time = time.time()
    try:
        data = request.get_json(silent=True) or {}
        base64_image = data.get("image")
        if not base64_image:
            return jsonify({"error": "Missing image"}), 400

        EXCLUDED_IDS = {"23-1-1-0520", "22-1-1-0558", "23-1-1-0052"}
        registered_faces = get_cached_faces(EXCLUDED_IDS)

        # 🔗 Send to Hugging Face
        payload = {"image": base64_image, "registered_faces": registered_faces}
        res = requests.post(f"{HF_AI_URL}/recognize", json=payload, timeout=60)

        if res.status_code != 200:
            return jsonify({"error": "Hugging Face service error"}), res.status_code

        hf_result = res.json()
        if not hf_result.get("success"):
            return jsonify({
                "error": hf_result.get("error", "Face not recognized"),
                "match_score": hf_result.get("match_score"),
                "anti_spoof_confidence": hf_result.get("anti_spoof_confidence"),
            }), 400

        sid = hf_result.get("student_id")
        raw_student = get_student_by_id(sid)
        if not raw_student:
            refresh_face_cache(EXCLUDED_IDS)
            raw_student = get_student_by_id(sid)
            if not raw_student:
                return jsonify({"error": "Student not found"}), 404

        student = normalize_student(raw_student)
        token = create_access_token(identity=student.get("student_id"), expires_delta=timedelta(hours=12))

        total_elapsed = time.time() - start_time
        current_app.logger.info(
            f"✅ Match: {sid} | Score={hf_result.get('match_score'):.4f} | "
            f"AntiSpoof={hf_result.get('anti_spoof_confidence'):.2f} | Total={total_elapsed:.2f}s"
        )

        return jsonify({
            "token": token,
            "student": student,
            "match_score": hf_result.get("match_score"),
            "anti_spoof_confidence": hf_result.get("anti_spoof_confidence"),
        }), 200

    except Exception as e:
        current_app.logger.error(f"❌ /login error: {traceback.format_exc()}")
        return jsonify({"error": "Internal server error"}), 500

@face_bp.route("/register-instructor", methods=["POST"])
def register_instructor():
    start_time = time.time()
    try:
        data = request.get_json(silent=True) or {}
        instructor_id = data.get("instructor_id")  # Expecting instructor_id

        # ✅ Validate input
        if not instructor_id or not data.get("image"):
            return jsonify({
                "success": False,
                "error": "Missing instructor_id or image"
            }), 400

        # 1️⃣ Call Hugging Face microservice for face recognition
        hf_start = time.time()
        res = requests.post(f"{HF_AI_URL}/register-instructor", json=data, timeout=60)
        hf_elapsed = time.time() - hf_start

        if res.status_code != 200:
            current_app.logger.warning(f"⚠️ HF service error {res.status_code}: {res.text}")
            return jsonify({
                "success": False,
                "error": "Hugging Face service error"
            }), res.status_code

        hf_result = res.json()
        if not hf_result.get("success") or not hf_result.get("embeddings"):
            warning_msg = (
                hf_result.get("warning") or
                hf_result.get("error") or
                "No embeddings returned"
            )
            return jsonify({
                "success": False,
                "warning": warning_msg,
                "angle": hf_result.get("angle", "unknown"),
            }), 200

        # 2️⃣ Normalize embeddings
        normalized_embeddings = {}
        for angle, vec in hf_result["embeddings"].items():
            v = np.array(vec, dtype=np.float32)
            norm = np.linalg.norm(v)
            if norm > 0:
                normalized_embeddings[angle] = (v / norm).tolist()

        # 3️⃣ Prepare update fields for async save (remove Course for instructors)
        update_fields = {
            "instructor_id": instructor_id,
            "First_Name": data.get("First_Name"),
            "Middle_Name": data.get("Middle_Name"),
            "Last_Name": data.get("Last_Name"),
            "Suffix": data.get("Suffix"),
            "registered": True,  # Mark instructor as registered
            "embeddings": normalized_embeddings,  # Store embeddings for each angle
            "updated_at": datetime.utcnow(),
        }

        # 4️⃣ Save the face data (embeddings) for the instructor in MongoDB
        save_face_data_for_instructor(instructor_id, update_fields)

        total_elapsed = time.time() - start_time
        current_app.logger.info(
            f"✅ /register-instructor {instructor_id} done in {total_elapsed:.2f}s (HF={hf_elapsed:.2f}s)"
        )

        return jsonify({
            "success": True,
            "instructor_id": instructor_id,
            "angle": hf_result.get("angle", "unknown"),
            "message": "Registration successful and saved.",
        }), 200

    except requests.exceptions.Timeout:
        return jsonify({
            "success": False,
            "error": "AI service timeout"
        }), 504

    except Exception as e:
        current_app.logger.error(
            f"❌ /register-instructor error: {str(e)}\n{traceback.format_exc()}"
        )
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

# ============================================================
# 🌐 MULTI-FACE ATTENDANCE
# ============================================================
@face_bp.route("/multi-recognize", methods=["POST"])
def multi_face_recognize():
    """Detect multiple faces, log new ones, and return updated attendance list."""
    start_time = time.time()

    try:
        data = request.get_json(silent=True) or {}
        faces = data.get("faces", [])
        class_id = data.get("class_id")

        if not faces or not class_id:
            return jsonify({"error": "Missing faces or class_id"}), 400

        # Load class
        cls = classes_collection.find_one({"_id": ObjectId(class_id)})
        if not cls:
            return jsonify({"error": "Class not found"}), 404

        # Use today's date
        today_str = datetime.now(PH_TZ).strftime("%Y-%m-%d")

        # ------------- FIX #1 (CRITICAL) -------------
        # NEVER create attendance log here
        today_log = attendance_collection.find_one(
            {"class_id": class_id, "date": today_str}
        )

        if not today_log:
            return jsonify({
                "error": "Attendance session not started",
                "details": "Call /start-session first"
            }), 400
        # ---------------------------------------------

        # Call HuggingFace recognize API
        registered_faces = get_cached_faces(class_id)
        payload = {"faces": faces, "registered_faces": registered_faces}

        res = requests.post(f"{HF_AI_URL}/recognize-multi", json=payload, timeout=90)
        if res.status_code != 200:
            return jsonify({"error": "AI service error"}), res.status_code

        recognized = res.json().get("recognized", [])

        # Process student detections
        detected_ids = {f.get("student_id") for f in recognized if f.get("student_id")}

        existing_students = {s["student_id"] for s in today_log.get("students", [])}
        new_entries = []
        now_dt = datetime.now(PH_TZ)

        for face in recognized:
            sid = face.get("student_id")
            if not sid or sid in existing_students:
                continue

            student = get_student_by_id(sid)
            if not student:
                continue

            # Determine Present/Late
            attendance_start = cls.get("attendance_start_time")
            if attendance_start:
                try:
                    start_dt = datetime.fromisoformat(str(attendance_start).replace("Z", "+00:00"))
                    diff_minutes = (now_dt - start_dt).total_seconds() / 60
                    status = "Late" if diff_minutes > 15 else "Present"
                except:
                    status = "Present"
            else:
                status = "Present"

            new_entries.append({
                "student_id": sid,
                "first_name": student.get("first_name") or student.get("First_Name", ""),
                "last_name": student.get("last_name") or student.get("Last_Name", ""),
                "status": status,
                "time": now_dt.strftime("%H:%M:%S"),
                "time_logged": now_dt.isoformat()
            })

            existing_students.add(sid)

        # Insert new entries only
        if new_entries:
            attendance_collection.update_one(
                {"class_id": class_id, "date": today_str},
                {"$push": {"students": {"$each": new_entries}}}
            )

        # Reload updated log
        updated_log = attendance_collection.find_one(
            {"class_id": class_id, "date": today_str},
            {"students": 1}
        )

        final_results = []

        for s in updated_log.get("students", []):
            entry = {
                "student_id": s["student_id"],
                "first_name": s["first_name"],
                "last_name": s["last_name"],
                "status": s["status"],
                "time": s.get("time"),
                "time_logged": s.get("time_logged"),
                "bbox": None
            }

            # Attach bbox if visible in this frame
            for face in recognized:
                if face.get("student_id") == s["student_id"]:
                    entry["bbox"] = face.get("bbox")
                    break

            final_results.append(entry)

        duration = time.time() - start_time
        current_app.logger.info(
            f"🔥 Multi-face processed {len(final_results)} logs in {duration:.2f}s"
        )

        return jsonify({
            "success": True,
            "logged": final_results,
            "count": len(final_results),
        }), 200

    except Exception as e:
        current_app.logger.error(f"❌ /multi-recognize error: {traceback.format_exc()}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500



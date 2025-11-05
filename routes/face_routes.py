from flask import Blueprint, jsonify, request, current_app
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from flask_jwt_extended import create_access_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
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
        if not student_id or not data.get("image"):
            return jsonify({"success": False, "error": "Missing student_id or image"}), 400

        # 1️⃣ Call Hugging Face
        hf_start = time.time()
        res = requests.post(f"{HF_AI_URL}/register-auto", json=data, timeout=60)
        hf_elapsed = time.time() - hf_start

        if res.status_code != 200:
            current_app.logger.warning(f"⚠️ HF service error {res.status_code}: {res.text}")
            return jsonify({"success": False, "error": "Hugging Face service error"}), res.status_code

        hf_result = res.json()
        if not hf_result.get("success") or not hf_result.get("embeddings"):
            warning_msg = hf_result.get("warning") or hf_result.get("error") or "No embeddings returned"
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

        # 3️⃣ Upsert student
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
                    "created_at": datetime.utcnow(),
                }
            },
            upsert=True,
            return_document=True,
        )

        update_fields = {
            "student_id": student_id,
            "First_Name": data.get("First_Name") or student_doc.get("First_Name"),
            "Last_Name": data.get("Last_Name") or student_doc.get("Last_Name"),
            "Course": data.get("Course") or student_doc.get("Course"),
            "Section": data.get("Section") or student_doc.get("Section"),
            "Email": data.get("Email") or student_doc.get("Email"),
            "Contact_Number": data.get("Contact_Number") or student_doc.get("Contact_Number"),
            "Subjects": data.get("Subjects") or student_doc.get("Subjects"),
            "registered": True,
            "embeddings": normalized_embeddings,
            "updated_at": datetime.utcnow(),
        }

        executor.submit(save_face_data, student_id, update_fields)

        total_elapsed = time.time() - start_time
        current_app.logger.info(
            f"✅ /register-auto {student_id} done in {total_elapsed:.2f}s "
            f"(HF={hf_elapsed:.2f}s)"
        )

        return jsonify({
            "success": True,
            "student_id": student_id,
            "angle": hf_result.get("angle", "unknown"),
            "message": "Registration successful and saved.",
        }), 200

    except requests.exceptions.Timeout:
        return jsonify({"success": False, "error": "AI service timeout"}), 504
    except Exception as e:
        current_app.logger.error(f"❌ /register-auto error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": "Internal server error"}), 500


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


# ============================================================
# 🌐 MULTI-FACE ATTENDANCE
# ============================================================
@face_bp.route("/multi-recognize", methods=["POST"])
def multi_face_recognize():
    """Detect multiple faces, recognize them, and log attendance."""
    start_time = time.time()
    try:
        data = request.get_json(silent=True) or {}
        faces = data.get("faces", [])
        class_id = data.get("class_id")

        if not faces or not class_id:
            return jsonify({"error": "Missing faces or class_id"}), 400

        # 🔹 Call external AI recognition API
        registered_faces = get_cached_faces()
        payload = {"faces": faces, "registered_faces": registered_faces}
        res = requests.post(f"{HF_AI_URL}/recognize-multi", json=payload, timeout=90)

        if res.status_code != 200:
            return jsonify({"error": "AI service error"}), res.status_code

        hf_result = res.json()
        recognized = hf_result.get("recognized", [])
        if not recognized:
            return jsonify({"message": "No faces recognized"}), 200

        # 🔹 Get class info
        cls = classes_collection.find_one({"_id": ObjectId(class_id)})
        if not cls:
            return jsonify({"error": "Class not found"}), 404

        # 🧩 Build class data (with full schema matching 'classes')
        class_data = {
            "class_id": str(cls["_id"]),
            "subject_code": cls.get("subject_code", ""),
            "subject_title": cls.get("subject_title", ""),
            "course": cls.get("course", ""),
            "section": cls.get("section", ""),
            "year_level": cls.get("year_level", ""),
            "semester": cls.get("semester", ""),
            "instructor_id": cls.get("instructor_id", ""),
            "instructor_first_name": cls.get("instructor_first_name", "Unknown"),
            "instructor_last_name": cls.get("instructor_last_name", "Unknown"),
            "attendance_start_time": cls.get("attendance_start_time", ""),
            "attendance_end_time": cls.get("attendance_end_time", ""),
            "is_attendance_active": cls.get("is_attendance_active", False),
            "activated_by": cls.get("activated_by", ""),
            "date": date_val.strftime("%Y-%m-%d"),
        }


        date_val = datetime.now(PH_TZ)
        results = []

        for face in recognized:
            sid = face.get("student_id")
            if not sid:
                continue

            # 🔎 Fetch student data
            raw_student = get_student_by_id(sid)
            if not raw_student:
                continue

            student_data = {
                "student_id": raw_student.get("student_id"),
                "first_name": raw_student.get("first_name")
                or raw_student.get("First_Name", ""),
                "last_name": raw_student.get("last_name")
                or raw_student.get("Last_Name", ""),
            }

            # ✅ Check if already logged
            if already_logged_today(sid, class_id, date_val):
                # 🔍 Fetch existing log to display real status (not "AlreadyMarked")
                existing_log = attendance_collection.find_one(
                    {
                        "class_id": class_id,
                        "students.student_id": sid,
                        "date": {
                            "$gte": date_val.replace(hour=0, minute=0, second=0),
                            "$lt": date_val.replace(hour=23, minute=59, second=59),
                        },
                    },
                    {"students.$": 1}
                )

                existing_status = (
                    existing_log["students"][0]["status"]
                    if existing_log and "students" in existing_log
                    else "Present"
                )

                results.append({
                    "student_id": sid,
                    "first_name": student_data["first_name"],
                    "last_name": student_data["last_name"],
                    "status": existing_status,  # 👈 Use actual recorded status
                    "time": datetime.now(PH_TZ).strftime("%I:%M %p"),
                    "subject_code": class_data["subject_code"],
                    "subject_title": class_data["subject_title"],
                    "course": class_data["course"],
                    "section": class_data["section"],
                    "instructor_first_name": class_data["instructor_first_name"],
                    "instructor_last_name": class_data["instructor_last_name"],
                })
                continue

           # 🕒 Detect if student is late (10+ minutes after start)
            attendance_start_time = cls.get("attendance_start_time")
            if attendance_start_time:
                try:
                    # Convert to datetime safely (handles timezone format)
                    start_time = datetime.fromisoformat(str(attendance_start_time).replace("Z", "+00:00"))
                    diff_minutes = (date_val - start_time).total_seconds() / 60.0
                    status = "Late" if diff_minutes > 10 else "Present"
                except Exception as e:
                    current_app.logger.warning(f"⚠️ Time parse error: {e}")
                    status = "Present"
            else:
                status = "Present"

            # 📝 Log attendance normally
            log_res = log_attendance_model(
                class_data=class_data,
                student_data=student_data,
                date_val=date_val,
                class_start_time=cls.get("attendance_start_time"),
            )


            if log_res:
                log_res["status"] = status
                results.append({
                    "student_id": sid,
                    "first_name": student_data["first_name"],
                    "last_name": student_data["last_name"],
                    "status": log_res["status"],
                    "time": datetime.now(PH_TZ).strftime("%I:%M %p"),
                    "subject_code": class_data["subject_code"],
                    "subject_title": class_data["subject_title"],
                    "course": class_data["course"],
                    "section": class_data["section"],
                    "instructor_first_name": class_data["instructor_first_name"],
                    "instructor_last_name": class_data["instructor_last_name"],
                    "bbox": face.get("bbox"),
                })

        duration = time.time() - start_time
        current_app.logger.info(
            f"✅ Multi-face logged {len(results)} students in {duration:.2f}s"
        )

        return jsonify({
            "success": True,
            "logged": results,
            "count": len(results),
            "subject_code": class_data["subject_code"],
            "subject_title": class_data["subject_title"],
            "course": class_data["course"],
            "section": class_data["section"],
            "instructor_first_name": class_data["instructor_first_name"],
            "instructor_last_name": class_data["instructor_last_name"],
        }), 200

    except Exception as e:
        current_app.logger.error(f"❌ /multi-recognize error: {traceback.format_exc()}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


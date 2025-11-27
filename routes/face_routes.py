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
instructors_collection = db['instructors']

# 🌏 Philippine timezone
PH_TZ = timezone(timedelta(hours=8))
CACHE_TTL = 300  # 5 minutes

SESSION_INSTRUCTOR_DETECTED = {}
SESSION_LOGGED_STUDENTS = {}

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

def get_cached_faces(class_id):
    """
    Load embeddings for:
      ✅ Students enrolled in the class
      ✅ Instructor assigned to the class
    Output format (HF expected):
       { user_id, embedding, angle, is_instructor }
    """
    cls = classes_collection.find_one({"_id": ObjectId(class_id)})
    if not cls:
        print("❌ Class not found for embeddings.")
        return []

    registered = []

    # ------------------------------------------------------
    # 1️⃣ LOAD STUDENTS ENROLLED IN THIS CLASS
    # ------------------------------------------------------
    student_ids = [s["student_id"] for s in cls.get("students", [])]

    if student_ids:
        students = list(students_collection.find(
            {"student_id": {"$in": student_ids}, "embeddings": {"$exists": True}}
        ))

        for s in students:
            sid = s.get("student_id")
            embeddings = s.get("embeddings", {})
            for angle, vec in embeddings.items():
                if isinstance(vec, list) and len(vec) == 512:
                    registered.append({
                        "user_id": sid,
                        "embedding": vec,
                        "angle": angle,
                        "is_instructor": False
                    })

    # ------------------------------------------------------
    # 2️⃣ LOAD INSTRUCTOR EMBEDDINGS
    # ------------------------------------------------------
    instructor_id = cls.get("instructor_id")

    if instructor_id:
        instructor = instructors_collection.find_one(
            {"instructor_id": instructor_id, "embeddings": {"$exists": True}}
        )

        if instructor:
            for angle, vec in instructor.get("embeddings", {}).items():
                if isinstance(vec, list) and len(vec) == 512:
                    registered.append({
                        "user_id": instructor_id,
                        "embedding": vec,
                        "angle": angle,
                        "is_instructor": True
                    })
            print(f"👨‍🏫 Loaded instructor embeddings for: {instructor_id}")
        else:
            print("⚠️ Instructor has no embeddings yet.")

    print(f"🧠 Loaded {len(registered)} embeddings (students + instructor) for class {class_id}")
    return registered

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
# 🌐 MULTI-FACE ATTENDANCE (FINAL VERSION WITH SESSION MEMORY)
# ============================================================
@face_bp.route("/multi-recognize", methods=["POST"])
def multi_face_recognize():
    start_time = time.time()

    try:
        data = request.get_json(silent=True) or {}
        faces = data.get("faces", [])
        class_id = str(data.get("class_id"))

        if not faces or not class_id:
            return jsonify({"error": "Missing faces or class_id"}), 400

        # ------------------------------------------------------
        # 1. LOAD EMBEDDINGS (students + instructor)
        # ------------------------------------------------------
        registered_faces = get_cached_faces(class_id)
        payload = {"faces": faces, "registered_faces": registered_faces}

        if not registered_faces:
            return jsonify({
                "success": False,
                "message": "No registered faces for this class",
                "recognized": [],
                "instructor_detected": False
            }), 200

        # ------------------------------------------------------
        # 2. CALL HF AI
        # ------------------------------------------------------
        res = requests.post(f"{HF_AI_URL}/recognize-multi", json=payload, timeout=90)
        if res.status_code != 200:
            return jsonify({"error": "AI service error"}), res.status_code

        hf_result = res.json()
        recognized = hf_result.get("recognized", [])

        # ------------------------------------------------------
        # 3. FETCH CLASS INFO + ACTIVE LOG ID
        # ------------------------------------------------------
        cls = classes_collection.find_one({"_id": ObjectId(class_id)})
        if not cls:
            return jsonify({"error": "Class not found"}), 404

        log_id = cls.get("active_session_log_id")
        if not log_id:
            return jsonify({"error": "No active attendance log for this class"}), 400

        instructor_id = cls.get("instructor_id")

        # ------------------------------------------------------
        # 4. LOAD ATTENDANCE LOG DOCUMENT
        # ------------------------------------------------------
        att_log = attendance_collection.find_one({"_id": ObjectId(log_id)})
        if not att_log:
            return jsonify({"error": "Attendance log not found"}), 500

        now = datetime.now(PH_TZ)
        today_str = now.strftime("%Y-%m-%d")
        now_time = now.strftime("%H:%M:%S")
        now_nice = now.strftime("%I:%M %p")

        # ------------------------------------------------------
        # 5. INIT SESSION MEMORY (per class)
        # ------------------------------------------------------
        if class_id not in SESSION_INSTRUCTOR_DETECTED:
            SESSION_INSTRUCTOR_DETECTED[class_id] = False

        if class_id not in SESSION_LOGGED_STUDENTS:
            SESSION_LOGGED_STUDENTS[class_id] = {}

        results = []
        instructor_detected = SESSION_INSTRUCTOR_DETECTED[class_id]

        # ------------------------------------------------------
        # 6. WHEN NO RECOGNIZED FACES → KEEP SESSION STATE
        # ------------------------------------------------------
        if not recognized:
            return jsonify({
                "success": True,
                "logged": [],
                "count": 0,
                "instructor_detected": SESSION_INSTRUCTOR_DETECTED[class_id],
                "instructor_id": instructor_id,
                "instructor_first_name": cls.get("instructor_first_name"),
                "instructor_last_name": cls.get("instructor_last_name"),
            }), 200

        # ------------------------------------------------------
        # 7. PROCESS ALL RECOGNIZED FACES
        # ------------------------------------------------------
        for face in recognized:
            user_id = face.get("user_id")
            is_instructor = face.get("is_instructor", False)

            if not user_id:
                continue

            # --- INSTRUCTOR ---
            if is_instructor or user_id == instructor_id:
                SESSION_INSTRUCTOR_DETECTED[class_id] = True
                instructor_detected = True
                continue

            # --- STUDENT ---
            student = get_student_by_id(user_id)
            if not student:
                continue

            student_data = {
                "student_id": student.get("student_id"),
                "first_name": student.get("first_name") or student.get("First_Name", ""),
                "last_name": student.get("last_name") or student.get("Last_Name", "")
            }

            # Already logged in THIS session memory
            if user_id in SESSION_LOGGED_STUDENTS[class_id]:
                prev_status = SESSION_LOGGED_STUDENTS[class_id][user_id]["status"]
                results.append({
                    **student_data,
                    "status": prev_status,
                    "time": now_nice,
                    "bbox": face.get("bbox"),
                })
                continue

            # Already logged in DB? (THIS SPECIFIC LOG)
            existing = attendance_collection.find_one(
                {"_id": ObjectId(log_id), "students.student_id": user_id},
                {"students.$": 1}
            )

            if existing and existing.get("students"):
                existing_status = existing["students"][0]["status"]

                SESSION_LOGGED_STUDENTS[class_id][user_id] = {
                    "status": existing_status
                }

                results.append({
                    **student_data,
                    "status": existing_status,
                    "time": now_nice,
                    "bbox": face.get("bbox"),
                })
                continue

            # NEW STUDENT FOUND → compute status
            class_start = cls.get("attendance_start_time")
            if class_start:
                try:
                    class_start_dt = datetime.fromisoformat(
                        str(class_start).replace("Z", "+00:00")
                    )
                    diff_min = (now - class_start_dt).total_seconds() / 60
                    status = "Late" if diff_min > 15 else "Present"
                except:
                    status = "Present"
            else:
                status = "Present"

            # Update end_time on CORRECT ATTENDANCE LOG
            attendance_collection.update_one(
                {"_id": ObjectId(log_id)},
                {"$set": {"end_time": now_time}}
            )

            # Push student to THIS attendance log
            attendance_collection.update_one(
                {"_id": ObjectId(log_id)},
                {"$push": {
                    "students": {
                        "student_id": student_data["student_id"],
                        "first_name": student_data["first_name"],
                        "last_name": student_data["last_name"],
                        "status": status,
                        "time": now_time,
                    }
                }}
            )

            # Update session memory
            SESSION_LOGGED_STUDENTS[class_id][user_id] = {
                "status": status
            }

            # Add to response
            results.append({
                **student_data,
                "status": status,
                "time": now_nice,
                "bbox": face.get("bbox"),
            })

        # ------------------------------------------------------
        # 8. FINAL RESPONSE
        # ------------------------------------------------------
        duration = time.time() - start_time
        current_app.logger.info(
            f"✅ multi-recognize: {len(results)} logged, inst={SESSION_INSTRUCTOR_DETECTED[class_id]}, {duration:.2f}s"
        )

        return jsonify({
            "success": True,
            "logged": results,
            "count": len(results),
            "instructor_detected": SESSION_INSTRUCTOR_DETECTED[class_id],
            "instructor_id": instructor_id,
            "instructor_first_name": cls.get("instructor_first_name"),
            "instructor_last_name": cls.get("instructor_last_name"),
            "subject_code": cls.get("subject_code"),
            "subject_title": cls.get("subject_title"),
        }), 200

    except Exception as e:
        current_app.logger.error(f"❌ /multi-recognize error: {traceback.format_exc()}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500






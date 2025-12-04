from flask import Blueprint, jsonify, request, current_app
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
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
    save_face_data_for_instructor
)

# CONFIGURATION
face_bp = Blueprint("face_bp", __name__)
executor = ThreadPoolExecutor(max_workers=4)
limiter = Limiter(key_func=get_remote_address, default_limits=[])

# Hugging Face microservice endpoint
HF_AI_URL = "https://meuorii-face-recognition-attendance.hf.space"
students_collection = db["students"]
classes_collection = db["classes"]
attendance_collection = db["attendance_logs"]
instructors_collection = db['instructors']

# Philippine timezone
PH_TZ = timezone(timedelta(hours=8))
CACHE_TTL = 300 

SESSION_INSTRUCTOR_DETECTED = {}
SESSION_LOGGED_STUDENTS = {}

# Helper: Cache Management
def get_cached_faces(class_id):
    cls = classes_collection.find_one({"_id": ObjectId(class_id)})
    if not cls:
        print("Class not found for embeddings.")
        return []

    registered = []

    # LOAD STUDENTS ENROLLED IN THIS CLASS
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

    # LOAD INSTRUCTOR EMBEDDINGS
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
            print(f"Loaded instructor embeddings for: {instructor_id}")
        else:
            print("Instructor has no embeddings yet.")

    print(f"Loaded {len(registered)} embeddings (students + instructor) for class {class_id}")
    return registered

# REGISTER FACE
@face_bp.route("/register-auto", methods=["POST"])
def register_auto():
    start_time = time.time()
    try:
        data = request.get_json(silent=True) or {}
        student_id = data.get("student_id")

        if not student_id or not data.get("image"):
            return jsonify({
                "success": False,
                "error": "Missing student_id or image"
            }), 400

        course = (data.get("Course") or data.get("course") or "").strip().upper() or "UNKNOWN"
        data["course"] = course  
        current_app.logger.info(f"Preserved course for {student_id}: {course}")

        hf_start = time.time()
        res = requests.post(f"{HF_AI_URL}/register-auto", json=data, timeout=60)
        hf_elapsed = time.time() - hf_start

        if res.status_code != 200:
            current_app.logger.warning(f"HF service error {res.status_code}: {res.text}")
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

        normalized_embeddings = {}
        for angle, vec in hf_result["embeddings"].items():
            v = np.array(vec, dtype=np.float32)
            norm = np.linalg.norm(v)
            if norm > 0:
                normalized_embeddings[angle] = (v / norm).tolist()

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
            return_document=ReturnDocument.AFTER, 
        )

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


        students_collection.update_one(
            {"student_id": student_id},
            {"$set": {"Course": course}}
        )

        executor.submit(save_face_data, student_id, update_fields)

        total_elapsed = time.time() - start_time
        current_app.logger.info(
            f" /register-auto {student_id} done in {total_elapsed:.2f}s (HF={hf_elapsed:.2f}s)"
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
            f" /register-auto error: {str(e)}\n{traceback.format_exc()}"
        )
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

@face_bp.route("/register-instructor", methods=["POST"])
def register_instructor():
    start_time = time.time()
    try:
        data = request.get_json(silent=True) or {}
        instructor_id = data.get("instructor_id")

        if not instructor_id or not data.get("image"):
            return jsonify({
                "success": False,
                "error": "Missing instructor_id or image"
            }), 400

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

        normalized_embeddings = {}
        for angle, vec in hf_result["embeddings"].items():
            v = np.array(vec, dtype=np.float32)
            norm = np.linalg.norm(v)
            if norm > 0:
                normalized_embeddings[angle] = (v / norm).tolist()

        update_fields = {
            "instructor_id": instructor_id,
            "First_Name": data.get("First_Name"),
            "Middle_Name": data.get("Middle_Name"),
            "Last_Name": data.get("Last_Name"),
            "Suffix": data.get("Suffix"),
            "registered": True, 
            "embeddings": normalized_embeddings,
            "updated_at": datetime.utcnow(),
        }

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
            f"/register-instructor error: {str(e)}\n{traceback.format_exc()}"
        )
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

# MULTI-FACE ATTENDANCE
@face_bp.route("/multi-recognize", methods=["POST"])
def multi_face_recognize():
    start_time = time.time()

    try:
        data = request.get_json(silent=True) or {}
        faces = data.get("faces") or []
        class_id = str(data.get("class_id") or "").strip()

        if not faces or not class_id:
            return jsonify({"error": "Missing faces or class_id"}), 400

        registered_faces = get_cached_faces(class_id)
        if not isinstance(registered_faces, list):
            registered_faces = []

        if len(registered_faces) == 0:
            return jsonify({
                "success": False,
                "message": "No registered faces for this class",
                "recognized": [],
                "instructor_detected": False
            }), 200

        # Prepare payload for AI
        payload = {"faces": faces, "registered_faces": registered_faces}

        try:
            hf_res = requests.post(
                f"{HF_AI_URL}/recognize-multi",
                json=payload,
                timeout=60
            )
            if hf_res.status_code != 200:
                return jsonify({"error": "AI service failed"}), 500

            hf_result = hf_res.json()
        except Exception:
            return jsonify({"error": "AI service unreachable"}), 500

        recognized = hf_result.get("recognized") or []

        # FETCH CLASS DOCUMENT
        try:
            cls = classes_collection.find_one({"_id": ObjectId(class_id)})
        except Exception:
            return jsonify({"error": "Invalid class_id"}), 400

        if not cls:
            return jsonify({"error": "Class not found"}), 404

        instructor_id = cls.get("instructor_id")
        log_id_raw = cls.get("active_session_log_id")

        if not log_id_raw:
            return jsonify({"error": "No active attendance log for this class"}), 400

        # Convert to ObjectId
        try:
            log_id = ObjectId(str(log_id_raw))
        except Exception:
            return jsonify({"error": "Invalid log id"}), 500

        att_log = attendance_collection.find_one({"_id": log_id})

        if not att_log:
            now = datetime.now(PH_TZ)
            new_log = {
                "date": now.strftime("%Y-%m-%d"),
                "class_id": class_id,
                "course": cls.get("course"),
                "end_time": None,
                "instructor_id": instructor_id,
                "instructor_first_name": cls.get("instructor_first_name"),
                "instructor_last_name": cls.get("instructor_last_name"),
                "school_year": cls.get("school_year"),
                "section": cls.get("section"),
                "semester": cls.get("semester"),
                "start_time": now.strftime("%H:%M:%S"),
                "students": [],
                "subject_code": cls.get("subject_code"),
                "subject_title": cls.get("subject_title"),
                "year_level": cls.get("year_level"),
            }

            inserted = attendance_collection.insert_one(new_log)
            new_log_id = str(inserted.inserted_id)

            # Update class with new active log
            classes_collection.update_one(
                {"_id": ObjectId(class_id)},
                {"$set": {"active_session_log_id": new_log_id}}
            )

            SESSION_LOGGED_STUDENTS[class_id] = {}
            SESSION_INSTRUCTOR_DETECTED[class_id] = {
                "log_id": new_log_id,
                "detected": False
            }

            att_log = new_log
            log_id = ObjectId(new_log_id)

        now = datetime.now(PH_TZ)
        now_time = now.strftime("%H:%M:%S")
        now_readable = now.strftime("%I:%M %p")

        if class_id not in SESSION_LOGGED_STUDENTS:
            SESSION_LOGGED_STUDENTS[class_id] = {}

        instr_state = SESSION_INSTRUCTOR_DETECTED.get(class_id)
        if not instr_state or instr_state.get("log_id") != str(log_id):
            SESSION_INSTRUCTOR_DETECTED[class_id] = {
                "log_id": str(log_id),
                "detected": False
            }

        instructor_detected = SESSION_INSTRUCTOR_DETECTED[class_id]["detected"]
        results = []

        if len(recognized) == 0:
            return jsonify({
                "success": True,
                "logged": [],
                "count": 0,
                "instructor_detected": instructor_detected,
                "instructor_id": instructor_id,
                "instructor_first_name": cls.get("instructor_first_name"),
                "instructor_last_name": cls.get("instructor_last_name"),
                "subject_code": cls.get("subject_code"),
                "subject_title": cls.get("subject_title"),
            }), 200

        for face in recognized:
            user_id = str(face.get("user_id") or "")
            is_instructor = face.get("is_instructor", False)
            bbox = face.get("bbox")

            match_score = face.get("match_score")
            spoof_status = face.get("spoof_status")
            spoof_confidence = face.get("spoof_confidence")
            real_prob = face.get("real_prob")
            spoof_prob = face.get("spoof_prob")

            if not user_id:
                continue

            if is_instructor or user_id == instructor_id:
                if spoof_status == "Spoof" or (spoof_confidence is not None and spoof_confidence < 0.70):
                    print(f"Instructor SPOOF BLOCKED: {instructor_id} | confidence={spoof_confidence}")
                    continue

                SESSION_INSTRUCTOR_DETECTED[class_id] = {
                    "log_id": str(log_id),
                    "detected": True
                }
                instructor_detected = True
                continue

            student = get_student_by_id(user_id)
            if not student:
                continue

            stud_id = str(student.get("student_id"))
            first = student.get("first_name") or student.get("First_Name", "")
            last = student.get("last_name") or student.get("Last_Name", "")

            student_data = {
                "student_id": stud_id,
                "first_name": first,
                "last_name": last,
            }

            cache_entry = SESSION_LOGGED_STUDENTS[class_id].get(user_id)
            if cache_entry and cache_entry.get("log_id") == str(log_id):
                prev_status = cache_entry["status"]
                results.append({
                    **student_data,
                    "status": prev_status,
                    "time": now_readable,
                    "bbox": bbox,
                    "match_score": match_score,
                    "spoof_status": spoof_status,
                    "spoof_confidence": spoof_confidence,
                    "real_prob": real_prob,
                    "spoof_prob": spoof_prob
                })
                continue

            existing = attendance_collection.find_one(
                {"_id": log_id, "students.student_id": stud_id},
                {"students.$": 1}
            )

            if existing and existing.get("students"):
                status = existing["students"][0]["status"]

                SESSION_LOGGED_STUDENTS[class_id][user_id] = {
                    "status": status,
                    "log_id": str(log_id),
                }

                results.append({
                    **student_data,
                    "status": status,
                    "time": now_readable,
                    "bbox": bbox,
                    "match_score": match_score,
                    "spoof_status": spoof_status,
                    "spoof_confidence": spoof_confidence,
                    "real_prob": real_prob,
                    "spoof_prob": spoof_prob
                    
                })
                continue

            try:
                class_start = att_log["start_time"]
                class_dt = datetime.strptime(class_start, "%H:%M:%S").replace(
                    year=now.year, month=now.month, day=now.day
                )
                mins_late = (now - class_dt).total_seconds() / 60
                status = "Late" if mins_late > 15 else "Present"
            except Exception:
                status = "Present"

            attendance_collection.update_one(
                {"_id": log_id},
                {
                    "$push": {
                        "students": {
                            "student_id": stud_id,
                            "first_name": first,
                            "last_name": last,
                            "status": status,
                            "time": now_time
                        }
                    },
                    "$set": {"end_time": now_time}
                }
            )

            SESSION_LOGGED_STUDENTS[class_id][user_id] = {
                "status": status,
                "log_id": str(log_id),
            }

            results.append({
                **student_data,
                "status": status,
                "time": now_readable,
                "bbox": bbox,
                "match_score": match_score,
                "spoof_status": spoof_status,
                "spoof_confidence": spoof_confidence,
                "real_prob": real_prob,
                "spoof_prob": spoof_prob
            })


        duration = time.time() - start_time
        current_app.logger.info(
            f"[multi-recognize] logged={len(results)} instructor={instructor_detected} time={duration:.2f}s"
        )

        return jsonify({
            "success": True,
            "logged": results,
            "count": len(results),
            "instructor_detected": instructor_detected,
            "instructor_id": instructor_id,
            "instructor_first_name": cls.get("instructor_first_name"),
            "instructor_last_name": cls.get("instructor_last_name"),
            "subject_code": cls.get("subject_code"),
            "subject_title": cls.get("subject_title"),
        }), 200

    except Exception:
        current_app.logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500
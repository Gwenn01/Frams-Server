from flask import Blueprint, request, jsonify, after_this_request
from bson import ObjectId
from datetime import datetime, timedelta, timezone
import traceback
from config.db_config import db

classes_collection = db["classes"]
attendance_collection = db["attendance_logs"]
instructor_collection = db["instructors"]

# Attendance model helpers (class-based)
from models.attendance_model import (
    log_attendance as log_attendance_model,
    has_logged_attendance,
    mark_absent_bulk,
)

attendance_bp = Blueprint("attendance", __name__)

attendance_logs_col = db["attendance_logs"]

# SESSION MEMORY
SESSION_INSTRUCTOR_DETECTED = {}
SESSION_LOGGED_STUDENTS = {}

PH_TZ = timezone(timedelta(hours=8)) 

# Utilities
def _today_date():
    return datetime.now(PH_TZ).replace(hour=0, minute=0, second=0, microsecond=0)

def _parse_date(date_str):
    if not date_str:
        return _today_date()
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=PH_TZ)
    except ValueError:
        return _today_date()

def _class_to_payload(cls):
    if not cls:
        return None
    return {
        "class_id": str(cls["_id"]),
        "subject_code": cls.get("subject_code"),
        "subject_title": cls.get("subject_title"),
        "instructor_id": cls.get("instructor_id"),
        "instructor_first_name": cls.get("instructor_first_name"),
        "instructor_last_name": cls.get("instructor_last_name"),
        "course": cls.get("course"),
        "section": cls.get("section"),
        "is_attendance_active": cls.get("is_attendance_active", False),
        "attendance_start_time": cls.get("attendance_start_time"),
        "attendance_end_time": cls.get("attendance_end_time"),
        "students": cls.get("students", []),
    }

# Start attendance session
@attendance_bp.route("/start-session", methods=["POST"])
def start_session():
    try:
        data = request.get_json(silent=True) or {}
        class_id = data.get("class_id")
        instructor_id = data.get("instructor_id")

        if not class_id or not instructor_id:
            return jsonify({"error": "Missing class_id or instructor_id"}), 400

        try:
            class_oid = ObjectId(class_id)
        except:
            return jsonify({"error": "Invalid class_id"}), 400

        instructor = instructor_collection.find_one({"instructor_id": instructor_id})
        if not instructor:
            return jsonify({"error": "Instructor not found"}), 404

        if not instructor.get("registered"):
            return jsonify({"error": "Instructor must register face first"}), 400

        cls = classes_collection.find_one({"_id": class_oid})
        if not cls:
            return jsonify({"error": "Class not found"}), 404

        classes_collection.update_one(
            {"_id": class_oid},
            {
                "$set": {
                    "is_attendance_active": False,
                    "attendance_start_time": None,
                    "attendance_end_time": None,
                    "active_session_log_id": None,
                }
            }
        )

        SESSION_LOGGED_STUDENTS[class_id] = {}
        SESSION_INSTRUCTOR_DETECTED[class_id] = False

        now = datetime.now(PH_TZ)
        today_str = now.strftime("%Y-%m-%d")
        start_time_str = now.strftime("%H:%M:%S")

        log_doc = {
            "date": today_str,
            "class_id": class_id,
            "course": cls.get("course"),
            "end_time": None,
            "instructor_id": instructor_id,
            "instructor_first_name": instructor.get("first_name"),
            "instructor_last_name": instructor.get("last_name"),
            "school_year": cls.get("school_year"),
            "section": cls.get("section"),
            "semester": cls.get("semester"),
            "start_time": start_time_str,
            "students": [],
            "subject_code": cls.get("subject_code"),
            "subject_title": cls.get("subject_title"),
            "year_level": cls.get("year_level"),
        }

        inserted = attendance_collection.insert_one(log_doc)
        new_log_id = str(inserted.inserted_id)

        end_time = now + timedelta(minutes=30)

        update_res = classes_collection.update_one(
            {"_id": class_oid},
            {
                "$set": {
                    "is_attendance_active": True,
                    "attendance_start_time": now.isoformat(),
                    "attendance_end_time": end_time.isoformat(),
                    "active_session_log_id": new_log_id,
                    "instructor_id": instructor_id,
                }
            }
        )

        return jsonify({
            "success": True,
            "message": "Attendance session started successfully",
            "session": {
                "class_id": class_id,
                "log_id": new_log_id,
                "start_time": start_time_str,
                "end_time": end_time.strftime("%H:%M:%S"),
            }
        }), 200

    except Exception:
        print("ERROR IN /start-session", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

# Stop attendance session (auto-mark absentees asynchronously)
@attendance_bp.route("/stop-session", methods=["POST"])
def stop_session():
    try:
        data = request.get_json(silent=True) or {}
        class_id = data.get("class_id")

        if not class_id:
            return jsonify({"error": "Missing class_id"}), 400

        try:
            cls = classes_collection.find_one({"_id": ObjectId(class_id)})
        except:
            return jsonify({"error": "Invalid class_id"}), 400

        if not cls:
            return jsonify({"error": "Class not found"}), 404

        active_log_id = cls.get("active_session_log_id")
        if not active_log_id:
            return jsonify({"error": "No active attendance session found"}), 400

        if isinstance(active_log_id, ObjectId):
            log_id = active_log_id
        else:
            try:
                log_id = ObjectId(str(active_log_id))
            except:
                return jsonify({"error": "Invalid active_session_log_id"}), 400

        now = datetime.now(PH_TZ)
        now_time = now.strftime("%H:%M:%S")

        classes_collection.update_one(
            {"_id": ObjectId(class_id)},
            {"$set": {
                "is_attendance_active": False,
                "attendance_end_time": now.isoformat(),
                "active_session_log_id": None
            }}
        )

        att_log = attendance_collection.find_one({"_id": log_id})
        if not att_log:
            return jsonify({"error": "Attendance log not found"}), 404

        attendance_collection.update_one(
            {"_id": log_id},
            {"$set": {"end_time": now_time}}
        )

        logged_students = att_log.get("students", [])
        already_marked_ids = {str(s["student_id"]) for s in logged_students}

        class_students = cls.get("students", [])
        class_student_ids = {
            str(s.get("student_id")): s for s in class_students
        }

        if not class_student_ids:
            return jsonify({
                "success": True,
                "message": "Session stopped. No students enrolled in this class.",
                "log_id": str(log_id),
                "absent_count": 0
            }), 200

        absent_students = []

        for stud_id, info in class_student_ids.items():
            if stud_id not in already_marked_ids:
                absent_students.append({
                    "student_id": stud_id,
                    "first_name": info.get("first_name", ""),
                    "last_name": info.get("last_name", ""),
                    "status": "Absent",
                    "time": now_time
                })

        if absent_students:
            attendance_collection.update_one(
                {"_id": log_id},
                {"$push": {"students": {"$each": absent_students}}}
            )

        if class_id in SESSION_LOGGED_STUDENTS:
            SESSION_LOGGED_STUDENTS[class_id] = {}

        if class_id in SESSION_INSTRUCTOR_DETECTED:
            SESSION_INSTRUCTOR_DETECTED[class_id] = False

        return jsonify({
            "success": True,
            "message": (
                f"Session stopped successfully. "
                f"Marked {len(absent_students)} students as Absent."
            ),
            "log_id": str(log_id),
            "absent_count": len(absent_students)
        }), 200

    except Exception:
        import traceback
        print("Error in /stop-session:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

# Get currently active session (with auto-detect fallback)
@attendance_bp.route("/active-session", methods=["GET"])
def get_active_session():
    try:
        instructor_id = request.args.get("instructor_id")

        if instructor_id:
            cls = classes_collection.find_one({
                "is_attendance_active": True,
                "instructor_id": instructor_id
            })

            if cls:
                print(f"Active session found for instructor {instructor_id}: {cls.get('_id')}")
                return jsonify({
                    "active": True,
                    "class": _class_to_payload(cls),
                    "instructor_id": instructor_id
                }), 200

            print(f"No active session for instructor {instructor_id}")
            return jsonify({"active": False}), 200


        # Look for any active session in database
        cls = classes_collection.find_one({"is_attendance_active": True})

        if cls:
            print(f"Fallback active session found: {cls.get('_id')} | Instructor={cls.get('instructor_id')}")
            return jsonify({
                "active": True,
                "class": _class_to_payload(cls),
                "instructor_id": cls.get("instructor_id")
            }), 200

        return jsonify({
            "active": False,
            "error": "No active sessions found"
        }), 200

    except Exception:
        import traceback
        print("Error in /active-session:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500


# Log/Upsert a student's attendance
@attendance_bp.route("/log", methods=["POST"])
def log_attendance():
    try:
        data = request.get_json(silent=True) or {}
        required = ["class_id", "student"]
        missing = [k for k in required if k not in data]
        if missing:
            return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

        class_id = data["class_id"]
        student_data = data["student"]
        date_val = _parse_date(data.get("date"))
        status = data.get("status") 

        for f in ["student_id", "first_name", "last_name"]:
            if f not in student_data:
                return jsonify({"error": f"Missing student.{f}"}), 400


        cls = classes_collection.find_one({"_id": ObjectId(class_id)})
        if not cls:
            return jsonify({"error": "Class not found"}), 404

        class_data = {
            "class_id": str(cls["_id"]),
            "subject_code": cls.get("subject_code"),
            "subject_title": cls.get("subject_title"),
            "instructor_id": cls.get("instructor_id"),
            "instructor_first_name": cls.get("instructor_first_name"),
            "instructor_last_name": cls.get("instructor_last_name"),
            "course": cls.get("course"),
            "section": cls.get("section"),
        }

        if not status:
            result = log_attendance_model(
                class_data=class_data,
                student_data=student_data,
                date_val=date_val,
                class_start_time=cls.get("attendance_start_time")
            )
        else:
            result = log_attendance_model(
                class_data=class_data,
                student_data=student_data,
                date_val=date_val,
                class_start_time=None,
                status=status
            )

        if result is None:
            return jsonify({
                "success": False,
                "message": "Too late (>30 minutes). Attendance not recorded.",
                "class_id": class_data["class_id"],
                "student_id": student_data["student_id"],
            }), 400

        return jsonify({
            "success": True,
            "message": f"Attendance recorded as {result['status']}",
            **result
        }), 200

    except Exception:
        import traceback
        print("Error in /log:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

# Check if student already logged today
@attendance_bp.route("/has-logged", methods=["GET"])
def has_logged():
    try:
        student_id = request.args.get("student_id")
        class_id = request.args.get("class_id")
        date_val = _parse_date(request.args.get("date"))

        if not student_id or not class_id:
            return jsonify({"error": "Missing student_id or class_id"}), 400

        exists = has_logged_attendance(student_id, class_id, date_val)
        return jsonify({"exists": bool(exists)}), 200

    except Exception:
        import traceback
        print("Error in /has-logged:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

# Get attendance logs grouped by date (NOT BY CLASS)
@attendance_bp.route("/logs", methods=["GET"])
def get_all_logs_grouped():
    try:
        class_id = request.args.get("class_id")
        date_start = request.args.get("start")
        date_end = request.args.get("end")

        query = {}

        if class_id:
            query["class_id"] = str(class_id)

        if date_start and date_end:
            query["date"] = {"$gte": date_start, "$lte": date_end}

        print("LOG QUERY:", query)

        raw_logs = list(attendance_logs_col.find(query))

        grouped = {}
        for log in raw_logs:
            date = log.get("date")
            if not date:
                continue

            if date not in grouped:
                grouped[date] = {
                    "date": date,
                    "logs": [],
                    "unique_students": {}
                }

            log["_id"] = str(log["_id"])
            grouped[date]["logs"].append(log)

            # Merge deduped students
            for s in log.get("students", []):
                sid = s.get("student_id")
                if sid:
                    grouped[date]["unique_students"][sid] = s

        final_output = [
            {
                "date": date,
                "logs": info["logs"],
                "students": list(info["unique_students"].values())
            }
            for date, info in grouped.items()
        ]

        final_output.sort(key=lambda x: x["date"], reverse=True)

        return jsonify({"success": True, "logs": final_output}), 200

    except Exception:
        print("Error in /logs:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500


# Bulk mark ABSENT for students (manual)
@attendance_bp.route("/mark-absent", methods=["POST"])
def mark_absent():
    try:
        data = request.get_json(silent=True) or {}
        class_id = data.get("class_id")
        students = data.get("students", [])

        if not class_id or not isinstance(students, list):
            return jsonify({"error": "Missing class_id or students[]"}), 400

        date_val = _parse_date(data.get("date"))

        cls = classes_collection.find_one({"_id": ObjectId(class_id)})
        if not cls:
            return jsonify({"error": "Class not found"}), 404

        class_data = {
            "class_id": str(cls["_id"]),
            "subject_code": cls.get("subject_code"),
            "subject_title": cls.get("subject_title"),
            "instructor_id": cls.get("instructor_id"),
            "instructor_first_name": cls.get("instructor_first_name"),
            "instructor_last_name": cls.get("instructor_last_name"),
            "course": cls.get("course"),
            "section": cls.get("section"),
        }

        mark_absent_bulk(class_data, date_val, students)

        return jsonify({
            "success": True,
            "message": "Absent marked (where missing)",
            "class_id": class_id,
            "date": date_val.strftime("%Y-%m-%d"),
            "count": len(students),
        }), 200

    except Exception:
        import traceback
        print("Error in /mark-absent:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500
    
# Mark a student as Excused (Instructor action)
@attendance_bp.route("/mark-excused", methods=["POST"])
def mark_excused():
    try:
        data = request.get_json(force=True)
        student_id = data.get("student_id")
        class_id = data.get("class_id")
        date_str = data.get("date")
        reason = data.get("reason", "")
        instructor_id = data.get("instructor_id", "Unknown")

        if not all([student_id, class_id, date_str]):
            return jsonify({"error": "Missing required fields"}), 400

        date_val = _parse_date(date_str)
        date_str = date_val.strftime("%Y-%m-%d")

        attendance_logs = db["attendance_logs"]

        result = attendance_logs.update_one(
            {
                "class_id": class_id,
                "students.student_id": student_id,
                "date": date_str,
            },
            {
                "$set": {
                    "students.$.status": "Excused",
                    "students.$.excuse_reason": reason,
                    "students.$.updated_by": instructor_id,
                    "students.$.updated_at": datetime.now(PH_TZ),
                }
            }
        )

        if result.modified_count == 0:
            return jsonify({"error": "No matching record found"}), 404

        return jsonify({
            "success": True,
            "message": f"Student {student_id} marked as Excused.",
            "student_id": student_id,
            "class_id": class_id,
            "reason": reason
        }), 200

    except Exception:
        import traceback
        print("Error in /mark-excused:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

# Get attendance sessions for a specific class
@attendance_bp.route("/sessions/<class_id>", methods=["GET"])
def get_sessions_by_class(class_id):
    try:
        logs = list(attendance_logs_col.find({"class_id": str(class_id)}))

        sessions = []

        for log in logs:
            sessions.append({
                "_id": str(log["_id"]),
                "class_id": log.get("class_id"),
                "date": log.get("date"),
                "start_time": log.get("start_time"),
                "end_time": log.get("end_time"),
                "students": log.get("students", []),
                "subject_code": log.get("subject_code"),
                "subject_title": log.get("subject_title"),
                "course": log.get("course"),
                "section": log.get("section"),
                "semester": log.get("semester"),
                "school_year": log.get("school_year"),
            })

        return jsonify({
            "success": True,
            "sessions": sessions
        }), 200

    except Exception:
        import traceback
        print("Error in /sessions/<class_id>:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

@attendance_bp.route("/sessions", methods=["GET"])
def get_all_valid_sessions():
    try:
        logs = attendance_logs_col.find({
            "semester": {"$exists": True, "$ne": ""},
            "school_year": {"$exists": True, "$ne": ""}
        })

        sessions = []
        for log in logs:
            sessions.append({
                "_id": str(log["_id"]),
                "class_id": log.get("class_id"),
                "date": log.get("date"),
                "start_time": log.get("start_time"),
                "end_time": log.get("end_time"),
                "students": log.get("students", []),
                "subject_code": log.get("subject_code"),
                "subject_title": log.get("subject_title"),
                "course": log.get("course"),
                "section": log.get("section"),
                "semester": log.get("semester"),
                "school_year": log.get("school_year"),
                "instructor_first_name": log.get("instructor_first_name", ""),
                "instructor_last_name": log.get("instructor_last_name", ""),
            })

        return jsonify({
            "success": True,
            "sessions": sessions
        }), 200

    except Exception:
        import traceback
        print("Error in /sessions:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

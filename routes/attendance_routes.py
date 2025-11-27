from flask import Blueprint, request, jsonify, after_this_request
from bson import ObjectId
from datetime import datetime, timedelta, timezone
from threading import Thread

from utils.attendance_session import (
    start_attendance_session,
    stop_attendance_session,
)
from config.db_config import db

# 🔹 Work with classes instead of subjects
classes_collection = db["classes"]
attendance_collection = db["attendance_logs"]
instructor_collection = db["instructors"]

# 🔄 Attendance model helpers (class-based)
from models.attendance_model import (
    log_attendance as log_attendance_model,
    has_logged_attendance,
    get_attendance_logs_by_class_and_date,
    get_attendance_by_class,
    mark_absent_bulk,
)

attendance_bp = Blueprint("attendance", __name__)

attendance_logs_col = db["attendance_logs"]

# -----------------------------
# Timezone
# -----------------------------
PH_TZ = timezone(timedelta(hours=8))  # Philippine Time

# -----------------------------
# Utilities
# -----------------------------
def _today_date():
    """Return today's date normalized to midnight (PH time)."""
    return datetime.now(PH_TZ).replace(hour=0, minute=0, second=0, microsecond=0)

def _parse_date(date_str):
    """Convert YYYY-MM-DD string to datetime (PH tz), fallback to today."""
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

# -----------------------------
# API ROUTES
# -----------------------------

# ✅ Start attendance session
@attendance_bp.route("/start-session", methods=["POST"])
def start_session():
    try:
        data = request.get_json(silent=True) or {}
        class_id = data.get("class_id")
        instructor_id = data.get("instructor_id")

        if not class_id or not instructor_id:
            return jsonify({"error": "Missing class_id or instructor_id"}), 400

        # -------------------------------------------------
        # 1. FETCH INSTRUCTOR
        # -------------------------------------------------
        instructor = instructor_collection.find_one({"instructor_id": instructor_id})
        if not instructor:
            return jsonify({"error": "Instructor not found"}), 404

        # REQUIRE AT LEAST 1 FACE ANGLE
        if not instructor.get("registered"):
            return jsonify({"error": "Instructor has not registered their face"}), 400

        embeddings = instructor.get("embeddings", {})
        has_one_angle = any(
            isinstance(embeddings.get(a), list) and len(embeddings.get(a)) == 512
            for a in ["front", "left", "right", "up", "down"]
        )
        if not has_one_angle:
            return jsonify({"error": "Instructor must register at least 1 valid angle."}), 400

        # -------------------------------------------------
        # 2. FETCH CLASS DOCUMENT
        # -------------------------------------------------
        cls = classes_collection.find_one({"_id": ObjectId(class_id)})
        if not cls:
            return jsonify({"error": "Class not found"}), 404

        schedule_blocks = cls.get("schedule_blocks", [])
        if not schedule_blocks:
            return jsonify({"error": "This class has no schedule."}), 400

        # -------------------------------------------------
        # 3. VALIDATE TIME AGAINST CLASS SCHEDULE
        # -------------------------------------------------
        now = datetime.now(PH_TZ)
        current_day = now.strftime("%a")
        current_time = now.strftime("%H:%M")

        is_scheduled_now = False
        for block in schedule_blocks:
            if (
                current_day in block.get("days", [])
                and block.get("start") <= current_time <= block.get("end")
            ):
                is_scheduled_now = True
                break

        if not is_scheduled_now:
            readable = [
                f"{b.get('days')} {b.get('start')}–{b.get('end')}"
                for b in schedule_blocks
            ]
            return jsonify({
                "error": (
                    "⛔ Cannot start session.\n"
                    "Class schedule:\n"
                    f"{readable}"
                )
            }), 400

        # -------------------------------------------------
        # 4. PREVENT MULTIPLE ACTIVE SESSIONS
        # -------------------------------------------------
        already_active = classes_collection.find_one({
            "is_attendance_active": True,
            "instructor_id": instructor_id
        })
        if already_active:
            return jsonify({"error": "You already have an active session."}), 400

        # -------------------------------------------------
        # 5. CREATE COMPLETE ATTENDANCE LOG DOCUMENT
        # -------------------------------------------------
        today_str = now.strftime("%Y-%m-%d")
        start_time_str = now.strftime("%H:%M:%S")

        log_doc = {
            "date": today_str,
            "class_id": str(class_id),
            "course": cls.get("course"),
            "end_time": None,
            "instructor_id": instructor.get("instructor_id"),
            "instructor_first_name": instructor.get("first_name"),
            "instructor_last_name": instructor.get("last_name"),
            "school_year": cls.get("school_year"),
            "section": cls.get("section"),
            "semester": cls.get("semester"),
            "year_level": cls.get("year_level"),
            "start_time": start_time_str,
            "students": [],     
            "subject_code": cls.get("subject_code"),
            "subject_title": cls.get("subject_title")
        }

        inserted = attendance_collection.insert_one(log_doc)
        log_id = str(inserted.inserted_id)

        # -------------------------------------------------
        # 6. ACTIVATE SESSION
        # -------------------------------------------------
        end_time = now + timedelta(minutes=30)

        classes_collection.update_one(
            {"_id": ObjectId(class_id)},
            {"$set": {
                "is_attendance_active": True,
                "attendance_start_time": now.isoformat(),
                "attendance_end_time": end_time.isoformat(),
                "instructor_id": instructor_id,
                "active_session_log_id": log_id
            }}
        )

        return jsonify({
            "success": True,
            "message": "Attendance session started successfully",
            "session": {
                "class_id": class_id,
                "log_id": log_id,
                "start_time": start_time_str,
                "end_time": end_time.strftime("%H:%M:%S")
            }
        }), 200

    except Exception as e:
        import traceback
        print("❌ ERROR in /start-session:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

# ✅ Stop attendance session (auto-mark absentees asynchronously)
@attendance_bp.route("/stop-session", methods=["POST"])
def stop_session():
    try:
        data = request.get_json(silent=True) or {}
        class_id = data.get("class_id")

        if not class_id:
            return jsonify({"error": "Missing class_id"}), 400

        # -------------------------------------------------
        # 1. FETCH CLASS
        # -------------------------------------------------
        cls = classes_collection.find_one({"_id": ObjectId(class_id)})
        if not cls:
            return jsonify({"error": "Class not found"}), 404

        active_log_id = cls.get("active_session_log_id")
        if not active_log_id:
            return jsonify({"error": "No active attendance session found"}), 400

        now = datetime.now(PH_TZ)
        now_time = now.strftime("%H:%M:%S")

        # -------------------------------------------------
        # 2. STOP ACTIVE SESSION IN CLASS DOCUMENT
        # -------------------------------------------------
        classes_collection.update_one(
            {"_id": ObjectId(class_id)},
            {"$set": {
                "is_attendance_active": False,
                "attendance_end_time": now.isoformat(),
                "active_session_log_id": None
            }}
        )

        # -------------------------------------------------
        # 3. FETCH THE ACTIVE ATTENDANCE LOG DOCUMENT
        # -------------------------------------------------
        attendance_log = attendance_collection.find_one({"_id": ObjectId(active_log_id)})
        if not attendance_log:
            return jsonify({"error": "Attendance log not found"}), 404

        # Update end_time inside the attendance log
        attendance_collection.update_one(
            {"_id": ObjectId(active_log_id)},
            {"$set": {"end_time": now_time}}
        )

        # -------------------------------------------------
        # 4. IDENTIFY PRESENT STUDENTS
        # -------------------------------------------------
        logged_students = attendance_log.get("students", [])
        already_marked_ids = {s["student_id"] for s in logged_students}

        # -------------------------------------------------
        # 5. GET ALL ENROLLED STUDENTS FROM CLASS
        # -------------------------------------------------
        all_students = cls.get("students", [])
        absent_students = [
            s for s in all_students
            if s.get("student_id") not in already_marked_ids
        ]

        # -------------------------------------------------
        # 6. MARK ABSENTEES IN THE SAME ATTENDANCE LOG
        # -------------------------------------------------
        if absent_students:
            bulk_absent_entries = [
                {
                    "student_id": s["student_id"],
                    "first_name": s.get("first_name", ""),
                    "last_name": s.get("last_name", ""),
                    "status": "Absent",
                    "time": now_time
                }
                for s in absent_students
            ]

            attendance_collection.update_one(
                {"_id": ObjectId(active_log_id)},
                {"$push": {"students": {"$each": bulk_absent_entries}}}
            )

        # -------------------------------------------------
        # 7. RESPONSE
        # -------------------------------------------------
        return jsonify({
            "success": True,
            "message": (
                f"🛑 Session stopped successfully. "
                f"Marked {len(absent_students)} students as Absent."
            ),
            "log_id": active_log_id,
            "absent_count": len(absent_students)
        }), 200

    except Exception:
        import traceback
        print("❌ Error in /stop-session:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

# ✅ Get currently active session (with auto-detect fallback)
@attendance_bp.route("/active-session", methods=["GET"])
def get_active_session():
    try:
        # 🔹 Optional instructor_id parameter
        instructor_id = request.args.get("instructor_id")

        # -------------------------------------------------
        # 🧩 Case 1: instructor_id is provided (normal flow)
        # -------------------------------------------------
        if instructor_id:
            cls = classes_collection.find_one({
                "is_attendance_active": True,
                "instructor_id": instructor_id
            })

            if cls:
                print(f"🟢 Active session found for instructor {instructor_id}: {cls.get('_id')}")
                return jsonify({
                    "active": True,
                    "class": _class_to_payload(cls),
                    "instructor_id": instructor_id
                }), 200

            print(f"🟡 No active session for instructor {instructor_id}")
            return jsonify({"active": False}), 200

        # -------------------------------------------------
        # 🧭 Case 2: No instructor_id → Fallback auto-detect
        # -------------------------------------------------
        print("⚠️ Missing instructor_id in request (auto-detect mode).")

        # Look for any active session in database
        cls = classes_collection.find_one({"is_attendance_active": True})

        if cls:
            print(f"🟢 Fallback active session found: {cls.get('_id')} | Instructor={cls.get('instructor_id')}")
            return jsonify({
                "active": True,
                "class": _class_to_payload(cls),
                "instructor_id": cls.get("instructor_id")
            }), 200

        print("🟡 No active sessions found (auto-detect mode).")
        return jsonify({
            "active": False,
            "error": "No active sessions found"
        }), 200

    except Exception:
        import traceback
        print("❌ Error in /active-session:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500



# ✅ Log/Upsert a student's attendance
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
        status = data.get("status")  # optional (from client like attendance_app)

        # Validate student fields
        for f in ["student_id", "first_name", "last_name"]:
            if f not in student_data:
                return jsonify({"error": f"Missing student.{f}"}), 400

        # ✅ Fetch class info
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
                "message": "⛔ Too late (>30 minutes). Attendance not recorded.",
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
        print("❌ Error in /log:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

# ✅ Check if student already logged today
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
        print("❌ Error in /has-logged:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

# ✅ Get attendance logs grouped by date (NOT BY CLASS)
@attendance_bp.route("/logs", methods=["GET"])
def get_all_logs_grouped():
    try:
        class_id = request.args.get("class_id")   # optional
        date_start = request.args.get("start")
        date_end = request.args.get("end")

        query = {}

        # Optional filters
        if class_id:
            query["class_id"] = str(class_id)

        if date_start and date_end:
            query["date"] = {"$gte": date_start, "$lte": date_end}

        # 🔥 Fetch everything from attendance_logs
        raw_logs = list(attendance_logs_col.find(query))

        grouped = {}

        for log in raw_logs:
            date = log.get("date")
            if not date:
                continue

            if date not in grouped:
                grouped[date] = {
                    "date": date,
                    "logs": [],            # full attendance_logs documents
                    "students": [],        # all students combined
                    "unique_students": {}  # dedupe
                }

            # Convert _id to string
            log["_id"] = str(log["_id"])

            # 🔥 Append the FULL DOCUMENT (no trimming)
            grouped[date]["logs"].append(log)

            # Collect students (dedupe by student_id)
            for s in log.get("students", []):
                sid = s.get("student_id")
                if sid:
                    grouped[date]["unique_students"][sid] = s

        # Final formatting
        result = []
        for date, entry in grouped.items():
            result.append({
                "date": date,
                "logs": entry["logs"],                      # FULL documents
                "students": list(entry["unique_students"].values())  # deduped students
            })

        # Sort by date DESC
        result.sort(key=lambda x: x["date"], reverse=True)

        return jsonify({
            "success": True,
            "logs": result
        }), 200

    except Exception:
        import traceback
        print("❌ Error in /logs:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

# ✅ Bulk mark ABSENT for students (manual)
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
        print("❌ Error in /mark-absent:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500
    
# ✅ Mark a student as Excused (Instructor action)
@attendance_bp.route("/mark-excused", methods=["POST"])
def mark_excused():
    """
    Instructor marks a student as Excused for a specific date.
    Updates the 'students' subdocument inside attendance_logs.
    """
    try:
        data = request.get_json(force=True)
        student_id = data.get("student_id")
        class_id = data.get("class_id")
        date_str = data.get("date")
        reason = data.get("reason", "")
        instructor_id = data.get("instructor_id", "Unknown")

        if not all([student_id, class_id, date_str]):
            return jsonify({"error": "Missing required fields"}), 400

        # Parse date
        date_val = _parse_date(date_str)
        date_str = date_val.strftime("%Y-%m-%d")

        # ✅ Connect to your real collection
        attendance_logs = db["attendance_logs"]

        # 🧠 Find the correct document
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
        print("❌ Error in /mark-excused:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

# ✅ Get attendance sessions for a specific class
@attendance_bp.route("/sessions/<class_id>", methods=["GET"])
def get_sessions_by_class(class_id):
    try:
        # Find by STRING class_id (based on your DB)
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
        print("❌ Error in /sessions/<class_id>:", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500


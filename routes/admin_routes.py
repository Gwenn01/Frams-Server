from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta, date
import os
from bson import ObjectId
from config.db_config import db
from models.admin_model import find_admin_by_user_id, find_admin_by_email, create_admin
import re
from flask_jwt_extended import jwt_required, get_jwt_identity

admin_bp = Blueprint("admin_bp", __name__)
secret_key = os.getenv("JWT_SECRET", os.getenv("JWT_SECRET_KEY", "yoursecretkey"))

# Collections
students_col = db["students"]
instructors_col = db["instructors"]
classes_col = db["classes"]
attendance_logs_col = db["attendance_logs"]
subjects_col = db["subjects"]

# -------------------------------
# Helpers
# ------------------------------- frontend
def today_str_utc():
    return datetime.utcnow().strftime("%Y-%m-%d")

def to_date_str(dt):
    if not dt:
        return None
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d")
    if isinstance(dt, date):
        return dt.strftime("%Y-%m-%d")
    return str(dt)[:10]

def _serialize_subject(s):
    return {
        "_id": str(s["_id"]),
        "subject_code": s.get("subject_code"),
        "subject_title": s.get("subject_title"),
        "course": s.get("course"),
        "year_level": s.get("year_level"),
        "semester": s.get("semester"),
        "instructor_id": s.get("instructor_id"),
        "instructor_first_name": s.get("instructor_first_name"),
        "instructor_last_name": s.get("instructor_last_name"),
        "created_at": s.get("created_at"),
    }

def _serialize_class(cls):
    return {
        "_id": str(cls.get("_id")),
        "subject_id": str(cls.get("subject_id")) if cls.get("subject_id") else None,
        "subject_code": cls.get("subject_code") or "-",
        "subject_title": cls.get("subject_title") or "-",
        "course": cls.get("course") or "-",
        "year_level": cls.get("year_level") or "-",
        "semester": cls.get("semester") or "-",
        "section": cls.get("section") or "-",
        "instructor_id": str(cls.get("instructor_id")) if cls.get("instructor_id") else None,
        "instructor_first_name": cls.get("instructor_first_name") or "N/A",
        "instructor_last_name": cls.get("instructor_last_name") or "N/A",
        "schedule_blocks": cls.get("schedule_blocks", []),
        "students": cls.get("students", []),
        "created_at": cls.get("created_at").isoformat() if cls.get("created_at") else None,
    }

# =========================================
# ✅ Auth: Register (after frontend OTP)
# =========================================
@admin_bp.route("/api/admin/register", methods=["POST"])
def register_admin():
    data = request.get_json() or {}

    first_name = (data.get("first_name") or "").strip()
    last_name = (data.get("last_name") or "").strip()
    user_id = (data.get("user_id") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    program = (data.get("program") or "").strip().upper()  # ✅ Added

    # -------------------------------
    # Validate required fields
    # -------------------------------
    if not all([first_name, last_name, user_id, email, password, program]):
        return jsonify({"error": "Missing required fields"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters."}), 400

    if program not in ["BSINFOTECH", "BSCS"]:
        return jsonify({"error": "Invalid program. Only BSINFOTECH or BSCS allowed."}), 400

    if find_admin_by_user_id(user_id):
        return jsonify({"error": "User ID already exists"}), 409

    if find_admin_by_email(email):
        return jsonify({"error": "Email already exists"}), 409

    # -------------------------------
    # Enforce only one admin per program
    # -------------------------------
    existing_admin = db["admins"].find_one({"program": program})
    if existing_admin:
        return jsonify({"error": f"An admin account for {program} already exists."}), 409

    # -------------------------------
    # Save admin data
    # -------------------------------
    hashed_password = generate_password_hash(password)
    full_name = f"{first_name} {last_name}".strip()

    admin_data = {
        "first_name": first_name,
        "last_name": last_name,
        "full_name": full_name,
        "user_id": user_id,
        "email": email,
        "password": hashed_password,
        "program": program,  # ✅ Added field
        "created_at": datetime.utcnow(),
    }

    create_admin(admin_data)

    return jsonify({"message": f"Admin for {program} registered successfully"}), 201

# =========================================
# ✅ Auth: Login
# =========================================
@admin_bp.route("/api/admin/login", methods=["POST"])
def login_admin():
    data = request.get_json() or {}
    user_id = (data.get("user_id") or "").strip()
    password = data.get("password") or ""

    # -------------------------------
    # Validate inputs
    # -------------------------------
    if not user_id or not password:
        return jsonify({"error": "User ID and password are required."}), 400

    admin = find_admin_by_user_id(user_id)
    if not admin:
        return jsonify({"error": "Invalid User ID"}), 401

    if not check_password_hash(admin["password"], password):
        return jsonify({"error": "Incorrect password"}), 401

    program = admin.get("program", "N/A")  # ✅ Include program if available

    # -------------------------------
    # Create JWT token
    # -------------------------------
    token = jwt.encode(
        {
            "user_id": user_id,
            "role": "admin",
            "program": program,  # ✅ Include in token payload
            "exp": datetime.utcnow() + timedelta(hours=12),
        },
        secret_key,
        algorithm="HS256",
    )

    # -------------------------------
    # Return response
    # -------------------------------
    return jsonify(
        {
            "token": token,
            "message": f"Login successful ({program})",
            "admin": {
                "user_id": admin.get("user_id"),
                "first_name": admin.get("first_name"),
                "last_name": admin.get("last_name"),
                "email": admin.get("email"),
                "program": program,  # ✅ Added here
            },
        }
    ), 200

# ==============================
# ✅ Admin Overview Endpoints
# ==============================
@admin_bp.route("/api/admin/overview/stats", methods=["GET"])
def get_stats():
    program = request.args.get("program")  # e.g. BSINFOTECH / BSCS
    today = datetime.utcnow().strftime("%Y-%m-%d")

    # 🧩 Attendance logs filtered by course (handles both 'course' and 'Course')
    attendance_today = 0
    query = {"date": today}
    if program:
        query["$or"] = [
            {"course": {"$regex": f"^{program}$", "$options": "i"}},
            {"Course": {"$regex": f"^{program}$", "$options": "i"}},
            {"students.course": {"$regex": f"^{program}$", "$options": "i"}},
            {"students.Course": {"$regex": f"^{program}$", "$options": "i"}}
        ]

    for log in attendance_logs_col.find(query):
        attendance_today += len(log.get("students", []))

    # 🧩 Students and Classes filtered by course (case-insensitive)
    student_filter = {"$or": [
        {"course": {"$regex": f"^{program}$", "$options": "i"}},
        {"Course": {"$regex": f"^{program}$", "$options": "i"}}
    ]} if program else {}

    class_filter = {"$or": [
        {"course": {"$regex": f"^{program}$", "$options": "i"}},
        {"Course": {"$regex": f"^{program}$", "$options": "i"}}
    ]} if program else {}

    # 🧩 Instructors — fetch ALL instructors (not filtered by program)
    total_instructors = instructors_col.count_documents({})

    # ✅ Return compiled overview
    return jsonify(
        {
            "total_students": students_col.count_documents(student_filter),
            "total_instructors": total_instructors,
            "total_classes": classes_col.count_documents(class_filter),
            "attendance_today": attendance_today,
        }
    )

@admin_bp.route("/api/admin/overview/attendance-distribution", methods=["GET"])
def attendance_distribution():
    program = request.args.get("program")

    # Match logs by course at root or inside students array
    match_stage = {"$match": {
        "$or": [
            {"course": {"$regex": f"^{program}$", "$options": "i"}},
            {"Course": {"$regex": f"^{program}$", "$options": "i"}},
            {"students.course": {"$regex": f"^{program}$", "$options": "i"}},
            {"students.Course": {"$regex": f"^{program}$", "$options": "i"}},
        ]
    }} if program else {}

    pipeline = []
    if match_stage:
        pipeline.append(match_stage)

    pipeline += [
        {"$unwind": "$students"},
        {"$group": {"_id": "$students.status", "count": {"$sum": 1}}},
    ]

    result = list(attendance_logs_col.aggregate(pipeline))

    present = late = absent = 0
    for r in result:
        status = (r["_id"] or "").strip().lower()
        if status == "present":
            present = r["count"]
        elif status == "late":
            late = r["count"]
        elif status == "absent":
            absent = r["count"]

    return jsonify({"present": present, "late": late, "absent": absent})

@admin_bp.route("/api/admin/overview/attendance-trend", methods=["GET"])
def attendance_trend():
    program = request.args.get("program")
    days = int(request.args.get("days", 7))
    end_date = datetime.utcnow().date()
    trend = []

    for i in range(days):
        d = end_date - timedelta(days=(days - 1 - i))
        d_str = d.strftime("%Y-%m-%d")

        # Match by date and program at root or inside students
        query = {"date": d_str}
        if program:
            query["$or"] = [
                {"course": {"$regex": f"^{program}$", "$options": "i"}},
                {"Course": {"$regex": f"^{program}$", "$options": "i"}},
                {"students.course": {"$regex": f"^{program}$", "$options": "i"}},
                {"students.Course": {"$regex": f"^{program}$", "$options": "i"}},
            ]

        day_total = 0
        for log in attendance_logs_col.find(query):
            day_total += len(log.get("students", []))
        trend.append({"date": d_str, "count": day_total})

    return jsonify(trend)

@admin_bp.route("/api/admin/overview/recent-logs", methods=["GET"])
def recent_logs():
    program = request.args.get("program")
    limit = int(request.args.get("limit", 5))

    # Match both root and nested course fields
    query = {}
    if program:
        query["$or"] = [
            {"course": {"$regex": f"^{program}$", "$options": "i"}},
            {"Course": {"$regex": f"^{program}$", "$options": "i"}},
            {"students.course": {"$regex": f"^{program}$", "$options": "i"}},
            {"students.Course": {"$regex": f"^{program}$", "$options": "i"}},
        ]

    docs = list(attendance_logs_col.find(query).sort("date", -1).limit(20))
    flattened = []

    for log in docs:
        subject_title = log.get("subject_title")
        subject_code = log.get("subject_code")
        subject = (
            f"{subject_code} - {subject_title}"
            if subject_code and subject_title
            else (subject_title or subject_code)
        )

        for stu in log.get("students", []):
            flattened.append(
                {
                    "student": {
                        "first_name": stu.get("first_name") or stu.get("First_Name"),
                        "last_name": stu.get("last_name") or stu.get("Last_Name"),
                        "student_id": stu.get("student_id"),
                    },
                    "subject": subject,
                    "status": stu.get("status"),
                    "timestamp": stu.get("time_logged") or log.get("date"),
                }
            )

    flattened.sort(key=lambda x: str(x.get("timestamp") or ""), reverse=True)
    return jsonify(flattened[:limit])

@admin_bp.route("/api/admin/overview/last-student", methods=["GET"])
def last_student():
    program = request.args.get("program")
    query = {"$or": [
        {"course": {"$regex": f"^{program}$", "$options": "i"}},
        {"Course": {"$regex": f"^{program}$", "$options": "i"}}
    ]} if program else {}

    student = students_col.find_one(query, sort=[("created_at", -1)])
    if not student:
        return jsonify(None)

    return jsonify(
        {
            "student_id": student.get("student_id"),
            "first_name": student.get("First_Name") or student.get("first_name"),
            "last_name": student.get("Last_Name") or student.get("last_name"),
            "created_at": student.get("created_at"),
        }
    )

from flask import jsonify, request
from datetime import datetime, timezone

# ==============================
# ✅ Student Management
# ==============================
# ============================================================
# 📌 GET ALL STUDENTS — Filtered by Admin’s Program
# ============================================================
@admin_bp.route("/api/admin/students", methods=["GET"])
@jwt_required()
def get_all_students():
    try:
        identity = get_jwt_identity()
        program = identity.get("program") if isinstance(identity, dict) else None

        # 🧩 Ensure program filter (e.g., BSINFOTECH / BSCS)
        course_filter = {}
        if program:
            course_filter["$or"] = [
                {"Course": {"$regex": f"^{program}$", "$options": "i"}},
                {"course": {"$regex": f"^{program}$", "$options": "i"}},
            ]

        # 🧩 Fetch students only from that course
        students = list(
            students_col.find(
                course_filter,
                {
                    "_id": 0,
                    "student_id": 1,
                    "First_Name": 1,
                    "Last_Name": 1,
                    "Middle_Name": 1,
                    "Course": 1,
                    "Section": 1,
                    "created_at": 1,
                },
            )
        )

        normalized = []
        for s in students:
            sid = s.get("student_id")

            # ✅ Count attendance across attendance_logs.students array
            pipeline = [
                {"$unwind": "$students"},
                {"$match": {"students.student_id": sid}},
                {
                    "$group": {
                        "_id": "$students.student_id",
                        "present": {
                            "$sum": {
                                "$cond": [
                                    {"$eq": ["$students.status", "Present"]},
                                    1,
                                    0,
                                ]
                            }
                        },
                        "late": {
                            "$sum": {
                                "$cond": [
                                    {"$eq": ["$students.status", "Late"]},
                                    1,
                                    0,
                                ]
                            }
                        },
                        "total": {"$sum": 1},
                    }
                },
            ]

            agg = list(attendance_logs_col.aggregate(pipeline))
            if agg:
                present = agg[0]["present"]
                late = agg[0]["late"]
                total = agg[0]["total"]
                attendance_rate = (
                    round(((present + late) / total) * 100, 2) if total > 0 else None
                )
            else:
                attendance_rate = None

            normalized.append(
                {
                    "student_id": sid,
                    "first_name": s.get("First_Name"),
                    "last_name": s.get("Last_Name"),
                    "middle_name": s.get("Middle_Name"),
                    "course": s.get("Course"),
                    "section": s.get("Section"),
                    "created_at": s.get("created_at"),
                    "attendance_rate": attendance_rate,
                }
            )

        return jsonify(normalized), 200

    except Exception as e:
        print("❌ Error fetching students:", e)
        return jsonify({"error": "Server error", "details": str(e)}), 500


# ============================================================
# 📌 GET SINGLE STUDENT — Filtered by Admin’s Program
# ============================================================
@admin_bp.route("/api/admin/students/<student_id>", methods=["GET"])
@jwt_required()
def get_student(student_id):
    try:
        identity = get_jwt_identity()
        program = identity.get("program") if isinstance(identity, dict) else None

        # 🧩 Only fetch student within admin’s program
        query = {"student_id": student_id}
        if program:
            query["$or"] = [
                {"Course": {"$regex": f"^{program}$", "$options": "i"}},
                {"course": {"$regex": f"^{program}$", "$options": "i"}},
            ]

        student = students_col.find_one(query)
        if not student:
            return (
                jsonify({"error": "Student not found or not in your program"}),
                404,
            )

        # ✅ Compute attendance stats
        pipeline = [
            {"$unwind": "$students"},
            {"$match": {"students.student_id": student_id}},
            {
                "$group": {
                    "_id": "$students.student_id",
                    "present": {
                        "$sum": {
                            "$cond": [
                                {"$eq": ["$students.status", "Present"]},
                                1,
                                0,
                            ]
                        }
                    },
                    "late": {
                        "$sum": {
                            "$cond": [
                                {"$eq": ["$students.status", "Late"]},
                                1,
                                0,
                            ]
                        }
                    },
                    "total": {"$sum": 1},
                }
            },
        ]
        agg = list(attendance_logs_col.aggregate(pipeline))

        if agg:
            present = agg[0]["present"]
            late = agg[0]["late"]
            total = agg[0]["total"]
            attendance_rate = (
                round(((present + late) / total) * 100, 2) if total > 0 else None
            )
        else:
            attendance_rate = None

        return (
            jsonify(
                {
                    "student_id": student.get("student_id"),
                    "first_name": student.get("First_Name"),
                    "last_name": student.get("Last_Name"),
                    "middle_name": student.get("Middle_Name"),
                    "course": student.get("Course"),
                    "section": student.get("Section"),
                    "created_at": student.get("created_at"),
                    "attendance_rate": attendance_rate,
                }
            ),
            200,
        )

    except Exception as e:
        print("❌ Error fetching student:", e)
        return jsonify({"error": "Server error", "details": str(e)}), 500

# 📌 UPDATE STUDENT
@admin_bp.route("/api/admin/students/<student_id>", methods=["PUT"])
def update_student(student_id):
    data = request.get_json() or {}
    update_data = {}
    if "first_name" in data:
        update_data["First_Name"] = data["first_name"]
    if "last_name" in data:
        update_data["Last_Name"] = data["last_name"]
    if "middle_name" in data:
        update_data["Middle_Name"] = data["middle_name"]
    if "course" in data:
        update_data["Course"] = data["course"]
    if "section" in data:
        update_data["Section"] = data["section"]

    if not update_data:
        return jsonify({"error": "No valid fields provided"}), 400

    result = students_col.update_one({"student_id": student_id}, {"$set": update_data})
    if result.matched_count == 0:
        return jsonify({"error": "Student not found"}), 404
    return jsonify({"message": "Student updated successfully"}), 200


# 📌 DELETE STUDENT
@admin_bp.route("/api/admin/students/<student_id>", methods=["DELETE"])
def delete_student(student_id):
    """Delete a student record and refresh the face embeddings cache."""
    try:
        # Attempt to delete the student document
        result = students_col.delete_one({"student_id": student_id})
        if result.deleted_count == 0:
            return jsonify({"error": "Student not found"}), 404

        # ✅ Refresh the cached embeddings after deletion
        print(f"🗑️ Student {student_id} deleted — refreshing face cache...")

        # Import the helper from your face blueprint (same function inside /login)
        from routes.face_routes import refresh_face_cache

        refresh_face_cache()  # Rebuilds CACHED_FACES in memory

        return jsonify({
            "message": f"Student {student_id} deleted successfully and cache refreshed."
        }), 200

    except Exception as e:
        import traceback
        print("❌ Error deleting student:", e)
        print(traceback.format_exc())
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


# ==============================
# ✅ Subject Management
# ==============================
@admin_bp.route("/api/admin/subjects", methods=["GET"])
def get_subjects():
    subjects = list(subjects_col.find().sort("created_at", -1))
    return jsonify([_serialize_subject(s) for s in subjects])

@admin_bp.route("/api/admin/subjects", methods=["POST"])
def create_subject():
    data = request.get_json() or {}
    required_fields = [
        "subject_code",
        "subject_title",
        "course",
        "year_level",
        "semester",
    ]
    if not all(data.get(field) for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    subject_doc = {
        "subject_code": data["subject_code"],
        "subject_title": data["subject_title"],
        "course": data["course"],
        "year_level": data["year_level"],
        "semester": data["semester"],
        "created_at": datetime.utcnow(),
    }

    result = subjects_col.insert_one(subject_doc)
    new_subject = subjects_col.find_one({"_id": result.inserted_id})
    if new_subject:
        new_subject["_id"] = str(new_subject["_id"])
    return jsonify(new_subject), 201

@admin_bp.route("/api/admin/subjects/<id>", methods=["PUT"])
def update_subject(id):
    data = request.get_json() or {}
    update_data = {}
    for field in ["subject_code", "subject_title", "course", "year_level", "semester"]:
        if field in data:
            update_data[field] = data[field]

    result = subjects_col.update_one({"_id": ObjectId(id)}, {"$set": update_data})
    if result.matched_count == 0:
        return jsonify({"error": "Subject not found"}), 404
    return jsonify({"message": "Subject updated successfully"}), 200

@admin_bp.route("/api/admin/subjects/<id>", methods=["DELETE"])
def delete_subject(id):
    result = subjects_col.delete_one({"_id": ObjectId(id)})
    if result.deleted_count == 0:
        return jsonify({"error": "Subject not found"}), 404
    return jsonify({"message": "Subject deleted successfully"}), 200


# ==============================
# ✅ Class Management
# ==============================
@admin_bp.route("/api/classes", methods=["GET"])
def get_all_classes():
    classes = list(classes_col.find().sort("created_at", -1))
    output = []

    for cls in classes:
        class_id = str(cls["_id"])

        # 🔹 Compute attendance stats
        stats = list(
            attendance_logs_col.aggregate([
                {"$match": {"class_id": class_id}},
                {"$unwind": "$students"},
                {"$group": {
                    "_id": "$students.status",
                    "count": {"$sum": 1}
                }}
            ])
        )

        total_logs = sum(s["count"] for s in stats)
        present_count = sum(s["count"] for s in stats if s["_id"] == "Present")
        late_count = sum(s["count"] for s in stats if s["_id"] == "Late")
        absent_count = sum(s["count"] for s in stats if s["_id"] == "Absent")

        attendance_rate = round(((present_count + late_count) / total_logs) * 100, 2) if total_logs > 0 else 0

        cls_data = _serialize_class(cls)
        cls_data["attendance_rate"] = attendance_rate
        cls_data["attendance_breakdown"] = {
            "present": present_count,
            "late": late_count,
            "absent": absent_count,
            "total": total_logs
        }

        output.append(cls_data)

    return jsonify(output), 200


@admin_bp.route("/api/classes/<id>", methods=["GET"])
def get_class(id):
    try:
        cls = classes_col.find_one({"_id": ObjectId(id)})
    except Exception:
        return jsonify({"error": "Invalid class ID"}), 400
    if not cls:
        return jsonify({"error": "Class not found"}), 404

    # 🔹 Compute attendance stats for this class
    class_id = str(cls["_id"])
    stats = list(
        attendance_logs_col.aggregate([
            {"$match": {"class_id": class_id}},
            {"$unwind": "$students"},
            {"$group": {
                "_id": "$students.status",
                "count": {"$sum": 1}
            }}
        ])
    )

    total_logs = sum(s["count"] for s in stats)
    present_count = sum(s["count"] for s in stats if s["_id"] == "Present")
    late_count = sum(s["count"] for s in stats if s["_id"] == "Late")
    absent_count = sum(s["count"] for s in stats if s["_id"] == "Absent")

    attendance_rate = round(((present_count + late_count) / total_logs) * 100, 2) if total_logs > 0 else 0

    cls_data = _serialize_class(cls)
    cls_data["attendance_rate"] = attendance_rate
    cls_data["attendance_breakdown"] = {
        "present": present_count,
        "late": late_count,
        "absent": absent_count,
        "total": total_logs
    }

    return jsonify(cls_data), 200


@admin_bp.route("/api/classes/<id>", methods=["PUT"])
def update_class(id):
    data = request.get_json() or {}
    update_data = {}
    for field in [
        "section",
        "semester",
        "schedule_blocks",
        "instructor_id",
        "instructor_first_name",
        "instructor_last_name",
    ]:
        if field in data:
            update_data[field] = data[field]
    if not update_data:
        return jsonify({"error": "No valid fields provided"}), 400

    try:
        result = classes_col.update_one({"_id": ObjectId(id)}, {"$set": update_data})
    except Exception:
        return jsonify({"error": "Invalid class ID"}), 400
    if result.matched_count == 0:
        return jsonify({"error": "Class not found"}), 404
    return jsonify({"message": "Class updated successfully"}), 200


@admin_bp.route("/api/classes/<id>", methods=["DELETE"])
def delete_class(id):
    try:
        result = classes_col.delete_one({"_id": ObjectId(id)})
    except Exception:
        return jsonify({"error": "Invalid class ID"}), 400
    if result.deleted_count == 0:
        return jsonify({"error": "Class not found"}), 404
    return jsonify({"message": "Class deleted successfully"}), 200


# ==============================
# ✅ Instructor Management
# ==============================
@admin_bp.route("/api/instructors", methods=["GET"])
def get_all_instructors():
    instructors = list(instructors_col.find().sort("first_name", 1))
    formatted = []
    for instr in instructors:
        formatted.append(
            {
                "_id": str(instr.get("_id")),
                "instructor_id": instr.get("instructor_id"),
                "first_name": instr.get("first_name"),
                "last_name": instr.get("last_name"),
                "email": instr.get("email"),
            }
        )
    return jsonify(formatted), 200

@admin_bp.route("/api/classes/<class_id>/assign-instructor", methods=["PUT"])
def assign_instructor_to_class(class_id):
    data = request.get_json() or {}
    instructor_id = data.get("instructor_id")
    if not instructor_id:
        return jsonify({"error": "Instructor ID is required"}), 400

    instructor = instructors_col.find_one({"instructor_id": instructor_id})
    if not instructor:
        return jsonify({"error": "Instructor not found"}), 404

    update_data = {
        "instructor_id": instructor.get("instructor_id"),
        "instructor_first_name": instructor.get("first_name"),
        "instructor_last_name": instructor.get("last_name"),
        "is_attendance_active": False,
        "attendance_start_time": None,
        "attendance_end_time": None,
    }

    try:
        result = classes_col.update_one({"_id": ObjectId(class_id)}, {"$set": update_data})
    except Exception:
        return jsonify({"error": "Invalid class ID"}), 400
    if result.matched_count == 0:
        return jsonify({"error": "Class not found"}), 404

    return jsonify(
        {
            "message": "Instructor assigned successfully",
            "class_id": class_id,
            "instructor": {
                "instructor_id": update_data["instructor_id"],
                "first_name": update_data["instructor_first_name"],
                "last_name": update_data["instructor_last_name"],
            },
            "attendance_defaults": {
                "is_attendance_active": update_data["is_attendance_active"],
                "attendance_start_time": update_data["attendance_start_time"],
                "attendance_end_time": update_data["attendance_end_time"],
            },
        }
    ), 200

# ==============================
# ✅ Attendance Logs (Admin)
# ==============================
@admin_bp.route("/api/attendance/logs", methods=["GET"])
def get_attendance_logs():
    logs = []

    cursor = attendance_logs_col.find().sort("date", -1)
    for doc in cursor:
        class_id = str(doc.get("class_id"))
        subject_code = doc.get("subject_code", "")
        subject_title = doc.get("subject_title", "")
        instructor_first_name = doc.get("instructor_first_name", "")
        instructor_last_name = doc.get("instructor_last_name", "")
        section = doc.get("section", "")
        course = doc.get("course", "") 
        date = doc.get("date")

        # Flatten each student log
        for st in doc.get("students", []):
            logs.append({
                "student_id": st.get("student_id"),
                "first_name": st.get("first_name"),
                "last_name": st.get("last_name"),
                "status": st.get("status"),
                "time": st.get("time"),
                "date": date,
                "subject_code": subject_code,
                "subject_title": subject_title,
                "instructor_name": f"{instructor_first_name} {instructor_last_name}".strip(),
                "section": section,
                "course": course,  
                "class_id": class_id,
            })

    return jsonify(logs), 200


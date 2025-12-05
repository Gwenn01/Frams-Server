from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date
import os
import pandas as pd
from bson import ObjectId
from config.db_config import db
from models.admin_model import find_admin_by_user_id, find_admin_by_email, create_admin
from flask_jwt_extended import jwt_required, get_jwt, create_access_token


admin_bp = Blueprint("admin_bp", __name__)
secret_key = os.getenv("JWT_SECRET", os.getenv("JWT_SECRET_KEY", "yoursecretkey"))

# Collections
students_col = db["students"]
instructors_col = db["instructors"]
classes_col = db["classes"]
attendance_logs_col = db["attendance_logs"]
subjects_col = db["subjects"]
admins_col = db["admins"]
semesters_col = db["semesters"]

# Helpers
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

# Helper to serialize class documents
def _serialize_class(cls):
    students = cls.get("students", [])
    return {
        "_id": str(cls.get("_id")),
        "subject_code": cls.get("subject_code"),
        "subject_title": cls.get("subject_title"),
        "course": cls.get("course"),
        "year_level": cls.get("year_level"),
        "semester": cls.get("semester"),
        "school_year": cls.get("school_year"),
        "section": cls.get("section"),
        "instructor_id": cls.get("instructor_id"),
        "instructor_first_name": cls.get("instructor_first_name"),
        "instructor_last_name": cls.get("instructor_last_name"),
        "schedule_blocks": cls.get("schedule_blocks", []),
        "student_count": len(students),
        "students": students,
        "created_at": cls.get("created_at"),
    }

def _admin_program():
    claims = get_jwt()
    return claims.get("program", "").upper()

# Auth: Register (after frontend OTP)
@admin_bp.route("/api/admin/register", methods=["POST"])
def register_admin():
    data = request.get_json() or {}

    first_name = (data.get("first_name") or "").strip()
    last_name = (data.get("last_name") or "").strip()
    user_id = (data.get("user_id") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    program = (data.get("program") or "").strip().upper() 

    # Validate required fields
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

    # Save admin data
    hashed_password = generate_password_hash(password)
    full_name = f"{first_name} {last_name}".strip()

    admin_data = {
        "first_name": first_name,
        "last_name": last_name,
        "full_name": full_name,
        "user_id": user_id,
        "email": email,
        "password": hashed_password,
        "program": program, 
        "created_at": datetime.utcnow(),
    }

    create_admin(admin_data)

    return jsonify({"message": f"Admin for {program} registered successfully"}), 201

# Auth: Login
@admin_bp.route("/api/admin/login", methods=["POST"])
def login_admin():
    data = request.get_json() or {}
    user_id = (data.get("user_id") or "").strip()
    password = data.get("password") or ""

    admin = admins_col.find_one({"user_id": user_id})
    if not admin:
        return jsonify({"error": "Invalid User ID"}), 401

    if not check_password_hash(admin["password"], password):
        return jsonify({"error": "Incorrect password"}), 401

    program = admin.get("program")  

    token = create_access_token(
        identity=user_id,
        additional_claims={
            "role": "admin",
            "program": program
        },
        expires_delta=timedelta(hours=12),
    )

    return jsonify(
        {
            "token": token,
            "message": "Login successful",
            "admin": {
                "user_id": admin.get("user_id"),
                "first_name": admin.get("first_name"),
                "last_name": admin.get("last_name"),
                "program": program,
            },
        }
    ), 200

# Admin Profile (for Student Register Page)
@admin_bp.route("/api/admin/profile", methods=["GET"])
@jwt_required()
def get_admin_profile():
    claims = get_jwt()
    admin_id = claims.get("sub")
    program = claims.get("program")

    admin_doc = admins_col.find_one({"user_id": admin_id})
    if not admin_doc:
        return jsonify({"error": "Admin not found"}), 404

    return jsonify({
        "user_id": admin_doc.get("user_id"),
        "first_name": admin_doc.get("first_name"),
        "last_name": admin_doc.get("last_name"),
        "email": admin_doc.get("email"),
        "program": admin_doc.get("program", program or "Unknown Program")
    }), 200

# Admin Overview Endpoints
@admin_bp.route("/api/admin/overview/stats", methods=["GET"])
def get_stats():
    program = request.args.get("program")  
    today = datetime.utcnow().strftime("%Y-%m-%d")

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

    student_filter = {"$or": [
        {"course": {"$regex": f"^{program}$", "$options": "i"}},
        {"Course": {"$regex": f"^{program}$", "$options": "i"}}
    ]} if program else {}

    class_filter = {"$or": [
        {"course": {"$regex": f"^{program}$", "$options": "i"}},
        {"Course": {"$regex": f"^{program}$", "$options": "i"}}
    ]} if program else {}

    total_instructors = instructors_col.count_documents({})

    return jsonify(
        {
            "total_students": students_col.count_documents(student_filter),
            "total_instructors": total_instructors,
            "total_classes": classes_col.count_documents(class_filter),
            "attendance_today": attendance_today,
        }
    )

@admin_bp.route("/api/admin/overview/recent-logs", methods=["GET"])
def recent_logs():
    program = request.args.get("program")
    limit = int(request.args.get("limit", 5))

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

# Student Management
# GET ALL STUDENTS — Filtered by Admin’s Program
@admin_bp.route("/api/admin/students", methods=["GET"])
@jwt_required()
def get_all_students():
    claims = get_jwt()
    program = claims.get("program")

    course_filter = {}
    if program:
        course_filter["$or"] = [
            {"Course": {"$regex": f"^{program}$", "$options": "i"}},
            {"course": {"$regex": f"^{program}$", "$options": "i"}},
        ]

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

        pipeline = [
            {"$unwind": "$students"},
            {"$match": {"students.student_id": sid}},
            {
                "$group": {
                    "_id": "$students.student_id",
                    "present": {
                        "$sum": {"$cond": [{"$eq": ["$students.status", "Present"]}, 1, 0]}
                    },
                    "late": {
                        "$sum": {"$cond": [{"$eq": ["$students.status", "Late"]}, 1, 0]}
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

#  GET SINGLE STUDENT — Filtered by Admin’s Program
@admin_bp.route("/api/admin/students/<student_id>", methods=["GET"])
@jwt_required()
def get_student(student_id):
    claims = get_jwt()
    program = claims.get("program")

    query = {"student_id": student_id}
    if program:
        query["$or"] = [
            {"Course": {"$regex": f"^{program}$", "$options": "i"}},
            {"course": {"$regex": f"^{program}$", "$options": "i"}},
        ]

    student = students_col.find_one(query)
    if not student:
        return jsonify({"error": "Student not found or not in your program"}), 404

    pipeline = [
        {"$unwind": "$students"},
        {"$match": {"students.student_id": student_id}},
        {
            "$group": {
                "_id": "$students.student_id",
                "present": {
                    "$sum": {"$cond": [{"$eq": ["$students.status", "Present"]}, 1, 0]}
                },
                "late": {
                    "$sum": {"$cond": [{"$eq": ["$students.status", "Late"]}, 1, 0]}
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

    return jsonify(
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
    ), 200

# UPDATE STUDENT
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


# DELETE STUDENT
@admin_bp.route("/api/admin/students/<student_id>", methods=["DELETE"])
def delete_student(student_id):
    """Delete a student record and refresh the face embeddings cache."""
    try:
        result = students_col.delete_one({"student_id": student_id})
        if result.deleted_count == 0:
            return jsonify({"error": "Student not found"}), 404

        print(f"🗑️ Student {student_id} deleted — refreshing face cache...")

        from routes.face_routes import refresh_face_cache

        refresh_face_cache() 

        return jsonify({
            "message": f"Student {student_id} deleted successfully and cache refreshed."
        }), 200

    except Exception as e:
        import traceback
        print("Error deleting student:", e)
        print(traceback.format_exc())
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

# ✅ Subject Management
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

@admin_bp.route("/api/admin/semester/current", methods=["GET"])
@jwt_required()
def get_current_semester():
    try:
        sem = db.semesters.find_one()
        if not sem:
            return jsonify({"error": "No semester found"}), 404

        sem["_id"] = str(sem["_id"])
        return jsonify(sem), 200

    except Exception as e:
        print("GET /semester/current error:", e)
        return jsonify({"error": str(e)}), 500


@admin_bp.route("/api/admin/semester", methods=["PUT"])
def update_single_semester():
    try:
        data = request.get_json() or {}

        required = ["semester_name", "start_date", "end_date"]
        if not all(data.get(f) for f in required):
            return jsonify({"error": "Missing required fields"}), 400

        # Normalize semester input
        def normalize_semester(name):
            name = name.lower().strip()
            if "1st" in name:
                return "1st Sem"
            if "2nd" in name:
                return "2nd Sem"
            if "summer" in name:
                return "Summer"
            return name.title()

        normalized_semester = normalize_semester(data["semester_name"])

        start_year = int(data["start_date"][0:4])
        start_month = int(data["start_date"][5:7])

        if start_month <= 7:
            school_year = f"{start_year - 1}-{start_year}"
        else:
            school_year = f"{start_year}-{start_year + 1}"

        # Build update document
        update_data = {
            "semester_name": normalized_semester,
            "school_year": school_year,
            "start_date": data["start_date"],
            "end_date": data["end_date"],
            "is_active": True,
        }

        # Update the only semester document
        db.semesters.update_one({}, {"$set": update_data})

        sem = db.semesters.find_one()
        sem["_id"] = str(sem["_id"])

        return jsonify({
            "message": "Semester updated successfully",
            "semester": sem
        }), 200

    except Exception as e:
        print("❌ PUT /semester error:", e)
        return jsonify({"error": str(e)}), 500
    
@admin_bp.route("/api/admin/curriculum", methods=["GET"])
@jwt_required()
def get_curriculums():
    """Return all distinct curriculum values from subjects collection."""
    try:
        curr_list = subjects_col.distinct("curriculum")
        curr_list = sorted(list({str(c).strip() for c in curr_list if c}))

        return jsonify({"curriculums": curr_list}), 200

    except Exception as e:
        print("Error in GET /curriculum:", e)
        return jsonify({"error": "Failed to load curriculum list"}), 500

@admin_bp.route("/api/admin/semester/activate", methods=["PUT"])
def activate_single_semester():
    try:
        sem = db.semesters.find_one()
        if not sem:
            return jsonify({"error": "No semester exists"}), 404

        def normalize_semester(name):
            name = name.lower().strip()
            if "1st" in name:
                return "1st Sem"
            if "2nd" in name:
                return "2nd Sem"
            if "summer" in name:
                return "Summer"
            return name

        normalized_sem = normalize_semester(sem["semester_name"])

        # Save normalized name back to DB
        db.semesters.update_one({"_id": sem["_id"]}, {
            "$set": {
                "semester_name": normalized_sem,
                "is_active": True
            }
        })

        # Match & update subjects to use the new school year
        school_year = sem["school_year"]

        result = db.subjects.update_many(
            {"semester": {"$regex": f"^{normalized_sem}$", "$options": "i"}},
            {"$set": {"school_year": school_year}}
        )

        updated_sem = db.semesters.find_one({"_id": sem["_id"]})
        updated_sem["_id"] = str(updated_sem["_id"])

        return jsonify({
            "message": "Semester activated successfully",
            "subjects_updated": result.modified_count,
            "active_semester": updated_sem
        }), 200

    except Exception as e:
        print("PUT /semester/activate error:", e)
        return jsonify({"error": str(e)}), 500
    
@admin_bp.route("/api/admin/subjects/active", methods=["GET"])
@jwt_required()
def get_active_subjects():
    try:
        claims = get_jwt()
        admin_program = claims.get("program")
        if not admin_program:
            return jsonify({"error": "Admin program not found in token"}), 400

        # Fetch active semester
        active_sem = db.semesters.find_one({"is_active": True})
        if not active_sem:
            return jsonify({"message": "No active semester found"}), 404

        # Normalize semester name to match subject documents
        def normalize_semester(name):
            name = name.lower()
            if "1st" in name:
                return "1st Sem"
            if "2nd" in name:
                return "2nd Sem"
            if "summer" in name:
                return "Summer"
            return name

        normalized_sem = normalize_semester(active_sem["semester_name"])

        subjects = list(
            db.subjects.find({
                "semester": normalized_sem,
                "course": {"$regex": f"^{admin_program}$", "$options": "i"}
            }).sort("year_level", 1)
        )

        for subj in subjects:
            subj["_id"] = str(subj["_id"])

        return jsonify({
            "active_semester": {
                "_id": str(active_sem["_id"]),
                "semester_name": active_sem["semester_name"],
                "normalized_semester": normalized_sem,
                "school_year": active_sem["school_year"],
                "program": admin_program
            },
            "subjects": subjects
        }), 200

    except Exception as e:
        print("Error in get_active_subjects:", e)
        return jsonify({"error": str(e)}), 500


# Class Management 
from datetime import datetime
import pandas as pd

@admin_bp.route("/api/classes", methods=["POST"])
@jwt_required()
def create_class():
    admin_program = _admin_program() 

    data = request.get_json() or {}

    required_fields = [
        "subject_code", "subject_title", "course",
        "year_level", "section", "instructor_id"
    ]


    if not all(data.get(field) for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400
    
    if data["course"].upper() != admin_program:
        return jsonify({"error": "You are not allowed to create a class for another program"}), 403

    active_sem = semesters_col.find_one({"is_active": True})
    if not active_sem:
        return jsonify({"error": "No active semester found. Please set an active semester first."}), 400

    instructor = instructors_col.find_one({"instructor_id": data["instructor_id"]})
    if not instructor:
        return jsonify({"error": "Instructor not found"}), 404

    new_class = {
        "subject_code": data["subject_code"],
        "subject_title": data["subject_title"],
        "course": data["course"],
        "year_level": data["year_level"],
        "semester": active_sem["semester_name"],
        "school_year": active_sem["school_year"],
        "section": data["section"],
        "schedule_blocks": data.get("schedule_blocks", []),
        "instructor_id": instructor["instructor_id"],
        "instructor_first_name": instructor["first_name"],
        "instructor_last_name": instructor["last_name"],
        "students": [],
        "is_attendance_active": False,
        "attendance_start_time": None,
        "attendance_end_time": None,
        "created_at": datetime.utcnow(),
    }

    result = classes_col.insert_one(new_class)
    cls = classes_col.find_one({"_id": result.inserted_id})

    return jsonify(_serialize_class(cls)), 201

# Get all classes (filtered by admin program + active semester)
@admin_bp.route("/api/classes", methods=["GET"])
@jwt_required()
def get_all_classes():
    admin_program = _admin_program()

    active_sem = semesters_col.find_one({"is_active": True})
    if not active_sem:
        return jsonify({"error": "No active semester found"}), 400

    active_semester = active_sem["semester_name"]
    active_school_year = active_sem["school_year"]

    classes = list(classes_col.find({
        "course": {"$regex": f"^{admin_program}$", "$options": "i"},
        "semester": active_semester,
        "school_year": active_school_year
    }).sort("created_at", -1))

    output = []

    for cls in classes:
        class_id = str(cls["_id"])

        stats = list(attendance_logs_col.aggregate([
            {"$match": {"class_id": class_id}},
            {"$unwind": "$students"},
            {"$group": {"_id": "$students.status", "count": {"$sum": 1}}}
        ]))

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

# Get single class
@admin_bp.route("/api/classes/<id>", methods=["GET"])
@jwt_required()
def get_class(id):
    admin_program = _admin_program()

    try:
        cls = classes_col.find_one({"_id": ObjectId(id)})
    except Exception:
        return jsonify({"error": "Invalid class ID"}), 400

    if not cls:
        return jsonify({"error": "Class not found"}), 404

    # Block access if class belongs to another program
    if cls.get("course", "").upper() != admin_program:
        return jsonify({"error": "You are not allowed to access classes from another program"}), 403

    class_id = str(cls["_id"])
    stats = list(attendance_logs_col.aggregate([
        {"$match": {"class_id": class_id}},
        {"$unwind": "$students"},
        {"$group": {"_id": "$students.status", "count": {"$sum": 1}}}
    ]))

    total_logs = sum(s["count"] for s in stats)
    present_count = sum(s["count"] for s in stats if s["_id"] == "Present")
    late_count = sum(s["count"] for s in stats if s["_id"] == "Late")
    absent_count = sum(s["count"] for s in stats if s["_id"] == "Absent")

    attendance_rate = (
        round(((present_count + late_count) / total_logs) * 100, 2)
        if total_logs > 0 else 0
    )

    cls_data = _serialize_class(cls)
    cls_data["attendance_rate"] = attendance_rate
    cls_data["attendance_breakdown"] = {
        "present": present_count,
        "late": late_count,
        "absent": absent_count,
        "total": total_logs
    }

    return jsonify(cls_data), 200

# Update class details or instructor
@admin_bp.route("/api/classes/<id>", methods=["PUT"])
@jwt_required()
def update_class(id):
    admin_program = _admin_program()
    data = request.get_json() or {}

    cls = classes_col.find_one({"_id": ObjectId(id)})

    if not cls:
        return jsonify({"error": "Class not found"}), 404

    if cls["course"].upper() != admin_program:
        return jsonify({"error": "You are not allowed to modify another program's class"}), 403

    update_data = {}

    for field in ["section", "semester", "schedule_blocks"]:
        if field in data:
            update_data[field] = data[field]

    if "instructor_id" in data and data["instructor_id"]:

        instructor = instructors_col.find_one({"instructor_id": data["instructor_id"]})

        if not instructor:
            return jsonify({"error": "Instructor not found"}), 404

        update_data["instructor_id"] = instructor["instructor_id"]
        update_data["instructor_first_name"] = instructor["first_name"]
        update_data["instructor_last_name"] = instructor["last_name"]

    if not update_data:
        return jsonify({"error": "No valid fields provided"}), 400

    try:
        result = classes_col.update_one(
            {"_id": ObjectId(id)},
            {"$set": update_data}
        )
    except Exception as e:
        print("Update error:", e)
        return jsonify({"error": "Invalid class ID"}), 400

    if result.matched_count == 0:
        return jsonify({"error": "Class not found"}), 404

    return jsonify({"message": "Class updated successfully"}), 200

# Upload students via PDF + Program Restriction 
@admin_bp.route("/api/classes/<class_id>/upload-students", methods=["POST"])
@jwt_required()
def upload_students_to_class(class_id):
    import re
    import pdfplumber
    from io import BytesIO

    try:
        admin = get_jwt()
        admin_program = admin.get("program", "").upper()

        cls = classes_col.find_one({"_id": ObjectId(class_id)})
        if not cls:
            return jsonify({"error": "Class not found"}), 404

        if cls["course"].upper() != admin_program:
            return jsonify({
                "error": "Forbidden — You cannot upload students to another program's class"
            }), 403

        file = request.files.get("file")
        if not file:
            return jsonify({"error": "No file uploaded"}), 400

        file_bytes = BytesIO(file.read())

        with pdfplumber.open(file_bytes) as pdf:
            full_text = "\n".join([
                page.extract_text() or "" for page in pdf.pages
            ])

        lines = full_text.split("\n")

        header_line = next(line for line in lines if "Class List (" in line)
        inside = re.search(r"\((.*?)\)", header_line).group(1)

        school_year, semester_raw = [x.strip() for x in inside.split("/")]

        semester_map = {
            "First Semester": "1st Sem",
            "Second Semester": "2nd Sem",
            "Summer": "Mid Year"
        }
        semester = semester_map.get(semester_raw, semester_raw)

        header_idx = next(i for i, l in enumerate(lines) if "Class List (" in l)

        instructor_raw = lines[header_idx + 1].strip().title()
        name_parts = instructor_raw.split(" ")

        instructor_last_name = name_parts[-1]
        instructor_first_name = " ".join(name_parts[:-1])

        instructor_doc = instructors_col.find_one({
            "first_name": instructor_first_name,
            "last_name": instructor_last_name
        })

        if not instructor_doc:
            return jsonify({"error": f"Instructor '{instructor_raw}' not found"}), 404

        instructor_id = instructor_doc["instructor_id"]

        class_code = None
        for line in lines:
            if "Class:" in line:
                m = re.search(r"Class:\s*([A-Za-z0-9]+)", line)
                if m:
                    class_code = m.group(1) 
                break

        course_section = None

        for line in lines:
            if "Class:" in line and "::" in line:
                parts = [p.strip() for p in line.split("::")]
                if len(parts) > 1:
                    course_section = parts[1]  
                break

        if not course_section:
            return jsonify({"error": "Unable to extract course & section"}), 400

        course, section = course_section.rsplit(" ", 1)

        if course.upper() != admin_program:
            return jsonify({
                "error": f"Course '{course}' does NOT match your program '{admin_program}'"
            }), 403

        subject_code = None

        for line in lines:
            if "Class:" in line and "::" in line:
                parts = [p.strip() for p in line.split("::")]
                if len(parts) > 2:
                    subject_code = parts[2]  # "SA 101"
                break

        if not subject_code:
            return jsonify({"error": "Unable to extract subject code"}), 400

        subject_doc = subjects_col.find_one({"subject_code": subject_code})
        if not subject_doc:
            return jsonify({"error": f"Subject '{subject_code}' not found"}), 404

        subject_title = subject_doc["subject_title"]
        year_level = subject_doc["year_level"]

        student_ids = re.findall(r"\b\d{2}-\d-\d-\d{4}\b", full_text)

        if not student_ids:
            return jsonify({"error": "No student IDs found in PDF"}), 400

        students_list = []
        skipped_ids = []

        for sid in student_ids:
            stu = students_col.find_one({"student_id": sid})

            if not stu:
                skipped_ids.append(sid)
                continue  

            students_list.append({
                "student_id": sid,
                "first_name": stu.get("First_Name", "").strip(),
                "last_name": stu.get("Last_Name", "").strip(),
                "course": stu.get("Course") or course,
                "section": stu.get("Section") or section
            })

        classes_col.update_one(
            {"_id": ObjectId(class_id)},
            {"$set": {
                "class_code": class_code,
                "subject_code": subject_code,
                "subject_title": subject_title,
                "course": course,
                "section": section,
                "year_level": year_level,
                "semester": semester,
                "school_year": school_year,
                "instructor_id": instructor_id,
                "instructor_first_name": instructor_first_name,
                "instructor_last_name": instructor_last_name,
                "students": students_list,
                "schedule_blocks": []
            }}
        )

        return jsonify({
            "message": f"{len(students_list)} students uploaded successfully",
            "uploaded_count": len(students_list),
            "skipped_count": len(skipped_ids),
            "skipped_ids": skipped_ids,
            "class_code": class_code,
            "subject_code": subject_code,
            "subject_title": subject_title,
            "course": course,
            "section": section,
            "school_year": school_year,
            "semester": semester,
            "instructor": f"{instructor_first_name} {instructor_last_name}"
        }), 200

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500
    
# PREVIEW Class List PDF (WITH VALID/MISSING STUDENTS)
@admin_bp.route("/api/classes/preview-pdf", methods=["POST"])
@jwt_required()
def preview_class_pdf():
    import re
    import pdfplumber
    from io import BytesIO

    try:
        file = request.files.get("file")
        if not file:
            return jsonify({"error": "No file uploaded"}), 400

        file_bytes = BytesIO(file.read())

        with pdfplumber.open(file_bytes) as pdf:
            full_text = "\n".join([
                page.extract_text() or "" for page in pdf.pages
            ])

        lines = full_text.split("\n")

        header_line = next(line for line in lines if "Class List (" in line)
        inside = re.search(r"\((.*?)\)", header_line).group(1)

        school_year, semester_raw = [x.strip() for x in inside.split("/")]

        semester_map = {
            "First Semester": "1st Sem",
            "Second Semester": "2nd Sem",
            "Summer": "Mid Year"
        }
        semester = semester_map.get(semester_raw, semester_raw)

        header_idx = next(i for i, l in enumerate(lines) if "Class List (" in l)

        instructor_raw = lines[header_idx + 1].strip().title()
        name_parts = instructor_raw.split(" ")

        instructor_last_name = name_parts[-1]
        instructor_first_name = " ".join(name_parts[:-1])

        instructor_doc = instructors_col.find_one({
            "first_name": instructor_first_name,
            "last_name": instructor_last_name
        })
        instructor_id = instructor_doc["instructor_id"] if instructor_doc else None

        class_line = next((l for l in lines if l.startswith("Class:")), None)
        if not class_line:
            return jsonify({"error": "Cannot find class line"}), 400

        parts = [p.strip() for p in class_line.split("::")]

        m = re.search(r"Class:\s*([A-Za-z0-9]+)", parts[0])
        class_code = m.group(1) if m else None

        course_section = parts[1]  
        course, section = course_section.rsplit(" ", 1)

        subject_code = parts[2]

        subject_doc = subjects_col.find_one({"subject_code": subject_code})
        subject_title = subject_doc["subject_title"] if subject_doc else None
        year_level = subject_doc["year_level"] if subject_doc else None

        student_ids = re.findall(r"\b\d{2}-\d-\d-\d{4}\b", full_text)

        valid_students = []
        skipped_students = []

        for sid in student_ids:
            stu = students_col.find_one({"student_id": sid})
            if stu:
                valid_students.append({
                    "student_id": sid,
                    "first_name": stu.get("First_Name", "").strip(),
                    "last_name": stu.get("Last_Name", "").strip()
                })
            else:
                skipped_students.append(sid)

        return jsonify({
            "preview": True,
            "class_code": class_code,
            "course": course,
            "section": section,
            "school_year": school_year,
            "semester": semester,
            "subject_code": subject_code,
            "subject_title": subject_title,
            "year_level": year_level,
            "instructor_first_name": instructor_first_name,
            "instructor_last_name": instructor_last_name,
            "instructor_id": instructor_id,
            "student_ids": student_ids,
            "valid_students": valid_students,
            "skipped_students": skipped_students,
            "schedule_blocks": []
        }), 200

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

# Get students assigned to a class
@admin_bp.route("/api/classes/<class_id>/students", methods=["GET"])
@jwt_required()
def get_students_by_class(class_id):
    admin_program = _admin_program()

    try:
        cls = classes_col.find_one({"_id": ObjectId(class_id)})
    except Exception:
        return jsonify({"error": "Invalid class ID"}), 400

    if not cls:
        return jsonify({"error": "Class not found"}), 404

    if cls["course"].upper() != admin_program:
        return jsonify({"error": "Forbidden: You cannot access classes from another program"}), 403

    return jsonify(cls.get("students", [])), 200

# Delete a class
@admin_bp.route("/api/classes/<id>", methods=["DELETE"])
@jwt_required()
def delete_class(id):
    admin_program = _admin_program()

    try:
        cls = classes_col.find_one({"_id": ObjectId(id)})
    except Exception:
        return jsonify({"error": "Invalid class ID"}), 400

    if not cls:
        return jsonify({"error": "Class not found"}), 404

    if cls["course"].upper() != admin_program:
        return jsonify({"error": "Forbidden: You cannot delete another program’s class"}), 403

    result = classes_col.delete_one({"_id": cls["_id"]})

    return jsonify({"message": "Class deleted successfully"}), 200

# Get all free classes (no instructor assigned)
@admin_bp.route("/api/classes/free", methods=["GET"])
@jwt_required()
def get_free_classes():
    admin_program = get_jwt().get("program", "").upper()

    if not admin_program:
        return jsonify([]), 200

    free_classes = list(classes_col.find({
        "course": {"$regex": f"^{admin_program}$", "$options": "i"},
        "$or": [
            {"instructor_id": {"$exists": False}},
            {"instructor_id": ""},
            {"instructor_id": None}
        ]
    }).sort("created_at", -1))

    return jsonify([_serialize_class(cls) for cls in free_classes]), 200

# Instructor Management
@admin_bp.route("/api/instructors", methods=["GET"])
def get_all_instructors():
    instructors = list(instructors_col.find().sort("first_name", 1))
    formatted = []

    for instr in instructors:
        embeddings = instr.get("embeddings", {})

        formatted.append(
            {
                "_id": str(instr.get("_id")),
                "instructor_id": instr.get("instructor_id"),
                "first_name": instr.get("first_name"),
                "last_name": instr.get("last_name"),
                "email": instr.get("email"),
                "registered": instr.get("registered", False),
                "embeddings": list(embeddings.keys()) if embeddings else [],
            }
        )

    return jsonify(formatted), 200


@admin_bp.route("/api/classes/<class_id>/assign-instructor", methods=["PUT"])
@jwt_required()
def assign_instructor_to_class(class_id):
    try:
        admin_program = get_jwt().get("program", "").upper()
        try:
            cls = classes_col.find_one({"_id": ObjectId(class_id)})
        except Exception:
            return jsonify({"error": "Invalid class ID"}), 400

        if not cls:
            return jsonify({"error": "Class not found"}), 404

        if cls.get("course", "").upper() != admin_program:
            return jsonify({
                "error": "Forbidden: You cannot assign instructors to another program’s class"
            }), 403

        data = request.get_json() or {}
        instructor_id = data.get("instructor_id")

        if not instructor_id:
            return jsonify({"error": "Instructor ID is required"}), 400

        instructor = instructors_col.find_one({"instructor_id": instructor_id})
        if not instructor:
            return jsonify({"error": "Instructor not found"}), 404

        update_data = {
            "instructor_id": instructor.get("instructor_id"),
            "instructor_first_name": instructor.get("first_name", "N/A"),
            "instructor_last_name": instructor.get("last_name", "N/A"),
            "is_attendance_active": False,
            "attendance_start_time": None,
            "attendance_end_time": None,
        }

        classes_col.update_one(
            {"_id": ObjectId(class_id)},
            {"$set": update_data}
        )

        return jsonify({
            "message": "Instructor assigned successfully",
            "class_id": class_id,
            "instructor": {
                "instructor_id": update_data["instructor_id"],
                "first_name": update_data["instructor_first_name"],
                "last_name": update_data["instructor_last_name"],
            }
        }), 200

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500
    
@admin_bp.route("/api/instructors/<instructor_id>/classes", methods=["GET"])
@jwt_required()
def get_classes_by_instructor(instructor_id):
    claims = get_jwt()
    admin_program = claims.get("program", "").upper()

    # Get classes assigned to instructor
    classes = list(classes_col.find({
        "instructor_id": instructor_id,
        "course": {"$regex": f"^{admin_program}$", "$options": "i"}
    }))

    serialized = [_serialize_class(cls) for cls in classes]

    return jsonify(serialized), 200

# Attendance Logs (Admin)
@admin_bp.route("/api/attendance/logs", methods=["GET"])
def get_attendance_logs():
    try:
        logs = []

        # Fetch ALL documents from attendance_logs (sorted newest to oldest)
        cursor = attendance_logs_col.find().sort("date", -1)

        for doc in cursor:

            # Extract class-level fields from the document
            class_id = str(doc.get("class_id"))
            subject_code = doc.get("subject_code", "")
            subject_title = doc.get("subject_title", "")
            instructor_first_name = doc.get("instructor_first_name", "")
            instructor_last_name = doc.get("instructor_last_name", "")
            instructor_name = f"{instructor_first_name} {instructor_last_name}".strip()
            section = doc.get("section", "")
            course = doc.get("course", "")
            semester = doc.get("semester", "")
            school_year = doc.get("school_year", "")
            year_level = doc.get("year_level", "")
            date = doc.get("date")
            start_time = doc.get("start_time")
            end_time = doc.get("end_time")

            students = doc.get("students", [])
            for s in students:
                logs.append({
                    # Student details
                    "student_id": s.get("student_id"),
                    "first_name": s.get("first_name", ""),
                    "last_name": s.get("last_name", ""),
                    "status": s.get("status", ""),
                    "time": s.get("time", ""),
                    "date": date,
                    "start_time": start_time,
                    "end_time": end_time,
                    "class_id": class_id,
                    "subject_code": subject_code,
                    "subject_title": subject_title,
                    "section": section,
                    "course": course,
                    "year_level": year_level,
                    "instructor_name": instructor_name,
                    "semester": semester,
                    "school_year": school_year
                })

        return jsonify(logs), 200

    except Exception as e:
        print("❌ Error loading attendance logs:", e)
        return jsonify({"error": "Failed to load attendance logs"}), 500


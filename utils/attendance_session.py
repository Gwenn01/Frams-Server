from datetime import datetime, timedelta, timezone
from bson import ObjectId
from config.db_config import db
from models.attendance_model import has_logged_attendance

classes_collection = db["classes"]

attendance_active = False
current_class_id = None

# PH timezone
PH_TZ = timezone(timedelta(hours=8))

# -----------------------------
# Helpers
# -----------------------------
def _today_date_ph():
    """Return today's date normalized to midnight (PH time)."""
    return datetime.now(PH_TZ).replace(hour=0, minute=0, second=0, microsecond=0)

def refresh_session_state_from_db(instructor_id=None):
    """Sync local state with DB per instructor and auto-stop if end_time expired."""
    global attendance_active, current_class_id

    query = {"is_attendance_active": True}
    if instructor_id:
        query["instructor_id"] = instructor_id

    active = classes_collection.find_one(query)
    if active:
        end_time = active.get("attendance_end_time")
        if isinstance(end_time, str):
            try:
                end_time = datetime.fromisoformat(end_time)
            except Exception:
                end_time = None

        now_ph = datetime.now(PH_TZ)
        if end_time and now_ph >= end_time:
            stop_attendance_session(str(active["_id"]))
            attendance_active = False
            current_class_id = None
        else:
            attendance_active = True
            current_class_id = str(active["_id"])
    else:
        attendance_active = False
        current_class_id = None


def start_attendance_session(class_id, instructor_id=None):
    """Start attendance per instructor (won’t affect others)."""
    global attendance_active, current_class_id

    # 🔹 Check if the same instructor already has an active session
    query = {"is_attendance_active": True}
    if instructor_id:
        query["instructor_id"] = instructor_id

    active = classes_collection.find_one(query)
    if active:
        print(f"⚠️ Instructor {instructor_id} already has an active session for {active['_id']}")
        return False

    start_time = datetime.now(PH_TZ)
    end_time = start_time + timedelta(minutes=30)

    result = classes_collection.update_one(
        {"_id": ObjectId(class_id)},
        {"$set": {
            "is_attendance_active": True,
            "attendance_start_time": start_time.isoformat(),
            "attendance_end_time": end_time.isoformat(),
            "activated_by": instructor_id or "system",
            "instructor_id": instructor_id
        }}
    )

    if result.modified_count == 0:
        print(f"⚠️ Class {class_id} not updated (maybe wrong ObjectId?)")
        attendance_active = False
        current_class_id = None
        return False

    attendance_active = True
    current_class_id = class_id
    print(f"✅ Attendance session started for {class_id} by {instructor_id} (auto-stop at {end_time})")
    return True


def stop_attendance_session(class_id=None):
    """Stop an active attendance session (manual or auto)."""
    global attendance_active, current_class_id

    if not attendance_active:
        active = classes_collection.find_one({"is_attendance_active": True}, {"_id": 1})
        if not active:
            print("⚠️ No active session to stop")
            return False
        current_class_id = str(active["_id"])

    if class_id and class_id != current_class_id:
        print(f"⚠️ Tried to stop session for {class_id}, but active session is {current_class_id}")
        return False

    now_ph = datetime.now(PH_TZ)

    result = classes_collection.update_one(
        {"_id": ObjectId(current_class_id), "is_attendance_active": True},
        {"$set": {
            "is_attendance_active": False,
            "attendance_end_time": now_ph.isoformat()
        }}
    )

    if result.modified_count == 0:
        print(f"⚠️ Class {current_class_id} not updated on stop")
        return False

    print(f"🛑 Attendance session stopped for class {current_class_id}")
    attendance_active = False
    current_class_id = None
    return True


def already_logged_today(student_id, class_id, date_val=None):
    """
    Check if a student already logged attendance today.
    date_val: optional datetime or string (YYYY-MM-DD).
    """
    if date_val is None:
        date_val = _today_date_ph()
    return has_logged_attendance(student_id, class_id, date_val)

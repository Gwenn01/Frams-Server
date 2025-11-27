from datetime import datetime, timedelta, timezone
from bson import ObjectId
from config.db_config import db
from models.attendance_model import has_logged_attendance

classes_collection = db["classes"]
attendance_collection = db["attendance_logs"]

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
        # Check if expired
        end_time = active.get("attendance_end_time")
        try:
            end_dt = datetime.fromisoformat(end_time)
        except:
            end_dt = None

        now_ph = datetime.now(PH_TZ)

        if end_dt and now_ph >= end_dt:
            stop_attendance_session(str(active["_id"]))
            attendance_active = False
            current_class_id = None
        else:
            attendance_active = True
            current_class_id = str(active["_id"])
    else:
        attendance_active = False
        current_class_id = None


# -----------------------------
# START SESSION (UPDATED)
# -----------------------------
def start_attendance_session(class_id, instructor_id=None):
    """Start attendance session + create attendance_log document."""
    global attendance_active, current_class_id

    # Check if already active
    if classes_collection.find_one({"is_attendance_active": True, "instructor_id": instructor_id}):
        print("⚠️ Instructor already has an active session.")
        return False

    now = datetime.now(PH_TZ)
    end_time = now + timedelta(minutes=30)
    today_str = now.strftime("%Y-%m-%d")

    # 1️⃣ Create session log document
    new_log = {
        "class_id": str(class_id),
        "date": today_str,
        "start_time": now.strftime("%H:%M:%S"),
        "end_time": None,
        "students": [],
    }

    inserted = attendance_collection.insert_one(new_log)
    log_id = str(inserted.inserted_id)

    # 2️⃣ Save session + active_session_log_id into the class
    result = classes_collection.update_one(
        {"_id": ObjectId(class_id)},
        {"$set": {
            "is_attendance_active": True,
            "attendance_start_time": now.isoformat(),
            "attendance_end_time": end_time.isoformat(),
            "active_session_log_id": log_id,
            "activated_by": instructor_id or "system",
            "instructor_id": instructor_id
        }}
    )

    if result.modified_count == 0:
        print("⚠️ Session start failed.")
        return False

    attendance_active = True
    current_class_id = class_id

    print(f"✅ Started session for {class_id}, log_id={log_id}")
    return True


# -----------------------------
# STOP SESSION (UPDATED)
# -----------------------------
def stop_attendance_session(class_id=None):
    """Stop attendance + clear active_session_log_id."""
    global attendance_active, current_class_id

    # If no active in memory, check DB
    active = classes_collection.find_one({"is_attendance_active": True})
    if not active:
        print("⚠️ No active session to stop.")
        return False

    cls_id = str(active["_id"])
    log_id = active.get("active_session_log_id")

    now = datetime.now(PH_TZ)

    # Update class
    classes_collection.update_one(
        {"_id": ObjectId(cls_id)},
        {"$set": {
            "is_attendance_active": False,
            "attendance_end_time": now.isoformat(),
            "active_session_log_id": None
        }}
    )

    # Update log end time
    if log_id:
        attendance_collection.update_one(
            {"_id": ObjectId(log_id)},
            {"$set": {"end_time": now.strftime("%H:%M:%S")}}
        )

    print(f"🛑 Session stopped for class {cls_id}. log_id={log_id}")

    attendance_active = False
    current_class_id = None
    return True


# -----------------------------
# CHECK LOGGED TODAY
# -----------------------------
def already_logged_today(student_id, class_id, date_val=None):
    if date_val is None:
        date_val = _today_date_ph()
    return has_logged_attendance(student_id, class_id, date_val)

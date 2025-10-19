from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
import os

# ----------------------------
# Load Environment Variables
# ----------------------------
load_dotenv()

# ----------------------------
# Flask App Initialization
# ----------------------------
app = Flask(__name__)

# ✅ Allow both local + deployed frontend domains
CORS(
    app,
    resources={r"/*": {"origins": [
        "http://localhost:5173",               # local React dev
        "https://your-frontend-domain.com",    # replace with production frontend (if any)
        "https://meuorii-face-recognition-attendance.hf.space"  # allow Hugging Face microservice
    ]}},
    supports_credentials=True,
    expose_headers=["Content-Type", "Authorization"],
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
)

# ----------------------------
# Flask Config / Secrets
# ----------------------------
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "fallback-secret")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "fallback-jwt-secret")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False
os.environ.setdefault("JWT_SECRET", app.config["JWT_SECRET_KEY"])

# JWT Manager
jwt = JWTManager(app)

# ----------------------------
# Import Blueprints
# ----------------------------
from routes.auth_routes import auth_bp
from routes.student_routes import student_bp
from routes.instructor_routes import instructor_bp
from routes.attendance_routes import attendance_bp
from routes.face_routes import face_bp
from routes.admin_routes import admin_bp


# Register all blueprints
app.register_blueprint(auth_bp, url_prefix="/api/auth")
app.register_blueprint(student_bp, url_prefix="/api/student")
app.register_blueprint(instructor_bp, url_prefix="/api/instructor")
app.register_blueprint(attendance_bp, url_prefix="/api/attendance")
app.register_blueprint(face_bp, url_prefix="/api/face")
app.register_blueprint(admin_bp)

# ----------------------------
# Health + Root Routes
# ----------------------------
@app.route("/")
def home():
    return jsonify({
        "status": "ok",
        "message": "🚀 Face Recognition Attendance Backend is running!",
        "environment": os.getenv("RAILWAY_ENVIRONMENT", "development")
    }), 200


@app.route("/healthz")
def healthz():
    return jsonify(status="healthy"), 200


@app.errorhandler(404)
def not_found(_):
    return jsonify(error="Not found"), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify(error="Server error", detail=str(e)), 500


# ----------------------------
# Run App (For Railway)
# ----------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))  # ✅ Railway expects port 8080
    app.run(host="0.0.0.0", port=port, debug=False)

# ✅ Expose WSGI app for production (Gunicorn)
application = app

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
import os, requests

load_dotenv()
app = Flask(__name__)

# Single CORS configuration
allowed_origins = [
    "http://localhost:5173",
    "https://face-recognition-attendance-monitor.vercel.app",
    "https://meuorii-face-recognition-attendance.hf.space",
]

CORS(
    app,
    resources={r"/*": {"origins": allowed_origins}},
    supports_credentials=True,
    expose_headers=["Content-Type", "Authorization"],
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)

# JWT Config
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "fallback-secret")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "fallback-jwt-secret")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False
jwt = JWTManager(app)

# Blueprints
from routes.auth_routes import auth_bp
from routes.instructor_routes import instructor_bp
from routes.attendance_routes import attendance_bp
from routes.face_routes import face_bp
from routes.admin_routes import admin_bp

app.register_blueprint(auth_bp, url_prefix="/api/auth")
app.register_blueprint(instructor_bp, url_prefix="/api/instructor")
app.register_blueprint(attendance_bp, url_prefix="/api/attendance")
app.register_blueprint(face_bp, url_prefix="/api/face")
app.register_blueprint(admin_bp)

# Health checks 
@app.route("/")
def home():
    return jsonify(
        status="ok",
        message="Face Recognition Attendance Backend is running!",
        environment=os.getenv("RAILWAY_ENVIRONMENT", "development"),
    )

@app.route("/healthz")
def healthz():
    return jsonify(status="healthy")

@app.errorhandler(404)
def not_found(_):
    return jsonify(error="Not found"), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify(error="Server error", detail=str(e)), 500

@app.before_request
def allow_options_requests():
    if request.method == "OPTIONS":
        return ('', 200)

# Preload embeddings 
def preload_embeddings():
    try:
        print("Embeddings cached successfully!")
    except Exception as e:
        print(f"Failed to preload embeddings: {e}")

if hasattr(app, "before_serving"):
    app.before_serving(preload_embeddings)
elif hasattr(app, "before_first_request"):
    app.before_first_request(preload_embeddings)
else:
    preload_embeddings()

# Connectivity check
def check_reachability():
    urls = {
        "Hugging Face Space": "https://meuorii-face-recognition-attendance.hf.space",
        "Frontend (Vercel)": "https://face-recognition-attendance-monitor.vercel.app",
    }
    print("\nChecking external service connectivity...")
    for name, url in urls.items():
        try:
            res = requests.get(url, timeout=5)
            print(f"{name} reachable → {url}" if res.status_code == 200 else f"⚠️ {name} responded {res.status_code}")
        except Exception as e:
            print(f"{name} unreachable → {e}")

if __name__ == "__main__":
    print("Starting Flask app...")
    check_reachability()
    port = int(os.getenv("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)

application = app

"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
import secrets
import os
from pathlib import Path
from passlib.context import CryptContext
import json

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# --- Security: sessions and password hashing ---
# Secret key for session cookies (set SECRET_KEY env var in production)
secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.add_middleware(SessionMiddleware, secret_key=secret_key, https_only=False)

# Password hashing context (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Users file (repo root `users.json`). If missing, a default admin is created
USERS_FILE = Path(__file__).parent.parent / "users.json"

def load_users():
    if not USERS_FILE.exists():
        # Create default admin user if ADMIN_PASSWORD provided or fallback to 'changeme'
        admin_password = os.environ.get("ADMIN_PASSWORD", "changeme")
        admin = {"username": "admin", "password": pwd_context.hash(admin_password), "role": "ADMIN"}
        USERS_FILE.write_text(json.dumps({"admin": admin}, indent=2))
    try:
        return json.loads(USERS_FILE.read_text())
    except Exception:
        return {}

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_user(username: str):
    users = load_users()
    return users.get(username)

def set_session_user(request: Request, username: str):
    request.session["user"] = username
    # create a per-session CSRF token
    request.session["csrf_token"] = secrets.token_urlsafe(16)

def clear_session(request: Request):
    request.session.pop("user", None)
    request.session.pop("csrf_token", None)

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str, request: Request):
    """Sign up a student for an activity"""
    # Basic CSRF protection: require X-CSRF-Token header matching session
    header_token = request.headers.get("X-CSRF-Token")
    session_token = request.session.get("csrf_token")
    if not session_token or not header_token or header_token != session_token:
        raise HTTPException(status_code=403, detail="Missing or invalid CSRF token")
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, email: str, request: Request):
    """Unregister a student from an activity"""
    # Require authentication: only logged-in users can unregister
    if not request.session.get("user"):
        raise HTTPException(status_code=401, detail="Authentication required")

    # Basic CSRF protection
    header_token = request.headers.get("X-CSRF-Token")
    session_token = request.session.get("csrf_token")
    if not session_token or not header_token or header_token != session_token:
        raise HTTPException(status_code=403, detail="Missing or invalid CSRF token")
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}


# --- Authentication endpoints ---
@app.post("/login")
async def login(request: Request):
    payload = await request.json()
    username = payload.get("username")
    password = payload.get("password")
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password required")

    user = get_user(username)
    if not user or not verify_password(password, user.get("password")):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    set_session_user(request, username)
    return {"message": "logged in", "csrf_token": request.session.get("csrf_token")}


@app.post("/logout")
def logout(request: Request):
    clear_session(request)
    return {"message": "logged out"}

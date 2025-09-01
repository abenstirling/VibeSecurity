"""
Configuration and setup for Vibe Security application.
Contains Firebase initialization, FastAPI app setup, and middleware configuration.
"""

import os
import secrets

import firebase_admin
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from firebase_admin import credentials, firestore

# Load environment variables
load_dotenv()

# Firebase client configuration (safe to expose to frontend)
FIREBASE_CONFIG = {
    "api_key": os.getenv("FIREBASE_API_KEY", ""),
    "auth_domain": os.getenv("FIREBASE_AUTH_DOMAIN", ""),
    "project_id": os.getenv("FIREBASE_PROJECT_ID", ""),
    "storage_bucket": os.getenv("FIREBASE_STORAGE_BUCKET", ""),
    "messaging_sender_id": os.getenv("FIREBASE_MESSAGING_SENDER_ID", ""),
    "app_id": os.getenv("FIREBASE_APP_ID", ""),
    "measurement_id": os.getenv("FIREBASE_MEASUREMENT_ID", ""),
}

# CSRF token storage (in-memory for this example, consider using Redis in production)
csrf_tokens = {}


def initialize_firebase():
    """Initialize Firebase Admin SDK"""
    if not firebase_admin._apps:
        try:
            # Try to load from service account file
            cred = credentials.Certificate("vibesecurityco-firebase-adminsdk-fbsvc-bba0a870cf.json")
            firebase_admin.initialize_app(cred)
            print("Firebase initialized with service account file")
        except Exception as e:
            print(f"Error initializing Firebase with cert file: {str(e)}")
            # Fallback to application default credentials or admin config
            firebase_admin.initialize_app()
            print("Firebase initialized with application default credentials")

    return firestore.client()


def create_app():
    """Create and configure FastAPI application"""
    # Initialize FastAPI app with docs disabled
    app = FastAPI(docs_url=None, redoc_url=None)

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add CSRF middleware
    @app.middleware("http")
    async def csrf_middleware(request: Request, call_next):
        # Skip CSRF check for GET requests, static files, and API endpoints
        if request.method == "GET" or request.url.path.startswith("/static") or request.url.path.startswith("/api/"):
            return await call_next(request)

        # Get CSRF token from header
        csrf_token = request.headers.get("X-CSRF-Token")

        # If no token in header, try to get from form data
        if not csrf_token and request.headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
            form_data = await request.form()
            csrf_token = form_data.get("csrf_token")

        # Get session token from cookies
        session_token = request.cookies.get("session_token")

        # Verify CSRF token
        if not session_token or not csrf_token or csrf_token != csrf_tokens.get(session_token):
            return JSONResponse(status_code=403, content={"detail": "CSRF token missing or invalid"})

        response = await call_next(request)
        return response

    # Add middleware for security headers
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://www.gstatic.com https://www.googletagmanager.com https://platform.twitter.com https://syndication.twitter.com https://www.producthunt.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://platform.twitter.com https://www.producthunt.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; img-src 'self' data: https://api.producthunt.com; connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://www.googleapis.com https://syndication.twitter.com https://api.twitter.com https://www.producthunt.com https://api.producthunt.com; frame-src 'self' https://platform.twitter.com https://www.producthunt.com;"
        )
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        return response

    # Mount static files
    app.mount("/static", StaticFiles(directory="static"), name="static")

    return app


def generate_csrf_token(session_token: str) -> str:
    """Generate a new CSRF token for a session"""
    token = secrets.token_urlsafe(32)
    csrf_tokens[session_token] = token
    return token


def validate_csrf_token(session_token: str, csrf_token: str) -> bool:
    """Validate a CSRF token against the session token"""
    return csrf_tokens.get(session_token) == csrf_token


# Initialize Firebase and get Firestore client
db = initialize_firebase()

# Setup Jinja2 templates
templates = Jinja2Templates(directory="templates")

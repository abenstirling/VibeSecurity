"""
Main page routes for Vibe Security.
Contains routes for main pages like home, dashboard, blog, etc.
"""

import secrets

from fastapi import APIRouter, Request

from config import FIREBASE_CONFIG, generate_csrf_token, templates

router = APIRouter()


@router.get("/")
async def root(request: Request):
    """Home page with optional URL parameter for auto-scanning"""
    # Check for URL parameter
    url = request.query_params.get("url")

    # Generate session token if not exists
    session_token = request.cookies.get("session_token")
    if not session_token:
        session_token = secrets.token_urlsafe(32)

    # Generate CSRF token
    csrf_token = generate_csrf_token(session_token)

    if url:
        # Ensure URL is properly formatted
        if not url.startswith(("http://", "https://")):
            # Use the same protocol as the request
            protocol = request.url.scheme
            url = f"{protocol}://{url}"
        # Pass the URL to the template
        response = templates.TemplateResponse(
            "index.html",
            {"request": request, "target_url": url, "csrf_token": csrf_token, "firebase_config": FIREBASE_CONFIG},
        )
    else:
        response = templates.TemplateResponse(
            "index.html", {"request": request, "csrf_token": csrf_token, "firebase_config": FIREBASE_CONFIG}
        )

    # Set session cookie
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=True,
        samesite="Strict",
        max_age=3600,  # 1 hour
    )

    return response


@router.get("/dashboard")
async def dashboard(request: Request):
    """Dashboard page for authenticated users"""
    return templates.TemplateResponse("dashboard.html", {"request": request, "firebase_config": FIREBASE_CONFIG})


@router.get("/blog")
async def blog(request: Request):
    """Blog page"""
    return templates.TemplateResponse("blog.html", {"request": request})


@router.get("/privacy")
async def privacy(request: Request):
    """Privacy policy page"""
    from datetime import datetime

    return templates.TemplateResponse(
        "privacy.html",
        {"request": request, "firebase_config": FIREBASE_CONFIG, "current_date": datetime.now().strftime("%B %d, %Y")},
    )


@router.get("/terms")
async def terms(request: Request):
    """Terms of service page"""
    from datetime import datetime

    return templates.TemplateResponse(
        "terms.html",
        {"request": request, "firebase_config": FIREBASE_CONFIG, "current_date": datetime.now().strftime("%B %d, %Y")},
    )

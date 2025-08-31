"""
Core API routes for Vibe Security.
Contains main API endpoints for scanning, token verification, and contact forms.
"""

import asyncio

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from firebase_admin import auth, firestore

from config import db
from scanner import SecurityScanner

router = APIRouter()


@router.post("/api/scan")
async def scan_url(request: Request):
    """Scan a URL for security vulnerabilities"""
    try:
        data = await request.json()
        url = data.get("url")
        token = data.get("token")

        if not url:
            raise HTTPException(status_code=400, detail="URL is required")

        scanner = SecurityScanner(url)
        results = await scanner.scan()

        # Store scan in Firestore
        scan_ref = db.collection("scans").document()
        scan_data = {"url": url, "results": results, "timestamp": firestore.SERVER_TIMESTAMP}

        # If user is authenticated, use their UID, otherwise use "front_page"
        if token:
            try:
                decoded_token = auth.verify_id_token(token)
                user_id = decoded_token["uid"]
                print(f"Storing scan for user {user_id}")
                scan_data["userId"] = user_id
            except Exception as e:
                print(f"Error verifying token: {str(e)}")
                scan_data["userId"] = "front_page"
        else:
            scan_data["userId"] = "front_page"

        # Store the scan
        scan_ref.set(scan_data)
        print(f"Scan stored with ID: {scan_ref.id}")

        # Add a small delay to ensure the document is written before fetching history
        await asyncio.sleep(1)

        return JSONResponse(content=results)
    except Exception as e:
        print(f"Scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/api/verify-token")
async def verify_token_endpoint(request: Request):
    """Verify a Firebase authentication token"""
    try:
        data = await request.json()
        token = data.get("token")

        if not token:
            raise HTTPException(status_code=400, detail="Token is required")

        decoded_token = auth.verify_id_token(token)
        return JSONResponse(content={"uid": decoded_token["uid"]})
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e)) from e


@router.post("/api/contact")
async def contact_form(data: dict):
    """Handle contact form submissions"""
    try:
        # Store the message in Firestore
        message_ref = db.collection("contact_messages").document()
        message_data = {
            "name": data["name"],
            "email": data["email"],
            "message": data["message"],
            "timestamp": firestore.SERVER_TIMESTAMP,
            "status": "new",
        }
        message_ref.set(message_data)

        return {"status": "success", "message": "Contact form submitted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e

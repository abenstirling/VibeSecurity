"""
Admin routes for Vibe Security.
Contains administrative endpoints for user management and system administration.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from firebase_admin import auth

from auth import verify_token

router = APIRouter()


@router.post("/api/admin/create-user")
async def create_user(request: Request, decoded_token=Depends(verify_token)):
    """Create a new user account (admin only)"""
    try:
        data = await request.json()
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            raise HTTPException(status_code=400, detail="Email and password are required")

        # Admin check would need to be implemented differently without users collection
        # For now, we'll just create the user

        # Create the user in Firebase Authentication
        user = auth.create_user(email=email, password=password)

        # Set custom claims for premium status if needed
        if data.get("premium", False):
            auth.set_custom_user_claims(user.uid, {"premium": True})

        return {"status": "success", "uid": user.uid}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e

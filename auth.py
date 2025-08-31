"""
Authentication utilities and dependencies for Vibe Security.
Contains Firebase token verification and authentication helpers.
"""

import json

from fastapi import HTTPException, Request
from firebase_admin import auth


async def verify_token(request: Request):
    """Dependency to verify Firebase token"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        print("Missing or invalid Authorization header")
        raise HTTPException(status_code=401, detail="Invalid authentication header")

    token = auth_header.split("Bearer ")[1]
    try:
        # Try to verify the token
        decoded_token = auth.verify_id_token(token)

        # Check if uid is in the token
        if "uid" not in decoded_token:
            print(f"UID missing from token: {json.dumps(decoded_token)}")
            raise HTTPException(status_code=401, detail="Invalid token: missing UID")

        return decoded_token  # Return the full token
    except auth.InvalidIdTokenError as e:
        print("Invalid ID token error")
        raise HTTPException(status_code=401, detail="Invalid token") from e
    except auth.ExpiredIdTokenError as e:
        print("Token expired")
        raise HTTPException(status_code=401, detail="Token expired") from e
    except auth.RevokedIdTokenError as e:
        print("Token revoked")
        raise HTTPException(status_code=401, detail="Token revoked") from e
    except Exception as e:
        print(f"Token verification error: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Error verifying token: {str(e)}") from e


def get_user_id_from_token(decoded_token: dict) -> str:
    """Extract user ID from decoded token"""
    return decoded_token.get("uid")


def is_premium_user(decoded_token: dict) -> bool:
    """Check if user has premium status"""
    return decoded_token.get("premium", False)

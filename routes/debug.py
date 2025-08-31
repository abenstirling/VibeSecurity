"""
Debug routes for Vibe Security.
Contains debugging endpoints for system diagnostics and troubleshooting.
"""

from datetime import datetime

import firebase_admin
from fastapi import APIRouter, Request
from firebase_admin import auth, firestore

from config import db

router = APIRouter()


@router.get("/api/debug")
async def debug_info(request: Request):
    """Debug endpoint to verify Firebase connectivity"""
    try:
        # Check if Firebase Admin is initialized
        apps_count = len(firebase_admin._apps)

        # Try to get a collection reference
        users_ref = db.collection("users")

        # Try to get a single document to test connectivity
        test_docs = list(users_ref.limit(1).stream())
        docs_exist = len(test_docs) > 0

        return {
            "status": "ok",
            "firebase_apps": apps_count,
            "firestore_connected": True,
            "documents_exist": docs_exist,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        return {"status": "error", "error": str(e), "timestamp": datetime.now().isoformat()}


@router.get("/api/debug/all-scans")
async def all_scans_debug(request: Request):
    """Debug endpoint to show all scans in the system"""
    try:
        # Get all scans from Firestore
        scans_ref = db.collection("scans").order_by("timestamp", direction=firestore.Query.DESCENDING)
        scans = []
        user_ids = set()  # Track unique user IDs
        user_info_cache = {}  # Cache user info to avoid repeated lookups

        for scan in scans_ref.stream():
            try:
                scan_data = scan.to_dict()

                # Get user ID from any of the possible field names
                user_id = None
                if "userId" in scan_data:
                    user_id = scan_data["userId"]
                elif "user_id" in scan_data:
                    user_id = scan_data["user_id"]
                elif "userID" in scan_data:
                    user_id = scan_data["userID"]
                else:
                    user_id = "Unknown"

                # Add to set of unique user IDs
                if user_id != "Unknown":
                    user_ids.add(user_id)

                # Look up user email from Firebase Auth if we haven't cached it already
                if user_id != "Unknown" and user_id not in user_info_cache:
                    try:
                        auth_user = auth.get_user(user_id)
                        user_info_cache[user_id] = {"email": auth_user.email, "uid": auth_user.uid}
                    except Exception as e:
                        print(f"Error fetching user info for {user_id}: {str(e)}")
                        user_info_cache[user_id] = {"email": "Unknown", "uid": user_id}

                # Add user info to the scan data
                if user_id != "Unknown" and user_id in user_info_cache:
                    scan_data["userEmail"] = user_info_cache[user_id]["email"]
                else:
                    scan_data["userEmail"] = "Unknown"

                # Convert Firestore timestamps
                if "timestamp" in scan_data and hasattr(scan_data["timestamp"], "seconds"):
                    scan_data["timestamp"] = {
                        "seconds": scan_data["timestamp"].seconds,
                        "nanoseconds": scan_data["timestamp"].nanoseconds,
                        "date": datetime.fromtimestamp(scan_data["timestamp"].seconds).isoformat(),
                    }

                # Don't include full results to reduce payload size
                if "results" in scan_data:
                    if isinstance(scan_data["results"], dict) and "checks" in scan_data["results"]:
                        scan_data["results"] = {
                            "checksCount": len(scan_data["results"]["checks"]),
                            "summary": scan_data["results"].get("summary", {}),
                        }
                    elif isinstance(scan_data["results"], list):
                        scan_data["results"] = {"checksCount": len(scan_data["results"])}

                scan_data["id"] = scan.id
                scans.append(scan_data)
            except Exception as e:
                print(f"Error processing scan document {scan.id}: {str(e)}")

        return {
            "users_count": len(user_ids),
            "scans_count": len(scans),
            "scans": scans,
        }
    except Exception as e:
        print(f"All scans debug error: {str(e)}")
        return {"status": "error", "error": str(e), "timestamp": datetime.now().isoformat()}


@router.get("/api/debug/user-scans/{user_id}")
async def user_scans_debug(user_id: str):
    """Debug endpoint to show scans for a specific user"""
    try:
        print(f"Fetching scans for user ID: {user_id}")

        # First try direct match on userId field (usual location)
        scans_ref = (
            db.collection("scans")
            .where("userId", "==", user_id)
            .order_by("timestamp", direction=firestore.Query.DESCENDING)
        )

        scans = list(scans_ref.stream())
        print(f"Found {len(scans)} scans with exact userId match")

        # If no results, try checking all scans and looking for any field that might contain the user ID
        if not scans:
            print("No exact matches, checking all scans...")
            all_scans = list(
                db.collection("scans").order_by("timestamp", direction=firestore.Query.DESCENDING).stream()
            )
            matched_scans = []

            for scan in all_scans:
                scan_data = scan.to_dict()
                print(f"Checking scan {scan.id}")

                # Check userId with case-insensitive comparison
                if scan_data.get("userId") and scan_data.get("userId").lower() == user_id.lower():
                    print(f"  Found match by userId (case-insensitive): {scan_data.get('userId')}")
                    matched_scans.append(scan)
                    continue

                # Check user_id field
                if scan_data.get("user_id") and scan_data.get("user_id").lower() == user_id.lower():
                    print(f"  Found match by user_id field: {scan_data.get('user_id')}")
                    matched_scans.append(scan)
                    continue

                # Check userID field (alternative casing)
                if scan_data.get("userID") and scan_data.get("userID").lower() == user_id.lower():
                    print(f"  Found match by userID field: {scan_data.get('userID')}")
                    matched_scans.append(scan)
                    continue

                # Log field names for debugging
                print(f"  Scan fields: {list(scan_data.keys())}")

            scans = matched_scans
            print(f"Found {len(scans)} scans with flexible matching")

        scan_history = []
        for scan in scans:
            try:
                scan_data = scan.to_dict()
                scan_id = scan.id

                print(f"Processing scan {scan_id} with URL: {scan_data.get('url', 'Unknown')}")

                # Convert Firestore timestamps to a JSON-serializable format
                if "timestamp" in scan_data and hasattr(scan_data["timestamp"], "seconds"):
                    scan_data["timestamp"] = {
                        "seconds": scan_data["timestamp"].seconds,
                        "nanoseconds": scan_data["timestamp"].nanoseconds,
                        "date": datetime.fromtimestamp(scan_data["timestamp"].seconds).isoformat(),
                    }

                # Add the document ID
                scan_data["id"] = scan.id
                scan_history.append(scan_data)
            except Exception as e:
                print(f"Error processing scan document {scan.id}: {str(e)}")

        print(f"Found {len(scan_history)} scans for user {user_id}")

        # Try to get user information from Firebase Auth
        user_info = {}
        try:
            auth_user = auth.get_user(user_id)
            user_info = {
                "email": auth_user.email,
                "uid": auth_user.uid,
                "emailVerified": auth_user.email_verified,
            }
        except Exception as e:
            print(f"Error fetching user info from Auth: {str(e)}")

        return {"user_id": user_id, "user_info": user_info, "scans_count": len(scan_history), "scans": scan_history}

    except Exception as e:
        print(f"User scans debug error: {str(e)}")
        return {"status": "error", "error": str(e), "timestamp": datetime.now().isoformat()}


@router.get("/api/debug/repair-scans")
async def repair_scans():
    """Special repair endpoint to fix userId issues in scans"""
    try:
        # Get all scans
        all_scans = db.collection("scans").stream()
        fixed_count = 0
        unchanged_count = 0
        error_count = 0

        # Process each scan
        for scan in all_scans:
            try:
                scan_data = scan.to_dict()
                scan_id = scan.id

                # Check for different user ID field formats
                user_id = None
                field_to_standardize = False

                if "userId" in scan_data:
                    user_id = scan_data["userId"]
                elif "user_id" in scan_data:
                    user_id = scan_data["user_id"]
                    field_to_standardize = True
                elif "userID" in scan_data:
                    user_id = scan_data["userID"]
                    field_to_standardize = True

                if not user_id:
                    print(f"Scan {scan_id} has no user ID field")
                    continue

                updates = {}

                # Standardize field name if needed
                if field_to_standardize:
                    updates["userId"] = user_id
                    if "user_id" in scan_data:
                        # Mark for removal (can't actually delete in update operation)
                        updates["user_id"] = firestore.DELETE_FIELD
                    if "userID" in scan_data:
                        updates["userID"] = firestore.DELETE_FIELD

                # Apply updates if needed
                if updates:
                    db.collection("scans").document(scan_id).update(updates)
                    fixed_count += 1
                    print(f"Fixed scan {scan_id}: standardized userId field")
                else:
                    unchanged_count += 1

            except Exception as e:
                print(f"Error processing scan {scan.id}: {str(e)}")
                error_count += 1

        return {
            "status": "success",
            "fixed_count": fixed_count,
            "unchanged_count": unchanged_count,
            "error_count": error_count,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        print(f"Repair scans error: {str(e)}")
        return {"status": "error", "error": str(e), "timestamp": datetime.now().isoformat()}

"""
Scan management routes for Vibe Security.
Contains endpoints for managing scans, scan history, and scheduled scans.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from firebase_admin import firestore

from auth import verify_token
from config import db

router = APIRouter()


@router.get("/api/scan-history")
async def get_scan_history(request: Request, decoded_token=Depends(verify_token)):
    """Get scan history for authenticated user"""
    try:
        user_id = decoded_token["uid"]
        print(f"Getting scan history for user {user_id}")

        # Get scans from Firestore
        scans_query = db.collection("scans")

        # First attempt with exact userId match
        scans_ref = (
            scans_query.where("userId", "==", user_id)
            .order_by("timestamp", direction=firestore.Query.DESCENDING)
            .limit(10)
        )

        try:
            scans = list(scans_ref.stream())

            # If no results, try checking all scans with more flexible matching
            if not scans:
                print("No scans found with exact userId match, checking all scans with flexible matching")
                # Get all scans
                all_scans_ref = scans_query.order_by("timestamp", direction=firestore.Query.DESCENDING)
                all_scans = list(all_scans_ref.stream())
                matched_scans = []

                for scan in all_scans:
                    scan_data = scan.to_dict()

                    # Check multiple possible user ID field names
                    if (
                        scan_data.get("userId")
                        and scan_data.get("userId").lower() == user_id.lower()
                        or scan_data.get("user_id")
                        and scan_data.get("user_id").lower() == user_id.lower()
                        or scan_data.get("userID")
                        and scan_data.get("userID").lower() == user_id.lower()
                    ):
                        matched_scans.append(scan)

                scans = matched_scans
                print(f"Found {len(scans)} scans with flexible matching")

            scan_history = []
            for scan in scans:
                try:
                    scan_data = scan.to_dict()
                    print(f"Processing scan: {scan.id}, URL: {scan_data.get('url', 'Unknown')}")

                    # Convert Firestore timestamps to a JSON-serializable format
                    if "timestamp" in scan_data and hasattr(scan_data["timestamp"], "seconds"):
                        scan_data["timestamp"] = {
                            "seconds": scan_data["timestamp"].seconds,
                            "nanoseconds": scan_data["timestamp"].nanoseconds,
                        }

                    # Add the document ID
                    scan_data["id"] = scan.id

                    # Ensure results is properly formatted
                    if "results" not in scan_data or scan_data["results"] is None:
                        scan_data["results"] = {
                            "checks": [],
                            "url": scan_data.get("url", ""),
                            "timestamp": scan_data.get("timestamp"),
                        }

                    scan_history.append(scan_data)
                except Exception as e:
                    print(f"Error processing scan document {scan.id}: {str(e)}")

            print(f"Returning {len(scan_history)} scans for user {user_id}")
            return {"scans": scan_history}
        except Exception as e:
            print(f"Error fetching scans from Firestore: {str(e)}")
            # Return empty array instead of error
            return {"scans": []}

    except Exception as e:
        print(f"Scan history error: {str(e)}")
        # Return empty array instead of error
        return {"scans": []}


@router.get("/api/user-info")
async def get_user_info(request: Request, decoded_token=Depends(verify_token)):
    """Get user information from Firebase token"""
    try:
        user_id = decoded_token["uid"]
        print(f"Getting user info for user {user_id}")

        # Use information directly from the Firebase auth token
        return {"email": decoded_token.get("email", ""), "premium": decoded_token.get("premium", False)}

    except Exception as e:
        print(f"User info error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/api/scheduled-scans")
async def get_scheduled_scans(request: Request):
    """Get scheduled scans for authenticated user"""
    try:
        # Verify token and get user ID
        decoded_token = await verify_token(request)
        if not decoded_token or "uid" not in decoded_token:
            raise HTTPException(status_code=401, detail="Unauthorized")

        user_id = decoded_token["uid"]
        print(f"Getting scheduled scans for user {user_id}")

        # Get scheduled scans from scan history
        scans_query = db.collection("scans").where("scheduled", "==", True).where("schedule_status", "==", "active")
        scan_docs = list(scans_query.stream())

        # Filter scans by user ID with flexible matching
        matched_scans = []
        for scan in scan_docs:
            scan_data = scan.to_dict()
            scan_user_id = None

            # Get user ID from any of the possible field names
            if "userId" in scan_data:
                scan_user_id = scan_data["userId"]
            elif "user_id" in scan_data:
                scan_user_id = scan_data["user_id"]
            elif "userID" in scan_data:
                scan_user_id = scan_data["userID"]

            # Compare user IDs if we found one
            if scan_user_id and str(scan_user_id).lower() == str(user_id).lower():
                matched_scans.append(scan)

        print(f"Found {len(matched_scans)} scheduled scans for user {user_id}")

        # Convert scans to response format
        scan_list = []
        for scan in matched_scans:
            scan_data = scan.to_dict()

            # Format timestamps
            timestamp = scan_data.get("timestamp")
            last_scan = scan_data.get("last_scheduled_scan")

            if timestamp and hasattr(timestamp, "seconds"):
                timestamp = datetime.fromtimestamp(timestamp.seconds).isoformat()
            if last_scan and hasattr(last_scan, "seconds"):
                last_scan = datetime.fromtimestamp(last_scan.seconds).isoformat()

            scan_list.append(
                {
                    "id": scan.id,
                    "url": scan_data.get("url"),
                    "timestamp": timestamp,
                    "scheduled": scan_data.get("scheduled"),
                    "schedule_status": scan_data.get("schedule_status"),
                    "last_scheduled_scan": last_scan,
                    "schedule_interval": scan_data.get("schedule_interval", 24),
                }
            )

        return {"scans": scan_list}
    except Exception as e:
        print(f"Error getting scheduled scans: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/api/scheduled-scans")
async def create_scheduled_scan(request: Request):
    """Create a scheduled scan for a URL"""
    try:
        # Verify token and get user ID
        decoded_token = await verify_token(request)
        if not decoded_token or "uid" not in decoded_token:
            raise HTTPException(status_code=401, detail="Unauthorized")

        user_id = decoded_token["uid"]

        # Get scan data from request body
        scan_data = await request.json()
        if not scan_data or "url" not in scan_data:
            raise HTTPException(status_code=400, detail="URL is required in request body")

        # Get the scan from history with flexible field matching
        scan_query = db.collection("scans").where("url", "==", scan_data["url"])
        scan_docs = list(scan_query.stream())

        # Filter scans by user ID with flexible matching
        matched_scans = []
        for scan in scan_docs:
            scan_data = scan.to_dict()
            scan_user_id = None

            # Get user ID from any of the possible field names
            if "userId" in scan_data:
                scan_user_id = scan_data["userId"]
            elif "user_id" in scan_data:
                scan_user_id = scan_data["user_id"]
            elif "userID" in scan_data:
                scan_user_id = scan_data["userID"]

            # Compare user IDs if we found one
            if scan_user_id and str(scan_user_id).lower() == str(user_id).lower():
                matched_scans.append(scan)

        if not matched_scans:
            raise HTTPException(status_code=404, detail="Scan not found in history")

        # Get the most recent scan
        scan_doc = max(matched_scans, key=lambda x: x.get("timestamp").timestamp() if x.get("timestamp") else 0)
        scan_ref = scan_doc.reference

        # Update the scan to be scheduled
        scan_ref.update(
            {
                "scheduled": True,
                "last_scheduled_scan": None,
                "schedule_status": "active",
                "schedule_interval": 24,  # 24 hours
            }
        )

        return {"message": "Scan scheduled successfully", "scan_id": scan_doc.id}
    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"Error scheduling scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.delete("/api/scheduled-scans/{scan_id}")
async def delete_scheduled_scan(scan_id: str, request: Request):
    """Delete/unschedule a scheduled scan"""
    try:
        # Verify token and get user ID
        decoded_token = await verify_token(request)
        if not decoded_token or "uid" not in decoded_token:
            raise HTTPException(status_code=401, detail="Unauthorized")

        user_id = decoded_token["uid"]

        # Get the scan
        scan_ref = db.collection("scans").document(scan_id)
        scan = scan_ref.get()

        if not scan.exists:
            return JSONResponse(status_code=404, content={"error": "Scan not found"})

        scan_data = scan.to_dict()

        # Check user ID with flexible matching
        scan_user_id = None
        if "userId" in scan_data:
            scan_user_id = scan_data["userId"]
        elif "user_id" in scan_data:
            scan_user_id = scan_data["user_id"]
        elif "userID" in scan_data:
            scan_user_id = scan_data["userID"]

        if not scan_user_id or str(scan_user_id).lower() != str(user_id).lower():
            raise HTTPException(status_code=403, detail="Not authorized to unschedule this scan")

        # Update the scan to be unscheduled
        scan_ref.update({"scheduled": False, "schedule_status": "inactive"})

        return {"message": "Scan unscheduled successfully"}
    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"Error unscheduling scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.delete("/api/delete-scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan completely from the system"""
    print(f"Attempting to delete scan with ID: {scan_id}")
    try:
        scan_ref = db.collection("scans").document(scan_id)
        scan = scan_ref.get()
        if not scan.exists:
            print(f"Scan with ID {scan_id} not found.")
            return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "Scan not found"})
        scan_ref.delete()
        print(f"Deleted scan with ID: {scan_id}")
        return {"status": "deleted", "id": scan_id}
    except Exception as e:
        print(f"Error deleting scan {scan_id}: {e}")
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"error": str(e)})

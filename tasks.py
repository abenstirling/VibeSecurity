"""
Background tasks for Vibe Security.
Contains scheduled tasks and background operations.
"""

import asyncio
from datetime import datetime, timedelta

from config import db
from scanner import SecurityScanner


async def run_scheduled_scans():
    """Background task that runs scheduled scans at their configured intervals"""
    while True:
        try:
            # Get all active scheduled scans
            scans_query = db.collection("scans").where("scheduled", "==", True).where("schedule_status", "==", "active")
            scheduled_scans = list(scans_query.stream())

            for scan in scheduled_scans:
                scan_data = scan.to_dict()
                scan_ref = scan.reference

                # Check if it's time to run the scan
                last_scan = scan_data.get("last_scheduled_scan")
                interval = scan_data.get("schedule_interval", 24)  # Default to 24 hours

                should_run = False
                if not last_scan:
                    should_run = True
                else:
                    # Convert Firestore timestamp to datetime
                    if hasattr(last_scan, "timestamp"):
                        last_scan_time = datetime.fromtimestamp(last_scan.timestamp())
                    else:
                        last_scan_time = datetime.fromtimestamp(last_scan.seconds)
                    next_scan_time = last_scan_time + timedelta(hours=interval)
                    if datetime.now() >= next_scan_time:
                        should_run = True

                if should_run:
                    try:
                        # Run the scan with the URL
                        scanner = SecurityScanner(scan_data["url"])
                        results = await scanner.scan()

                        # Update the scan with new results
                        scan_ref.update(
                            {"last_scheduled_scan": datetime.now(), "results": results, "timestamp": datetime.now()}
                        )

                        print(f"Completed scheduled scan for {scan_data['url']}")
                    except Exception as e:
                        print(f"Error running scheduled scan for {scan_data['url']}: {str(e)}")

            # Wait for 1 hour before checking again
            await asyncio.sleep(3600)
        except Exception as e:
            print(f"Error in scheduled scanner: {str(e)}")
            await asyncio.sleep(60)  # Wait 1 minute before retrying

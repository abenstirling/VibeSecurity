"""
Statistics routes for Vibe Security.
Contains endpoints for accessing usage statistics and analytics.
"""


from fastapi import APIRouter, HTTPException, Request

from config import FIREBASE_CONFIG, db, templates

router = APIRouter()


@router.get("/stats")
async def stats_page(request: Request):
    """Statistics page"""
    return templates.TemplateResponse("stats.html", {"request": request, "firebase_config": FIREBASE_CONFIG})


@router.get("/api/stats")
async def get_stats():
    """Get comprehensive statistics about scans and usage"""
    try:
        # Get all scans
        scans_ref = db.collection("scans")
        scans = scans_ref.stream()

        # Initialize data structures
        domain_counts = {}
        user_counts = {"authenticated": set(), "front_page": 0}
        scan_dates = {}
        timing_data = {"total_time": [], "check_times": {}, "trends": []}

        # Process each scan
        for scan in scans:
            scan_data = scan.to_dict()

            # Count domains
            domain = scan_data.get("url", "")
            domain_counts[domain] = domain_counts.get(domain, 0) + 1

            # Count users
            user_id = scan_data.get("userId", "")
            if user_id == "front_page":
                user_counts["front_page"] += 1
            else:
                user_counts["authenticated"].add(user_id)

            # Track scan dates
            timestamp = scan_data.get("timestamp")
            if timestamp:
                date = timestamp.strftime("%Y-%m-%d")
                scan_dates[date] = scan_dates.get(date, 0) + 1

            # Process timing data if available in results
            results = scan_data.get("results", {})
            if results:
                if "timing_stats" in results:
                    # New format with detailed timing
                    timing_stats = results["timing_stats"]
                    total_time = timing_stats.get("total_time", 0)
                    timing_data["total_time"].append(total_time)

                    # Add to trends with detailed timing
                    if timestamp:
                        timing_data["trends"].append(
                            {
                                "date": date,
                                "domain": domain,
                                "totalTime": total_time,
                                "httpsTime": timing_stats.get("check_breakdown", {})
                                .get("HTTPS Usage", {})
                                .get("total", 0),
                                "sslTime": timing_stats.get("check_breakdown", {})
                                .get("SSL Certificate", {})
                                .get("total", 0),
                                "timing_stats": timing_stats,  # Include full timing stats for detailed analysis
                            }
                        )
                elif "total_time" in results:
                    # Old format
                    total_time = results["total_time"]
                    timing_data["total_time"].append(total_time)

                    # Add to trends with basic timing
                    if timestamp:
                        timing_data["trends"].append(
                            {
                                "date": date,
                                "domain": domain,
                                "totalTime": total_time,
                                "httpsTime": 0,  # Not available in old format
                                "sslTime": 0,  # Not available in old format
                            }
                        )

        # Sort domains by count
        sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
        all_domains = [{"domain": domain, "count": count} for domain, count in sorted_domains]

        # Calculate scan trends with cumulative counts
        sorted_dates = sorted(scan_dates.items())
        cumulative_count = 0
        trends = []
        for date, count in sorted_dates:
            cumulative_count += count
            trends.append({"date": date, "count": count, "cumulative": cumulative_count})

        # Calculate timing statistics if available
        timing_stats = None
        if timing_data["total_time"]:
            avg_total_time = sum(timing_data["total_time"]) / len(timing_data["total_time"])

            # Calculate averages for each check type if available
            averages = {}
            check_counts = {}

            for trend in timing_data["trends"]:
                if "timing_stats" in trend and "check_breakdown" in trend["timing_stats"]:
                    for check, timing in trend["timing_stats"]["check_breakdown"].items():
                        if isinstance(timing, dict) and "total" in timing:
                            if check not in averages:
                                averages[check] = 0
                                check_counts[check] = 0
                            averages[check] += timing["total"]
                            check_counts[check] += 1

            # Calculate final averages
            for check in averages:
                if check_counts[check] > 0:
                    averages[check] = averages[check] / check_counts[check]

            timing_stats = {
                "avgTimeToLoad": avg_total_time,
                "avgTotalTime": avg_total_time,
                "averages": averages,
                "trends": sorted(timing_data["trends"], key=lambda x: (x["date"], x["domain"])),
            }

        # Calculate summary statistics
        total_scans = sum(domain_counts.values())
        unique_domains = len(domain_counts)
        avg_scans_per_domain = total_scans / unique_domains if unique_domains > 0 else 0
        total_users = len(user_counts["authenticated"]) + (1 if user_counts["front_page"] > 0 else 0)

        return {
            "domains": all_domains,
            "trends": trends,
            "userStats": {"authenticated": len(user_counts["authenticated"]), "frontPage": user_counts["front_page"]},
            "summary": {
                "totalScans": total_scans,
                "uniqueDomains": unique_domains,
                "avgScansPerDomain": avg_scans_per_domain,
                "totalUsers": total_users,
            },
            "timingStats": timing_stats,
        }
    except Exception as e:
        print(f"Error getting stats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}") from e

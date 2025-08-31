import re
import socket
import ssl
import time
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


class SecurityScanner:
    def __init__(self, url: str):
        self.url = url
        self.parsed_url = urlparse(url)
        self.results: list[dict[str, Any]] = []
        self.timings: dict[str, Any] = {}

    async def _time_check(self, check_name: str, check_func) -> dict[str, Any]:
        """Wrapper to time a security check with detailed timing breakdown"""
        start_time = time.time()
        network_time = 0
        processing_time = 0

        try:
            # Time the network operations separately
            if hasattr(check_func, "__name__") and check_func.__name__ in [
                "_check_https",
                "_check_ssl_validity",
                "_check_csp",
                "_check_x_frame_options",
                "_check_hsts",
                "_check_directory_listing",
                "_check_server_info",
                "_check_admin_pages",
                "_check_https_forms",
                "_check_exposed_api_keys",
            ]:
                # Start timing before network request
                network_start = time.time()
                # Make the network request
                result = await check_func()
                # Calculate network time after request completes
                network_time = time.time() - network_start
            else:
                # For non-network checks, just run the function
                result = await check_func()
                network_time = 0  # No network time for non-network checks

            end_time = time.time()
            total_time = end_time - start_time
            processing_time = total_time - network_time

            # Store detailed timing information
            self.timings[check_name] = {"total": total_time, "network": network_time, "processing": processing_time}

            # Add timing information to the result
            if isinstance(result, dict):
                result["timing"] = {"total": total_time, "network": network_time, "processing": processing_time}

            return result
        except Exception as e:
            end_time = time.time()
            total_time = end_time - start_time
            self.timings[check_name] = {
                "total": total_time,
                "network": network_time,
                "processing": processing_time,
                "error": str(e),
            }
            return {
                "check": check_name,
                "status": "warning",
                "details": f"Check failed: {str(e)}",
                "timing": {
                    "total": total_time,
                    "network": network_time,
                    "processing": processing_time,
                    "error": str(e),
                },
            }

    async def check_https(self) -> dict[str, Any]:
        """Check if the site uses HTTPS"""
        return await self._time_check("HTTPS Usage", self._check_https)

    async def _check_https(self) -> dict[str, Any]:
        """Check if the site uses HTTPS"""
        try:
            requests.get(self.url, verify=True, timeout=5)
            is_https = self.url.startswith("https://")
            return {
                "check": "HTTPS Usage",
                "status": "pass" if is_https else "fail",
                "details": "Site uses HTTPS" if is_https else "Site does not use HTTPS",
            }
        except Exception:
            return {"check": "HTTPS Usage", "status": "fail", "details": "Could not verify HTTPS usage"}

    async def check_ssl_validity(self) -> dict[str, Any]:
        """Check SSL certificate validity"""
        return await self._time_check("SSL Certificate", self._check_ssl_validity)

    async def _check_ssl_validity(self) -> dict[str, Any]:
        """Check SSL certificate validity"""
        try:
            hostname = self.parsed_url.netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssock.getpeercert()
                    return {"check": "SSL Certificate", "status": "pass", "details": "Valid SSL certificate"}
        except Exception:
            return {"check": "SSL Certificate", "status": "fail", "details": "Invalid or expired SSL certificate"}

    async def check_csp(self) -> dict[str, Any]:
        """Check Content Security Policy"""
        try:
            response = requests.get(self.url, timeout=5)
            csp = response.headers.get("Content-Security-Policy")
            return {
                "check": "Content Security Policy",
                "status": "pass" if csp else "warning",
                "details": "CSP is configured" if csp else "CSP is not configured",
            }
        except Exception:
            return {
                "check": "Content Security Policy",
                "status": "warning",
                "details": "Could not verify CSP configuration",
            }

    async def check_x_frame_options(self) -> dict[str, Any]:
        """Check X-Frame-Options header"""
        try:
            response = requests.get(self.url, timeout=5)
            xfo = response.headers.get("X-Frame-Options")
            return {
                "check": "X-Frame-Options",
                "status": "pass" if xfo else "warning",
                "details": "X-Frame-Options is configured" if xfo else "X-Frame-Options is not configured",
            }
        except Exception:
            return {
                "check": "X-Frame-Options",
                "status": "warning",
                "details": "Could not verify X-Frame-Options configuration",
            }

    async def check_hsts(self) -> dict[str, Any]:
        """Check HSTS header"""
        try:
            response = requests.get(self.url, timeout=5)
            hsts = response.headers.get("Strict-Transport-Security")
            return {
                "check": "HSTS",
                "status": "pass" if hsts else "warning",
                "details": "HSTS is configured" if hsts else "HSTS is not configured",
            }
        except Exception:
            return {"check": "HSTS", "status": "warning", "details": "Could not verify HSTS configuration"}

    async def check_directory_listing(self) -> dict[str, Any]:
        """Check for directory listing vulnerability"""
        try:
            response = requests.get(self.url + "/", timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            has_directory_listing = any(
                tag.name == "a" and tag.get("href", "").endswith("/") for tag in soup.find_all()
            )
            return {
                "check": "Directory Listing",
                "status": "warning" if has_directory_listing else "pass",
                "details": "Directory listing may be enabled"
                if has_directory_listing
                else "Directory listing appears to be disabled",
            }
        except Exception:
            return {
                "check": "Directory Listing",
                "status": "pass",
                "details": "Could not verify directory listing configuration",
            }

    async def check_server_info(self) -> dict[str, Any]:
        """Check for server information leakage"""
        try:
            response = requests.get(self.url, timeout=5)
            server = response.headers.get("Server")
            return {
                "check": "Server Information",
                "status": "warning" if server else "pass",
                "details": f"Server information is exposed: {server}" if server else "Server information is hidden",
            }
        except Exception:
            return {
                "check": "Server Information",
                "status": "warning",
                "details": "Could not verify server information configuration",
            }

    async def check_admin_pages(self) -> dict[str, Any]:
        """Check for common admin pages"""
        common_admin_paths = ["/admin", "/wp-admin", "/administrator", "/manager"]
        try:
            for path in common_admin_paths:
                response = requests.get(self.url + path, timeout=5)
                if response.status_code == 200:
                    return {"check": "Admin Pages", "status": "warning", "details": f"Admin page found at {path}"}
            return {"check": "Admin Pages", "status": "pass", "details": "No common admin pages found"}
        except Exception:
            return {"check": "Admin Pages", "status": "warning", "details": "Could not verify admin pages"}

    async def check_https_forms(self) -> dict[str, Any]:
        """Check for HTTPS forms"""
        try:
            response = requests.get(self.url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            insecure_forms = [form for form in forms if form.get("action", "").startswith("http://")]
            return {
                "check": "HTTPS Forms",
                "status": "fail" if insecure_forms else "pass",
                "details": f"Found {len(insecure_forms)} forms using HTTP" if insecure_forms else "All forms use HTTPS",
            }
        except Exception:
            return {"check": "HTTPS Forms", "status": "warning", "details": "Could not verify form security"}

    async def check_exposed_api_keys(self) -> dict[str, Any]:
        """Check for exposed API keys in the website content"""
        try:
            response = requests.get(self.url, timeout=5)
            content = response.text.lower()

            # Common API key patterns
            patterns = {
                "stripe": r"sk_(live|test)_[0-9a-zA-Z]{24}",
                "aws": r"AKIA[0-9A-Z]{16}",
                "github": r"ghp_[0-9a-zA-Z]{36}",
                "google": r"AIza[0-9A-Za-z-_]{35}",
                "firebase": r"[0-9a-zA-Z-]{20}\.[0-9a-zA-Z-]{20}\.[0-9a-zA-Z-]{20}",
                "generic": r"[a-zA-Z0-9]{32,}",
            }

            found_keys = []
            for key_type, pattern in patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    # Add each found key with its type
                    for key in matches:
                        found_keys.append(f"{key_type.upper()}: {key}")

            if found_keys:
                return {
                    "check": "Exposed API Keys",
                    "status": "fail",
                    "details": f"Found {len(found_keys)} exposed API keys:\n" + "\n".join(found_keys),
                }
            else:
                return {"check": "Exposed API Keys", "status": "pass", "details": "No exposed API keys found"}
        except Exception:
            return {"check": "Exposed API Keys", "status": "warning", "details": "Could not verify API key exposure"}

    async def scan(self) -> dict[str, Any]:
        """Run all security checks with detailed timing analysis"""
        start_time = time.time()
        print(f"Starting scan for {self.url}")

        # Define all checks to run (removed API Rate Limiting)
        checks = [
            ("HTTPS Usage", self.check_https),
            ("SSL Certificate", self.check_ssl_validity),
            ("Content Security Policy", self.check_csp),
            ("X-Frame-Options", self.check_x_frame_options),
            ("HSTS", self.check_hsts),
            ("Directory Listing", self.check_directory_listing),
            ("Server Information", self.check_server_info),
            ("Admin Pages", self.check_admin_pages),
            ("HTTPS Forms", self.check_https_forms),
            ("Exposed API Keys", self.check_exposed_api_keys),
        ]

        results = []
        for check_name, check_func in checks:
            try:
                print(f"Running check: {check_name}")
                result = await self._time_check(check_name, check_func)
                # Log timing information for each check
                if isinstance(result, dict) and "timing" in result:
                    timing = result["timing"]
                    print(
                        f"Check {check_name} completed in {timing.get('total', 0):.2f}s (Network: {timing.get('network', 0):.2f}s, Processing: {timing.get('processing', 0):.2f}s)"
                    )
                results.append(result)
            except Exception as e:
                print(f"Error in check {check_name}: {str(e)}")
                results.append(
                    {
                        "check": check_name,
                        "status": "warning",
                        "details": f"Check failed: {str(e)}",
                        "timing": {"error": str(e)},
                    }
                )

        end_time = time.time()
        total_time = end_time - start_time
        print(f"\nScan completed in {total_time:.2f}s")

        # Calculate timing statistics
        timing_stats = {
            "total_time": total_time,
            "check_breakdown": {},
            "network_time_total": 0,
            "processing_time_total": 0,
            "slowest_checks": [],
        }

        # Process timing data for each check
        for check_name, timing in self.timings.items():
            if isinstance(timing, dict):
                timing_stats["check_breakdown"][check_name] = timing
                timing_stats["network_time_total"] += timing.get("network", 0)
                timing_stats["processing_time_total"] += timing.get("processing", 0)
                timing_stats["slowest_checks"].append(
                    {
                        "check": check_name,
                        "total_time": timing.get("total", 0),
                        "network_time": timing.get("network", 0),
                        "processing_time": timing.get("processing", 0),
                    }
                )

        # Sort slowest checks by total time
        timing_stats["slowest_checks"].sort(key=lambda x: x["total_time"], reverse=True)

        # Log timing summary
        print("\nTiming Summary:")
        print(f"Total scan time: {total_time:.2f}s")
        print(f"Network time: {timing_stats['network_time_total']:.2f}s")
        print(f"Processing time: {timing_stats['processing_time_total']:.2f}s")
        print("\nAll checks timing:")
        for check in timing_stats["slowest_checks"]:
            print(
                f"- {check['check']}: {check['total_time']:.2f}s (Network: {check['network_time']:.2f}s, Processing: {check['processing_time']:.2f}s)"
            )

        # Get timestamp for the scan
        timestamp = datetime.now().isoformat()

        # Return structured response with detailed timings
        return {
            "url": self.url,
            "timestamp": timestamp,
            "checks": results,
            "timings": self.timings,
            "timing_stats": timing_stats,
            "total_time": total_time,
            "summary": {
                "pass": sum(1 for check in results if check["status"] == "pass"),
                "warning": sum(1 for check in results if check["status"] == "warning"),
                "fail": sum(1 for check in results if check["status"] == "fail"),
                "total": len(results),
            },
        }

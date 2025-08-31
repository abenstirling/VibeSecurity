"""
Replit security check routes for Vibe Security.
Contains endpoints for checking various security aspects of Replit deployments.
"""

import re

import requests
from bs4 import BeautifulSoup
from fastapi import APIRouter, Request

router = APIRouter()


@router.post("/api/replit/https-check")
async def check_replit_https(request: Request):
    """Check HTTPS and HSTS configuration"""
    try:
        data = await request.json()
        url = data.get("url")

        # Check if the URL uses HTTPS
        uses_https = url.startswith("https://")

        # Check for HSTS header
        try:
            response = requests.get(url, timeout=5)
            has_hsts = "Strict-Transport-Security" in response.headers
            hsts_value = response.headers.get("Strict-Transport-Security", "")
            has_secure_hsts = "max-age" in hsts_value and "includeSubDomains" in hsts_value

            # Detailed explanation
            explanation = []
            if not uses_https:
                explanation.append("❌ Site is not using HTTPS protocol")
            if not has_hsts:
                explanation.append("❌ HSTS header is missing")
            elif not has_secure_hsts:
                explanation.append("❌ HSTS header is not properly configured (missing max-age or includeSubDomains)")

            return {
                "httpsSecure": uses_https and has_hsts and has_secure_hsts,
                "details": "HTTPS and HSTS are properly configured"
                if (uses_https and has_hsts and has_secure_hsts)
                else "HTTPS or HSTS is not properly configured",
                "explanation": explanation,
            }
        except Exception as e:
            return {
                "httpsSecure": False,
                "details": f"Error checking HTTPS: {str(e)}",
                "explanation": [f"❌ Could not verify HTTPS configuration: {str(e)}"],
            }
    except Exception as e:
        return {
            "httpsSecure": False,
            "details": f"Error checking HTTPS: {str(e)}",
            "explanation": [f"❌ Error in HTTPS check: {str(e)}"],
        }


@router.post("/api/replit/input-check")
async def check_replit_input(request: Request):
    """Check input validation and security"""
    try:
        data = await request.json()
        url = data.get("url")

        # Check for common input validation patterns
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")

            # Check for form validation attributes
            forms = soup.find_all("form")
            has_validation = False
            has_csrf = False
            explanation = []

            for form in forms:
                # Check for required fields
                inputs = form.find_all("input")
                has_required = any(input.get("required") is not None for input in inputs)
                has_pattern = any(input.get("pattern") is not None for input in inputs)
                has_type = any(input.get("type") in ["email", "number", "url"] for input in inputs)

                # Check for CSRF tokens
                csrf_inputs = form.find_all(
                    "input", {"name": lambda x: x and ("csrf" in x.lower() or "token" in x.lower())}
                )
                has_csrf = has_csrf or len(csrf_inputs) > 0

                # Form is considered validated if it has any validation mechanism
                if has_required or has_pattern or has_type:
                    has_validation = True

            if not has_validation:
                explanation.append("❌ No input validation found (missing required, pattern, or type attributes)")
            if not has_csrf:
                explanation.append("❌ No CSRF protection found (missing CSRF tokens)")

            return {
                "inputSecure": has_validation and has_csrf,
                "details": "Input validation and CSRF protection are implemented"
                if (has_validation and has_csrf)
                else "Input validation or CSRF protection is missing",
                "explanation": explanation,
            }
        except Exception as e:
            return {
                "inputSecure": False,
                "details": "Could not verify input validation",
                "explanation": [f"❌ Error checking input validation: {str(e)}"],
            }
    except Exception as e:
        return {
            "inputSecure": False,
            "details": f"Error checking input validation: {str(e)}",
            "explanation": [f"❌ Error in input check: {str(e)}"],
        }


@router.post("/api/replit/secrets-check")
async def check_replit_secrets(request: Request):
    """Check for exposed secrets in source code"""
    try:
        data = await request.json()
        url = data.get("url")

        # Check for common secret patterns in the source code
        try:
            response = requests.get(url, timeout=5)
            source = response.text

            # Common secret patterns with more specific regex
            secret_patterns = [
                r'api[_-]?key\s*=\s*["\']\w+["\']',
                r'secret[_-]?key\s*=\s*["\']\w+["\']',
                r'password\s*=\s*["\']\w+["\']',
                r'token\s*=\s*["\']\w+["\']',
                r'credential\s*=\s*["\']\w+["\']',
                r'private[_-]?key\s*=\s*["\']\w+["\']',
            ]

            # Check for environment variable usage
            has_env_vars = re.search(r'os\.environ\[["\']\w+["\']\]', source) is not None

            # Only consider it a secret if it's not using environment variables
            has_secrets = (
                any(re.search(pattern, source, re.IGNORECASE) for pattern in secret_patterns) and not has_env_vars
            )

            explanation = []
            if has_secrets:
                explanation.append("❌ Found potential secrets in source code")
            if not has_env_vars:
                explanation.append("❌ No environment variable usage found")

            return {
                "secretsSecure": not has_secrets,
                "details": "No secrets found in source code"
                if not has_secrets
                else "Potential secrets found in source code",
                "explanation": explanation,
            }
        except Exception as e:
            return {
                "secretsSecure": False,
                "details": "Could not verify secrets",
                "explanation": [f"❌ Error checking secrets: {str(e)}"],
            }
    except Exception as e:
        return {
            "secretsSecure": False,
            "details": f"Error checking secrets: {str(e)}",
            "explanation": [f"❌ Error in secrets check: {str(e)}"],
        }


@router.post("/api/replit/csrf-check")
async def check_replit_csrf(request: Request):
    """Check CSRF protection implementation"""
    try:
        data = await request.json()
        url = data.get("url")

        # Check for CSRF protection
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")

            # Check for CSRF tokens in forms
            forms = soup.find_all("form")
            has_csrf = False
            explanation = []

            for form in forms:
                # Check for CSRF tokens
                csrf_inputs = form.find_all(
                    "input", {"name": lambda x: x and ("csrf" in x.lower() or "token" in x.lower())}
                )
                if len(csrf_inputs) > 0:
                    # Verify the token has a value
                    has_csrf = any(input.get("value") for input in csrf_inputs)
                    break

            # Check for CSRF-related headers
            headers = response.headers
            has_csrf_headers = any(
                header.lower() in ["x-csrf-token", "csrf-token", "x-xsrf-token"] for header in headers
            )

            if not has_csrf:
                explanation.append("❌ No CSRF tokens found in forms")
            if not has_csrf_headers:
                explanation.append("❌ No CSRF-related headers found")

            return {
                "csrfSecure": has_csrf or has_csrf_headers,
                "details": "CSRF protection is implemented"
                if (has_csrf or has_csrf_headers)
                else "CSRF protection is missing",
                "explanation": explanation,
            }
        except Exception as e:
            return {
                "csrfSecure": False,
                "details": "Could not verify CSRF protection",
                "explanation": [f"❌ Error checking CSRF protection: {str(e)}"],
            }
    except Exception as e:
        return {
            "csrfSecure": False,
            "details": f"Error checking CSRF: {str(e)}",
            "explanation": [f"❌ Error in CSRF check: {str(e)}"],
        }


@router.post("/api/replit/api-key-check")
async def check_replit_api_keys(request: Request):
    """Check for exposed API keys in frontend code"""
    try:
        data = await request.json()
        url = data.get("url")

        # Check for exposed API keys
        try:
            response = requests.get(url, timeout=5)
            source = response.text

            # Common API key patterns with more specific regex
            api_key_patterns = [
                r'api[_-]?key\s*=\s*["\']\w{20,}["\']',
                r'key\s*=\s*["\']\w{20,}["\']',
                r'secret\s*=\s*["\']\w{20,}["\']',
                r'token\s*=\s*["\']\w{20,}["\']',
            ]

            # Check for environment variable usage
            has_env_vars = re.search(r'os\.environ\[["\']\w+["\']\]', source) is not None

            # Only consider it an API key if it's not using environment variables
            has_api_keys = (
                any(re.search(pattern, source, re.IGNORECASE) for pattern in api_key_patterns) and not has_env_vars
            )

            explanation = []
            if has_api_keys:
                explanation.append("❌ Found potential API keys in frontend code")
            if not has_env_vars:
                explanation.append("❌ No environment variable usage found for API keys")

            return {
                "apiKeySecure": not has_api_keys,
                "details": "No API keys found in frontend code"
                if not has_api_keys
                else "Potential API keys found in frontend code",
                "explanation": explanation,
            }
        except Exception as e:
            return {
                "apiKeySecure": False,
                "details": "Could not verify API key security",
                "explanation": [f"❌ Error checking API keys: {str(e)}"],
            }
    except Exception as e:
        return {
            "apiKeySecure": False,
            "details": f"Error checking API keys: {str(e)}",
            "explanation": [f"❌ Error in API key check: {str(e)}"],
        }


@router.post("/api/replit/environment-check")
async def check_replit_environment(request: Request):
    """Check environment isolation"""
    try:
        data = await request.json()
        url = data.get("url")

        # Check if the URL is a Replit URL
        is_replit = "replit.com" in url or "repl.co" in url

        return {
            "environmentIsolated": is_replit,
            "details": "Environment appears to be properly isolated"
            if is_replit
            else "Environment may not be properly isolated",
        }
    except Exception as e:
        return {"environmentIsolated": False, "details": f"Error checking environment: {str(e)}"}


@router.post("/api/replit/deployment-check")
async def check_replit_deployment(request: Request):
    """Check deployment security"""
    try:
        data = await request.json()
        url = data.get("url")

        # Check if the URL uses HTTPS
        uses_https = url.startswith("https://")

        return {
            "deploymentSecure": uses_https,
            "details": "Deployment appears to be secure" if uses_https else "Deployment may not be secure",
        }
    except Exception as e:
        return {"deploymentSecure": False, "details": f"Error checking deployment: {str(e)}"}


@router.post("/api/replit/filesystem-check")
async def check_replit_filesystem(request: Request):
    """Check filesystem security"""
    try:
        data = await request.json()
        url = data.get("url")

        # Check for common file system vulnerabilities
        has_vulnerabilities = any(path in url.lower() for path in ["/.git", "/.env", "/config", "/backup"])

        return {
            "filesystemSecure": not has_vulnerabilities,
            "details": "File system appears to be secure"
            if not has_vulnerabilities
            else "Potential file system vulnerabilities found",
        }
    except Exception as e:
        return {"filesystemSecure": False, "details": f"Error checking filesystem: {str(e)}"}


@router.post("/api/replit/database-check")
async def check_replit_database(request: Request):
    """Check database security"""
    try:
        data = await request.json()
        url = data.get("url")

        # Check for common database connection strings
        db_patterns = [r"mongodb://", r"postgres://", r"mysql://", r"redis://"]

        has_db_connections = any(re.search(pattern, url, re.IGNORECASE) for pattern in db_patterns)

        return {
            "databaseSecure": not has_db_connections,
            "details": "No database connection strings found"
            if not has_db_connections
            else "Potential database connection strings found",
        }
    except Exception as e:
        return {"databaseSecure": False, "details": f"Error checking database: {str(e)}"}


@router.post("/api/replit/security-check")
async def check_replit_security(request: Request):
    """Check overall API security"""
    try:
        data = await request.json()
        url = data.get("url")

        # In a real implementation, you'd want to check the actual response headers
        # For now, we'll just check if it's a Replit URL
        is_replit = "replit.com" in url or "repl.co" in url

        return {"apiSecure": is_replit, "details": "API appears to be secure" if is_replit else "API may not be secure"}
    except Exception as e:
        return {"apiSecure": False, "details": f"Error checking API security: {str(e)}"}


@router.post("/api/replit/container-check")
async def check_replit_container(request: Request):
    """Check container security"""
    try:
        data = await request.json()
        url = data.get("url")

        # Check if the URL is a Replit URL
        is_replit = "replit.com" in url or "repl.co" in url

        return {
            "containerSecure": is_replit,
            "details": "Container appears to be secure" if is_replit else "Container may not be secure",
        }
    except Exception as e:
        return {"containerSecure": False, "details": f"Error checking container: {str(e)}"}


@router.post("/api/exposed-keys-check")
async def check_exposed_keys(request: Request):
    """Check for various types of exposed API keys and secrets"""
    try:
        data = await request.json()
        url = data.get("url")

        # Common API key patterns
        key_patterns = [
            # Stripe
            r"sk_(live|test)_[0-9a-zA-Z]{24}",
            r"pk_(live|test)_[0-9a-zA-Z]{24}",
            # AWS
            r"AKIA[0-9A-Z]{16}",
            r'aws_access_key_id\s*=\s*["\']AKIA[0-9A-Z]{16}["\']',
            # Google
            r"AIza[0-9A-Za-z-_]{35}",
            # GitHub
            r"ghp_[0-9a-zA-Z]{36}",
            r"github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}",
            # Generic API keys
            r'api[_-]?key\s*=\s*["\']\w{20,}["\']',
            r'secret[_-]?key\s*=\s*["\']\w{20,}["\']',
            r'access[_-]?key\s*=\s*["\']\w{20,}["\']',
            r'token\s*=\s*["\']\w{20,}["\']',
            # Database credentials
            r"mongodb://[^:]+:[^@]+@",
            r"postgres://[^:]+:[^@]+@",
            r"mysql://[^:]+:[^@]+@",
            r"redis://[^:]+:[^@]+@",
        ]

        try:
            # Get the page content
            response = requests.get(url, timeout=5)
            source = response.text

            # Check for API keys
            found_keys = []
            for pattern in key_patterns:
                matches = re.finditer(pattern, source, re.IGNORECASE)
                for match in matches:
                    # Mask the key for security
                    key = match.group(0)
                    masked_key = key[:4] + "*" * (len(key) - 8) + key[-4:]
                    found_keys.append(
                        {
                            "type": pattern.split("_")[0].replace("r", "").strip(),
                            "key": masked_key,
                            "line": source[: match.start()].count("\n") + 1,
                        }
                    )

            # Check for environment variable usage
            has_env_vars = re.search(r'os\.environ\[["\']\w+["\']\]', source) is not None

            explanation = []
            if found_keys:
                for key in found_keys:
                    explanation.append(f"❌ Found potential {key['type']} key on line {key['line']}: {key['key']}")
            if not has_env_vars:
                explanation.append("❌ No environment variable usage found for sensitive data")

            return {
                "secure": len(found_keys) == 0,
                "details": "No exposed API keys found"
                if len(found_keys) == 0
                else f"Found {len(found_keys)} potential API keys",
                "explanation": explanation,
                "found_keys": found_keys,
            }
        except Exception as e:
            return {
                "secure": False,
                "details": "Could not verify API key security",
                "explanation": [f"❌ Error checking API keys: {str(e)}"],
                "found_keys": [],
            }
    except Exception as e:
        return {
            "secure": False,
            "details": f"Error checking API keys: {str(e)}",
            "explanation": [f"❌ Error in API key check: {str(e)}"],
            "found_keys": [],
        }

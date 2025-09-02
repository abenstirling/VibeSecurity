"""
Go scanner wrapper for Vibe Security.
Provides a drop-in replacement for the Python SecurityScanner that calls the Go executable.
"""

import json
import os
import subprocess
from typing import Any


class SecurityScanner:
    def __init__(self, url: str):
        self.url = url
        self.executable_path = os.path.join(os.path.dirname(__file__), "goscan")

        # Check if the Go executable exists
        if not os.path.exists(self.executable_path):
            raise FileNotFoundError(f"Go scanner executable not found at {self.executable_path}")

    async def scan(self) -> dict[str, Any]:
        """Run security scan using Go executable"""
        try:
            # Call the Go scanner executable
            result = subprocess.run(
                [self.executable_path, self.url],
                capture_output=True,
                text=True,
                timeout=60,  # 60 second timeout
            )

            if result.returncode != 0:
                raise Exception(f"Go scanner failed with return code {result.returncode}: {result.stderr}")

            # Parse JSON output
            scan_data = json.loads(result.stdout)

            return scan_data

        except subprocess.TimeoutExpired as e:
            raise Exception("Go scanner timed out after 60 seconds") from e
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse Go scanner output: {e}") from e
        except Exception as e:
            raise Exception(f"Go scanner error: {e}") from e

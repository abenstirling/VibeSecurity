"""
Go scanner wrapper for Vibe Security.
Provides a drop-in replacement for the Python SecurityScanner that calls the Go executable.
"""

import json
import os
import platform
import subprocess
from typing import Any


class SecurityScanner:
    def __init__(self, url: str):
        self.url = url
        self.executable_path = self._get_executable_path()

        # Check if the Go executable exists
        if not os.path.exists(self.executable_path):
            raise FileNotFoundError(f"Go scanner executable not found at {self.executable_path}")

    def _get_executable_path(self) -> str:
        """Get the correct executable path based on the platform"""
        base_dir = os.path.dirname(__file__)
        
        # Detect platform
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        # Map platform to executable name
        if system == "linux":
            executable = "goscan-linux-amd64"
        elif system == "darwin":  # macOS
            if machine in ["arm64", "aarch64"]:
                executable = "goscan-darwin-arm64"
            else:
                executable = "goscan-darwin-amd64"
        else:
            # Default to Linux for unknown platforms (most servers)
            executable = "goscan-linux-amd64"
        
        executable_path = os.path.join(base_dir, executable)
        
        # Fallback to generic goscan if platform-specific doesn't exist
        if not os.path.exists(executable_path):
            executable_path = os.path.join(base_dir, "goscan")
        
        return executable_path

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

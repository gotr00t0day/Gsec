#!/usr/bin/env python3
"""
Post-Scan Verification Suite
Runs verification checks on Gsec scan results to filter false positives

Security Note: This module uses subprocess with validated, hardcoded script names only.
No user input is passed to subprocess calls, preventing command injection attacks.
"""

import os
import sys
import subprocess  # nosec - Used only with validated hardcoded script names
from pathlib import Path

# Whitelist of allowed verification scripts - prevents unauthorized script execution
ALLOWED_SCRIPTS = {
    "verify_path_traversal.py": "Path traversal verification script"
}

def check_file_exists(filepath):
    """Check if a file exists and has content."""
    return os.path.exists(filepath) and os.path.getsize(filepath) > 0

def validate_script_name(script_name):
    """Validate that the script name is in our whitelist."""
    if script_name not in ALLOWED_SCRIPTS:
        raise ValueError(f"Unauthorized script: {script_name}")
    return True

def run_path_traversal_verification():
    """Run path traversal verification if results exist."""
    path_traversal_file = "output/path_traversal.txt"

    if check_file_exists(path_traversal_file):
        print("🔍 Path traversal results found - running verification...")
        try:
            script_to_run = "verify_path_traversal.py"

            # Security validation: ensure script is whitelisted
            validate_script_name(script_to_run)

            # Execute the validated script using subprocess with argument list
            # nosec - script name is validated against whitelist, no user input
            subprocess.run([sys.executable, script_to_run], check=True)  # nosec
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Path traversal verification failed: {e}")
            return False
        except ValueError as e:
            print(f"❌ Security error: {e}")
            return False
    else:
        print("ℹ️  No path traversal results to verify")
        return True

def main():
    """Main verification runner."""
    print("=" * 60)
    print("🚀 GSEC POST-SCAN VERIFICATION SUITE")
    print("=" * 60)
    print("Filtering false positives from scan results...\n")

    # Change to script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)

    # Run verifications
    verifications = [
        ("Path Traversal", run_path_traversal_verification),
        # Add more verifications here in the future
        # ("SQL Injection", run_sqli_verification),
        # ("XSS", run_xss_verification),
    ]

    results = {}
    for name, func in verifications:
        print(f"Running {name} verification...")
        results[name] = func()
        print()

    # Summary
    print("=" * 60)
    print("📊 VERIFICATION SUMMARY")
    print("=" * 60)

    for name, success in results.items():
        status = "✅ COMPLETED" if success else "❌ FAILED"
        print(f"{name}: {status}")

    print("\n📁 Check the output/ directory for detailed verification reports")
    print("🎯 Verification complete!")

if __name__ == "__main__":
    main()

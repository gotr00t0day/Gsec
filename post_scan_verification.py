#!/usr/bin/env python3
"""
Post-Scan Verification Suite
Runs verification checks on Gsec scan results to filter false positives
"""

import os
import sys
import subprocess
from pathlib import Path


def check_file_exists(filepath):
    """Check if a file exists and has content."""
    return os.path.exists(filepath) and os.path.getsize(filepath) > 0


def run_path_traversal_verification():
    """Run path traversal verification if results exist."""
    path_traversal_file = "output/path_traversal.txt"
    
    if check_file_exists(path_traversal_file):
        print("🔍 Path traversal results found - running verification...")
        try:
            subprocess.run([sys.executable, "verify_path_traversal.py"], check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Path traversal verification failed: {e}")
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
    
    print(f"\n📁 Check the output/ directory for detailed verification reports")
    print("🎯 Verification complete!")


if __name__ == "__main__":
    main() 
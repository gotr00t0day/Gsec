#!/usr/bin/env python3
"""
macOS Installation Script for Gsec
Installs dependencies using Homebrew and Go instead of apt
"""

import subprocess
import platform
import os
import sys
from pathlib import Path


def run_command(cmd_list, allowed_commands=None):
    """Execute command safely using argument list with validation."""
    if allowed_commands is None:
        allowed_commands = {"brew", "go", "git", "which"}

    # Validate command and arguments
    if not cmd_list or not isinstance(cmd_list, list):
        print("Error: Invalid command list")
        return False
    if cmd_list[0] not in allowed_commands:
        print("Error: Unauthorized command")
        return False
    if not all(isinstance(arg, str) and not any(c in arg for c in '&;<>|$`') for arg in cmd_list):
        print("Error: Invalid command arguments")
        return False

    try:
        result = subprocess.run(
            cmd_list,
            check=True,
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print("Error executing command")
        return False
    except subprocess.TimeoutExpired:
        print("Command timed out")
        return False
    except Exception:
        print("Unexpected error")
        return False


def check_homebrew():
    """Check if Homebrew is installed."""
    try:
        result = subprocess.run(
            ["which", "brew"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def check_go():
    """Check if Go is installed."""
    try:
        result = subprocess.run(
            ["which", "go"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def install_macos():
    """Install dependencies for macOS."""
    print("Installing dependencies for macOS...")

    # Check prerequisites
    if not check_homebrew():
        print("Error: Homebrew is not installed. Please install Homebrew first:")
        print("https://brew.sh/")
        return False

    if not check_go():
        print("Error: Go is not installed. Please install Go first:")
        print("brew install go")
        return False

    # Install jq using Homebrew
    print("Installing jq...")
    if not run_command(["brew", "install", "jq"], {"brew"}):
        print("Warning: Failed to install jq")

    # Install Nuclei using Go
    print("Installing Nuclei...")
    nuclei_cmd = ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"]
    if not run_command(nuclei_cmd, {"go"}):
        print("Error: Failed to install Nuclei")
        return False

    # Clone nuclei-templates
    print("Cloning nuclei-templates...")
    if not clone_nuclei_templates():
        print("Warning: Failed to clone nuclei-templates")

    # Add Go bin to PATH
    print("Adding Go binaries to PATH...")
    setup_path()

    print("Installation complete!")
    print("Please restart your terminal or run: source ~/.zprofile")
    return True


def clone_nuclei_templates():
    """Clone nuclei-templates to home directory."""
    home = str(Path.home())
    target = os.path.join(home, "nuclei-templates")

    if os.path.exists(target):
        print("nuclei-templates already exists in home directory.")
        return True

    cmd = ["git", "clone", "https://github.com/projectdiscovery/nuclei-templates.git", target]
    return run_command(cmd, {"git"})


def setup_path():
    """Add Go bin directory to PATH."""
    home_dir = os.path.expanduser("~")
    zprofile_path = os.path.join(home_dir, ".zprofile")
    path_line = 'export PATH=$PATH:$HOME/go/bin'

    try:
        # Check if PATH line already exists
        if os.path.exists(zprofile_path):
            with open(zprofile_path, 'r', encoding='utf-8') as f:
                content = f.read()
                if path_line in content:
                    print("Go bin already in PATH")
                    return True

        # Add PATH line
        with open(zprofile_path, 'a', encoding='utf-8') as f:
            f.write(f'\n{path_line}\n')

        print("Added Go bin to PATH in ~/.zprofile")
        return True

    except Exception as e:
        print(f"Error setting up PATH: {e}")
        return False


def main():
    """Main function."""
    if platform.system() != "Darwin":
        print("This script is for macOS only. Use the original install.py for other systems.")
        sys.exit(1)

    success = install_macos()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
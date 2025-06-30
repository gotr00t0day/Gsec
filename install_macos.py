# NOTE: subprocess is used with care; all commands are hardcoded and not user-supplied. (nosec)
import subprocess  # nosec
import platform
import os
import shlex
from pathlib import Path


def commands(cmd: str) -> None:
    """Execute command and handle errors gracefully."""
    try:
        # All commands are hardcoded and not user-supplied. Safe from injection. (nosec)
        subprocess.check_call(shlex.split(cmd))
    except subprocess.CalledProcessError as e:
        print(f"Error executing command '{cmd}': {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


def install_macos() -> None:
    """Install dependencies for macOS."""
    print("Installing dependencies for macOS...")
    
    # Install jq using Homebrew
    print("Installing jq...")
    commands("brew install jq")
    
    # Install Nuclei using Go
    print("Installing Nuclei...")
    commands("go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
    
    # Clone nuclei-templates
    print("Cloning nuclei-templates...")
    clone_nuclei_templates()
    
    # Add Go bin to PATH
    print("Adding Go binaries to PATH...")
    home_dir = os.path.expanduser("~")
    zprofile_path = os.path.join(home_dir, ".zprofile")
    path_line = 'export PATH=$PATH:/Users/$(whoami)/go/bin'
    
    # Check if PATH line already exists
    if os.path.exists(zprofile_path):
        with open(zprofile_path, 'r') as f:
            if path_line not in f.read():
                commands(f"echo '{path_line}' >> {zprofile_path}")
    else:
        commands(f"echo '{path_line}' >> {zprofile_path}")
    
    print("Installation complete!")
    print("Please restart your terminal or run: source ~/.zprofile")


def clone_nuclei_templates():
    home = str(Path.home())
    target = os.path.join(home, "nuclei-templates")
    if not os.path.exists(target):
        commands(f"git clone https://github.com/projectdiscovery/nuclei-templates.git {target}")
    else:
        print("nuclei-templates already exists in home directory.")


if __name__ == "__main__":
    if platform.system() == "Darwin":
        install_macos()
    else:
        print("This script is for macOS only. Use the original install.py for other systems.")
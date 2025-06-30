import subprocess 
import platform

def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass

def install_macos():
    print("Installing dependencies for macOS...")
    
    # Install jq using Homebrew
    print("Installing jq...")
    commands("brew install jq")
    
    # Install Nuclei using Go
    print("Installing Nuclei...")
    commands("go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
    
    # Clone nuclei-templates
    print("Cloning nuclei-templates...")
    commands("cd ~ && git clone https://github.com/projectdiscovery/nuclei-templates.git")
    
    # Add Go bin to PATH
    print("Adding Go binaries to PATH...")
    commands("echo 'export PATH=\\$PATH:/Users/$(whoami)/go/bin' >> ~/.zprofile")
    
    print("Installation complete!")
    print("Please restart your terminal or run: source ~/.zprofile")

if __name__ == "__main__":
    if platform.system() == "Darwin":
        install_macos()
    else:
        print("This script is for macOS only. Use the original install.py for other systems.") 
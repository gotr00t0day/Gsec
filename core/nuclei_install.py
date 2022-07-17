import subprocess 


def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass

# This will install nuclei which does part of the vulnerability scanning.

commands("go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
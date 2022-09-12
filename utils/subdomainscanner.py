from colorama import Fore
import subprocess 

target = sys.argv[0]

def spotter(site: str) -> str:
    if "https://" in site:
        site = site.replace("https://", "")
    if "http://" in site:
        site = site.replace("http://", "")          
        cmd = f"./subdomainscanners/spotter.sh {site}"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, err = p.communicate()
        out = out.decode()
        print(out)

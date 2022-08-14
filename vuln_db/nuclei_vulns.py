from colorama import Fore
import requests
import subprocess


def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass


def nuclei_nginx_scan(url: str) -> str:
    sessions = requests.Session()
    res = sessions.get(f"{url}", verify=False)
    for item, value in res.headers.items():
        if "nginx" in value:
            cmd = f"nuclei -t ~/nuclei-templates/misconfiguration/nginx/ -u {url} -silent"
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            check, err = p.communicate()
            check = check.decode()
            if check:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.GREEN}{check}")
        else:
            pass

def nuclei_cve_scan(domain: str) -> str:
    cmd = "nuclei -u {domain} -tags cve -severity critical,high -silent"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check, err = p.communicate()
    check = check.decode()
    
    if check:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.GREEN}{check}")
    else:
        pass
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
            commands(f"nuclei -t ~/nuclei-templates/misconfiguration/nginx/ -u {url} -silent")

def nuclei_cve_scan(domain: str) -> str:
    commands("nuclei -u {domain} -tags cve -severity critical,high -silent")

def nuclei_headercommandinjection_scan(domain: str) -> str:
    commands("nuclei -t fuzzing/ -u {domain} -silent")

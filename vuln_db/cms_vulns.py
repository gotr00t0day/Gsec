from colorama import Fore
import subprocess

def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass

def apache_vuln_scan(url: str):
    cmd = f"nuclei -t ~/nuclei-templates/vulnerabilities/apache/ -u {url} -silent"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check, err = p.communicate()
    check = check.decode()
    
    if check:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.GREEN}{check}")
    else:
        pass

def joomla_vuln_scan(url: str):
    cmd = f"nuclei -t ~/nuclei-templates/vulnerabilities/joomla/ -u {url} -silent"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check, err = p.communicate()
    check = check.decode()
    
    if check:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.GREEN}{check}")
    else:
        pass

def drupal_vuln_scan(url: str):
    cmd = f"nuclei -t ~/nuclei-templates/vulnerabilities/drupal/ -u {url} -silent"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check, err = p.communicate()
    check = check.decode()

    if check:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.GREEN}{check}")
    else:
        pass

def jira_vuln_scan(url: str):
    cmd = f"nuclei -t ~/nuclei-templates/vulnerabilities/jira/ -u {url} -silent"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check, err = p.communicate()
    check = check.decode()

    if check:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.GREEN}{check}")
    else:
        pass
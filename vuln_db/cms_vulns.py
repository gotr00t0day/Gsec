from colorama import Fore
import subprocess
import os

def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass

def apache_vuln_scan(url: str):
    cmd = "nuclei -t ~/nuclei-templates/vulnerabilities/apache/ -u {url} -silent"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check, err = p.communicate()
    check = check.decode()
    
    if check:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.GREEN}{check}")
    else:
        pass

def joomla_vuln_scan(url: str):
    cmd = "nuclei -t ~/nuclei-templates/vulnerabilities/joomla/ -u {url} -silent"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check, err = p.communicate()
    check = check.decode()
    
    if check:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.GREEN}{check}")
    else:
        pass

def drupal_vuln_scan(url: str):
    cmd = "nuclei -t ~/nuclei-templates/vulnerabilities/drupal/ -u {url} -silent"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check, err = p.communicate()
    check = check.decode()

    if check:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.GREEN}{check}")
    else:
        pass

def jira_vuln_scan(url: str):
    cmd = "nuclei -t ~/nuclei-templates/vulnerabilities/jira/ -u {url} -silent"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check, err = p.communicate()
    check = check.decode()

    if check:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.GREEN}{check}")
    else:
        pass

def wordpress_vuln_scan(url: str):
    cmd = "nuclei -t ~/nuclei-templates/vulnerabilities/wordpress/ -u {url} -silent"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check, err = p.communicate()
    check = check.decode()

    if check:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.GREEN}{check}")
    else:
        pass

    cmd2 = "nuclei -t ~/nuclei-templates/vulnerabilities/fuzzing/wordpress-weak-credentials.yaml -u {url} -silent"
    p = subprocess.Popen(cmd2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check2, err = p.communicate()
    check2 = check2.decode()

    if check2:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.GREEN}{check2}")
    else:
        pass
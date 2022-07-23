from colorama import Fore
import subprocess
import os

def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass

def fuzz(url: str):
    jaeles_path = os.getcwd()
    cmd = f"{jaeles_path}/tools/jaeles scan -s {jaeles_path}/jaeles_signatures/fuzz/ -u {url} -q"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check, err = p.communicate()
    check = check.decode()
    
    if check:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.GREEN}{check}")
    else:
        pass
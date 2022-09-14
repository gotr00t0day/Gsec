from colorama import Fore
from modules import scan
import subprocess
import os

def apache_vuln_scan(url: str):
    scan.commands("nuclei -t ~/nuclei-templates/vulnerabilities/apache/ -u {url} -silent")

def joomla_vuln_scan(url: str):
    scan.commands("nuclei -t ~/nuclei-templates/vulnerabilities/joomla/ -u {url} -silent")

def drupal_vuln_scan(url: str):
    scan.commands("nuclei -t ~/nuclei-templates/vulnerabilities/drupal/ -u {url} -silent")

def jira_vuln_scan(url: str):
    scan.commands("nuclei -t ~/nuclei-templates/vulnerabilities/jira/ -u {url} -silent")

def wordpress_vuln_scan(url: str):
    scan.commands("nuclei -t ~/nuclei-templates/vulnerabilities/wordpress/ -u {url} -silent")
from colorama import Fore
from modules import scan, sub_output
from parsers import nuclei


def apache_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags apache -silent")
    nuclei.parse()

def joomla_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags joomla -silent")
    nuclei.parse()

def drupal_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags drupal -silent")
    nuclei.parse()

def jira_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags jira -silent")
    nuclei.parse()

def wordpress_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags wordpress -silent")
    nuclei.parse()

def umbraco_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags umbraco -silent")
    nuclei.parse()

def magento_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags magentoo -silent")
    nuclei.parse()

def phpbb_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags phpbb -silent")
    nuclei.parse()

def shopify_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags shopify -silent")
    nuclei.parse()

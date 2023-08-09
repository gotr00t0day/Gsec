from colorama import Fore
from modules import scan, sub_output


def apache_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags apache -silent")

def joomla_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags joomla -silent")

def drupal_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags drupal -silent")

def jira_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags jira -silent")

def wordpress_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags wordpress -silent")

def umbraco_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags umbraco -silent")

def magento_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags magentoo -silent")

def phpbb_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags phpbb -silent")

def shopify_vuln_scan(url: str):
    sub_output.subpro_scan(f"nuclei -u {url} -tags shopify -silent")

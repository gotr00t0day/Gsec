import requests
import re
from bs4 import BeautifulSoup

def apache_version():
    url = 'https://httpd.apache.org/download.cgi'

    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    version = soup.find("h1", attrs={'id':'apache24'}).get_text()
    version_number = re.search(r'([\d.]+)', version).group(1)
    return version_number

def nginx_version():
    url = 'https://nginx.org/en/download.html'

    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    version = soup.find('a', attrs={'href':'/download/nginx-1.22.1.tar.gz'}).get_text()
    version_number = re.search(r'([\d.]+)', version).group(1)
    return version_number
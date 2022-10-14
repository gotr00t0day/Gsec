```bash

Web Security Scanner


              ,~,
             ((()-                   - GSec v0.16
             -''-.                   - by c0deninja 
            (\  /\)                  - @gotr00t0day (Instagram)
      ~______\) | `\
   ~~~(         |  ')                Happy Hacking!!!
      | )____(  |                    
     /|/     ` /|
     \ \      / |
     |\|\   /| |\
```
<h4 align="center">Web Security Scanner &amp; Exploitation.</h4>


![Python Version](https://img.shields.io/badge/python-3.9.12-green)
![Issues](https://img.shields.io/github/issues/gotr00t0day/Gsec)
![Stars](https://img.shields.io/github/stars/gotr00t0day/Gsec)
![Twitter](https://img.shields.io/twitter/url?style=social&url=https%3A%2F%2Ftwitter.com%2Fgotr00t0day)


<p align="center">
  <a href="#features">Features</a> •
  <a href="#keys">Keys</a> •
  <a href="#installation">Install</a> •
  <a href="#usage">Usage</a> •
  <a href="https://discord.gg/59cKfqNNHq">Join Discord</a>

</p>

<hr>

## Features

   * Passive Scan
     - Find assets with shodan
     - RapidDNS to get subdomains
     - Certsh to enumerate subdomains
     - DNS enumeration
     - Waybackurls to fetch old links
   
   * Normal / Agressive Scan
     - Domain http code
     - Web port scanning
     - Server information
     - HTTP security header scanner
     - CMS security identifier / misconfiguration scanner
     - Technology scanner 
     - Programming Language check
     - Nuclei vulnerability scanning

<hr>

## Installation

Make sure you have GoLang installed, with out it you won't be able to install nuclei.

```bash

git clone https://github.com/gotr00t0day/Gsec.git

cd Gsec

pip3 install -r requirements.txt

# Make sure that nuclei-templates is cloned in the / directory. Gsec fetches the templates from ~/nuclei-templates
python3 install.py

```

## Keys

```bash

Gsec will fetch the shodan API key from the core directory, the passive recon script supports scanning with shodan,
please save your shodan key in core/.shodan for the scan to be able to work.


```

## OUTPUT

```bash

Some outputs that are too large will be saved in a file in the output folder / directory.


```

## Usage

```bash
# normal (passive and aggresive scans)

python3 gsec.py -t https://domain.com

# Passive Recon

python3 gsec.py -t https://domain.com --passive_recon

```

## Issues

In python3.10+ you might get an SSL error while running Gsec. To fix this issue just ``` pip3 install ceritifi ``` and then do ```/Applications/Python\ 3.10/Install\ Certificates.command``` and the issue will be fixed.

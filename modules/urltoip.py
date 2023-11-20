import socket 

def get_ip(domain: str):
    try:
        if "http" in domain:
            domain = domain.replace("http://", "")
        if "https" in domain:
            domain = domain.replace("https://", "")
        if "http://www." in domain:
            domain = domain.replace("http://www.", "")
        if "https://www." in domain:
            domain = domain.replace("https://www.", "")
        return socket.gethostbyname(domain)
    except socket.gaierror: 
        pass
    except UnicodeError:
        pass
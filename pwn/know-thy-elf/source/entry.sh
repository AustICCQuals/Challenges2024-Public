#!/bin/sh

libwin=$(mktemp -u XXXXXX).c
libwinso=$(mktemp -u XXXXXX).so
main=$(mktemp -u XXXXXX)

./construct-win.py "/tmp/$libwin"
./construct-main.py "/tmp/$main.c"

echo "[+] Creating your libwin..."
gcc -B/bin -shared -o /tmp/$libwinso /tmp/$libwin

echo "[+] Compiling your challenge..."
gcc -B/bin -o /tmp/$main /tmp/$main.c -L/tmp -l:$libwinso -Wl,-rpath,/tmp

echo "[+] running $main... "
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. /tmp/$main

#!/usr/bin/env tinyrange
#tinyrange file .
#tinyrange size lg
#tinyrange pull-file /root/server
#tinyrange forward-site proxy.golang.org

cd /root

apk add go

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o server .

#!/usr/bin/env tinyrange
#tinyrange file .
#tinyrange pkg pkg:go
#tinyrange pull-file /root/out.tar.gz

cd /root

go run .

tar cvf out.tar.gz out

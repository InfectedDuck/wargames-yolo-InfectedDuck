#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname
echo "Executing and deleting all scripts in /var/spool/$myname:"
for i in *;
do
    echo "Handling $i"
    ./$i
    rm -f $i
done
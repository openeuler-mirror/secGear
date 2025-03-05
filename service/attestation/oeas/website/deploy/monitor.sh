#!/bin/bash
# this script is for website monitoring,
# when website is up, delete all cert file.

HOST=$1
DST_PATH=$2

delete_file() {
    if [ -d $DST_PATH ]; then
        echo "found $DST_PATH" > /dev/stdout
        rm -rf $DST_PATH/*
    else
        echo "$DST_PATH not found" > /dev/stdout
    fi
}

while true;
do
    sleep 20
    RET=$(curl -sIL -w "%{http_code}\n" -o /dev/null $HOST)
    if [ $RET == "200" ]; then
        echo "website is up!!!" > /dev/stdout
        delete_file
        if [ $? -eq 0 ]; then
            echo "successful delete file, exit" > /dev/stdout
            break
        else
            echo "failed to delete file" > /dev/stdout
        fi
    else
        echo "waiting for website up, http_status: $RET" > /dev/stdout
    fi
done

#!/bin/bash

bash /etc/nginx/monitor.sh $DET_URL $DST_PATH &
/usr/share/nginx/sbin/nginx -g 'daemon off;'
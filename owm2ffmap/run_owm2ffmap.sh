#!/bin/bash

cd /var/www/hopglass.berlin.freifunk.net/owm2ffmap
source env/bin/activate
timeout 300s python owm2ffmap.py > /tmp/owm2ffmap.log 2>&1 && cp -a nodes.json graph.json /var/www/hopglass.berlin.freifunk.net/www/ && (cat /var/www/hopglass.berlin.freifunk.net/www/hopglass.appcache.template ; echo -n "# date: " ; date) > /var/www/hopglass.berlin.freifunk.net/www/hopglass.appcache

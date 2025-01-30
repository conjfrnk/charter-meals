#!/usr/local/bin/bash

#gzip -5fk style.css

gzip -7fk *.html

#find assets/ -type f -not -name "*.gz" -exec gzip -4fk "{}" \;

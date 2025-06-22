#!/bin/bash

cd libxml2/fuzzing

afl-fuzz -i in/ -o out -- ./xmllint_cov @@

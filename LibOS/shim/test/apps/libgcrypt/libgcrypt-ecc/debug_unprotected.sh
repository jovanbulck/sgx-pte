#!/bin/bash

LD_LIBRARY_PATH=libgcrypt/local/lib/:../libgpg-error-1.26/local/lib gdb --quiet -x gdb_script.py

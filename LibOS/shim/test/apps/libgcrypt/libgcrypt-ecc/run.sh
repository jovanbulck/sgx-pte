#!/bin/bash

sudo sh -c "echo 200000 > /sys/kernel/debug/tracing/buffer_size_kb"
sudo sh -c "echo '' > /sys/kernel/debug/tracing/trace"

../../pal_loader main $1
sudo cat /sys/kernel/debug/tracing/trace > measurements_raw.txt
dmesg | tail -n 30
./parse.py > measurements_parsed.txt
tail measurements_parsed.txt

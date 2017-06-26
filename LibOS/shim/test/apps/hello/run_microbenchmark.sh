#!/bin/bash

sudo sh -c "echo 200000 > /sys/kernel/debug/tracing/buffer_size_kb"
sudo sh -c "echo '' > /sys/kernel/debug/tracing/trace"

../pal_loader helloworld 0xbeef
sudo cat /sys/kernel/debug/tracing/trace > measurements_raw.txt
dmesg | tail

./parse_microbenchmarks.py
wc -l measurements.txt
R -q -e "x <- read.csv('measurements.txt', header = F); summary(x); \
         v <- sd(x[ , 1]); names(v) <- (' Std deviation:'); print(v);"
gnuplot plot_hist.gp

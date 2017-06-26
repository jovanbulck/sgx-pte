#!/bin/bash

# ensure KVM module is unloaded, since we hook into one of its IPI vectors
sudo service qemu-kvm stop
sudo rmmod kvm

sudo service aesmd stop
sudo rmmod graphene_sgx
sudo rmmod isgx
make || exit -1
sudo modprobe isgx || exit -1
sudo insmod graphene-sgx.ko || exit -1
sudo service aesmd start || exit -1

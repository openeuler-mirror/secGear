#!/bin/bash

mkdir build && cd build && cmake .. && make

./proxy_enclave &

./proxy_host &

sleep 25
rm -rf ../build


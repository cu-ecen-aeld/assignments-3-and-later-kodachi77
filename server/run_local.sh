#!/bin/bash

sudo -v

lsmod | grep 'aesdchar' > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Driver is already loaded. Unloading..."
    sudo ./aesdchar_unload

fi

chmod -x *.c *.h Makefile

make
../aesd-char-driver/make

echo "Loading driver"
sudo ../aesd-char-driver/aesdchar_load

./aesdsocket &
pid=$!

echo "Running test"
../assignment-autotest/test/assignment8/sockettest.sh > sockettest.log 2>&1

dmesg | grep 'aesdchar' > dmesg.log

kill $pid
sleep 1

if kill -0 $pid 2>/dev/null; then
    echo "aesdsocket ($pid) is still running."
else
    echo "aesdsocket ($pid) has been killed."
fi

echo "Unloading driver"
sudo ../aesd-char-driver/aesdchar_unload

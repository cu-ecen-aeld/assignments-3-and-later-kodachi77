#!/bin/sh

sudo -v

lsmod | grep 'aesdchar' > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Driver is already loaded. Unloading..."
    sudo ./aesdchar_unload

fi

chmod -x *.c *.h Makefile

make

echo "Loading dirver"
sudo ./aesdchar_load
echo "Running test"
../assignment-autotest/test/assignment8/drivertest.sh > drivertest.log 2>&1
echo "Unloading driver"
sudo ./aesdchar_unload
sudo tail -512 /var/log/kern.log | grep 'aesdchar' > dmesg.log
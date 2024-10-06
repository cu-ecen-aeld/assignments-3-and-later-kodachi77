#!/bin/sh

sudo -v

lsmod | grep 'aesdchar' > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Driver is already loaded. Unloading..."
    sudo ./aesdchar_unload

fi

make

echo "Clearing logs"
#sudo truncate -s 0 /var/log/kern.log
#sudo truncate -s 0 /var/log/syslog

chmod -x *.c *.h Makefile

echo "Loading dirver"
sudo ./aesdchar_load
echo "Running test"
../assignment-autotest/test/assignment8/drivertest.sh > drivertest.log 2>&1
echo "Unloading driver"
sudo ./aesdchar_unload
dmesg | grep 'aesdchar' > dmesg.log
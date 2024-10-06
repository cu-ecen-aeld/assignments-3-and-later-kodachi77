#!/bin/bash

sudo -v

lsmod | grep 'aesdchar' > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Driver is already loaded. Unloading..."
    sudo ../aesd-char-driver/aesdchar_unload

fi

chmod -x *.c *.h Makefile

make
cd ../aesd-char-driver && make && cd ../server

echo "Loading driver"
sudo ../aesd-char-driver/aesdchar_load

#valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=all --track-origins=yes --errors-for-leak-kinds=definite --verbose --log-file=valgrind-out.txt ./aesdsocket &
./aesdsocket &
pid=$!

echo "Running test"
../assignment-autotest/test/assignment8/sockettest.sh > sockettest.log 2>&1

sudo tail -512 /var/log/kern.log | grep 'aesdchar' > dmesg.log

kill $pid
sleep 1

if kill -0 $pid 2>/dev/null; then
    echo "aesdsocket ($pid) is still running."
else
    echo "aesdsocket ($pid) has been killed."
fi

# cat /dev/aesdchar

echo "Unloading driver"
sudo ../aesd-char-driver/aesdchar_unload

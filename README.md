#ZTE AX226

This is driver for linux system patched for ZTE ax226 usb modem

This drivers is working on i386 and x86_64 systems.

###installation

make

make install

###additional information

If you want to enable your device during system boot add 'drxvi314 ' to the end of file /etc/modules

and configure you device in file  /etc/network/interfaces like this

###

auto eth1

iface eth1 inet manual

pre-up /etc/init.d/wimax start

###

where eth1 - your device 
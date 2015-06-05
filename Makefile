KERNEL_VER 	:= $(shell uname -r)
KDIR 		:= /lib/modules/$(KERNEL_VER)/build
KSRC 		:= /lib/modules/$(KERNEL_VER)/source
INSTALL_DIR := /lib/modules/$(KERNEL_VER)/
TARGET_DRV 	:= drxvi314
INTERFACE 	:= Interface/usb/
COMMON		:= Common/
EXTRA_CFLAGS := -I$(src)/Include/
EXTRA_LDFLAGS := -s 

ANDROID		:= 
EXTRAFLAGS	:= -Wall O=$(KDIR)

ifeq ($(ANDROID), y)
	EXTRAFLAGS = 
endif

ifneq ($(KERNELRELEASE),)

obj-m = $(TARGET_DRV).o

$(TARGET_DRV)-objs := $(INTERFACE)InterfaceDld.o \
		$(INTERFACE)InterfaceIdleMode.o $(INTERFACE)InterfaceInit.o\
 		$(INTERFACE)InterfaceRx.o\
		$(INTERFACE)InterfaceIsr.o\
		$(INTERFACE)InterfaceMisc.o $(INTERFACE)InterfaceTx.o\
		$(COMMON)Arp.o $(COMMON)CmHost.o $(COMMON)Debug.o\
		$(COMMON)IPv6Protocol.o $(COMMON)Qos.o $(COMMON)Transmit.o\
		$(COMMON)Bcmnet.o $(COMMON)DDRInit.o $(COMMON)HandleControlPacket.o\
		$(COMMON)LeakyBucket.o $(COMMON)Misc.o $(COMMON)sort.o\
		$(COMMON)Bcmchar.o $(COMMON)hostmibs.o $(COMMON)PHSModule.o $(COMMON)BufferDld.o\
	 	$(COMMON)Osal_Misc.o $(COMMON)led_control.o $(COMMON)nvm.o $(COMMON)vendorspecificextn.o

else

PWD:= $(shell pwd)
default:
	$(MAKE) $(EXTRAFLAGS) -C $(KSRC) SUBDIRS=$(PWD) modules

	rm -f *.o *.mod.* .*.cmd
install:
	cp $(TARGET_DRV).ko $(INSTALL_DIR)
clean:
	find . -name \*.o -exec rm -rf '{}' ';'
	find . -name .\*.o.cmd -exec rm -rf '{}' ';'
	find . -name \*.*~ -exec rm -rf '{}' ';'
	find . -name \*.*.bak -exec rm -rf '{}' ';'
	rm -f *.ko *.o *.mod.* .*.cmd
	rm -fr .tmp_versions
	rm -rf Module.symvers
endif

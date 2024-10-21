# Load against the same system where you used to build. For example, we used ../../linux. We have to have ../../linux kernel
KDIR ?= /lib/modules/$(shell uname -r)/build
# Specify the module name
MODULE_NAME = tc_ingress_clsact_filter
# Specify the object files
obj-m += $(MODULE_NAME).o
# Build target
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
# Clean target
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
.PHONY: all clean

# Load against the same system where you used to build. For example, we used ../../linux. We have to have ../../linux kernel
MODULE_NAME := tc_ingress_clsact_filter
KERNEL_SOURCE := ../../linux
KDIR := $(KERNEL_SOURCE)
PWD := $(shell pwd)
EXTRA_CFLAGS += -I$(KDIR)/include
# Build the module
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
# Clean up
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
.PHONY: all clean

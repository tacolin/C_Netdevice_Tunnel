ifneq ($(KERNELRELEASE),)

obj-m   := taco.o
taco-objs := kmain.o kdev.o kfilter.o

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

default:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) modules


endif

clean:
	@$(RM) -rf *.o *.ko *~ core .depend *.mod.c .*.cmd .tmp_versions .*.o.d *.symvers *.markers *.order



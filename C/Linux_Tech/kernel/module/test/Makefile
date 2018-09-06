#obj-m: 模块名称
obj-m := test.o

#跳转到内核源码目录下，读取那里的Makefile
KERNELDIR ?= /usr/src/linux-headers-$(shell uname -r)

# M=$(PWD) modules 回到当前目录下继续执行当前目录下的Makefile
PWD := $(shell pwd)

all: modules


modules:
	make -C $(KERNELDIR) M=$(PWD) modules


clean:
	rm -rf *.o *~ core .depend *.symvers .*.cmd *.ko *.mod.c .tmp_versions *.order

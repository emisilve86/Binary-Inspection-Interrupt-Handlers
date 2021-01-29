obj-m = inspection-module.o

inspection-module-objs := disassembler.o inspection.o

all:
	KCPPFLAGS="-DIDT_INDEX=236" make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
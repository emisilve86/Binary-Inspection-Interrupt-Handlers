# Binary Inspection of Linux Interrupt Handlers on x86_64 Architectures #

This is a kernel module designed to perform binary inspection of x86_64 code related to the management of interrupts on Linux OS. It exploits the content of the **idtr** register to retrieve the address of the entry-point function devoted to handle a specific interrupt. The latter is read from the **IDT** entry of interest. Binaries are then disassembled and eventual *jmp* and *call* are followed so as to dump the instructions with the same order they are expected to be processed. The inspection terminates when the *iret* instruction is encountered.

Inspection is performed only once when the module is loaded. Then the module can be also removed. Its purpose is only that of dumping x86_64 assembly code.

The generated x86_64 assembly is printed along with the relative addresses within the **dmesg** buffer. If the kernel is compiled with ```KALLSYMS``` enabled, also the available symbols are printed inline with the assembly.

## Usage

In order to use this module, the user has to:

* open the Makefile and replace the default value of ```IDT_INDEX``` with a valid index within the **IDT** table

* compile with ```make```

* load the module with ```insmod inspection-module.ko```

* launch ```dmesg``` from terminal

* unmount the module with ```rmmod inspection_module```

## Example

An example of the output can be as follows:
```sh
[Interrupt Handler Inspection] Binary inspection starting from the "Local APIC Timer Interrupt" routine (IDT index 236)
0xffffffffad401c60: 68 13 ff ff ff           push 0xffffff13
0xffffffffad401c65: e8 b6 ec ff ff           call 0xad400920      [interrupt_entry+0x0/0xc8]
  0xffffffffad400920: 66                       data16
  0xffffffffad400921: 66                       data16
  0xffffffffad400922: 90                       nop
  0xffffffffad400923: fc                       cld
  0xffffffffad400924: f6 44 24 18 03           test BYTE PTR [esp+0x18],0x3
  0xffffffffad400929: 74 44                    jz 0xad40096f
  0xffffffffad40092b: 0f 01 f8                 sgdtd eax
                ...                               ...
```
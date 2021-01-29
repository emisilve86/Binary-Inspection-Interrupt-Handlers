/*****************************************************************************
 * Copyright  2021  Emisilve86                                               *
 *                                                                           *
 * Licensed under the Apache License, Version 2.0 (the "License");           *
 * you may not use this file except in compliance with the License.          *
 * You may obtain a copy of the License at                                   *
 *                                                                           *
 *     http://www.apache.org/licenses/LICENSE-2.0                            *
 *                                                                           *
 * Unless required by applicable law or agreed to in writing, software       *
 * distributed under the License is distributed on an "AS IS" BASIS,         *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 * See the License for the specific language governing permissions and       *
 * limitations under the License.                                            *
 *****************************************************************************/

#ifdef CONFIG_X86_64
#include <linux/version.h>
#include <linux/module.h>
#ifdef CONFIG_KALLSYMS
#include <linux/kallsyms.h>
#endif
#include <linux/slab.h>
#include <asm/desc.h>
#include <asm/desc_defs.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
#include <asm/trapnr.h>
#else
#include <asm/traps.h>
#endif
#include <asm/irq_vectors.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable_types.h>


#define MAX_LEVEL			5
#define SEQUENCE_MAX_BYTES	16392
#define BUFFER_SIZE			128

#define ADDRESS_MASK		0xfffffffffffff000
#define PAGE_TABLE_ADDRESS	phys_to_virt(__read_cr3() & ADDRESS_MASK)
#define PT_ADDRESS_MASK		0x7ffffffffffff000
#define VALID				0x1
#define LH_MAPPING			0x80

#define PML4(addr)	(((long long)(addr) >> 39) & 0x1ff)
#define PDP(addr)	(((long long)(addr) >> 30) & 0x1ff)
#define PDE(addr)	(((long long)(addr) >> 21) & 0x1ff)
#define PTE(addr)	(((long long)(addr) >> 12) & 0x1ff)


struct idt_entry_info {
	char *name;
	unsigned short index;
	unsigned long address;
} __attribute__((packed));

typedef struct idt_entry_info entry_info;


static entry_info *idt_entries;

static const char *idt_entry_names[NR_VECTORS] = {
	[X86_TRAP_DE] = "Divide-by-zero",											/* 0 */
	[X86_TRAP_DB] = "Debug",													/* 1 */
	[X86_TRAP_NMI] = "Non-maskable Interrupt",									/* 2 */
	[X86_TRAP_BP] = "Breakpoint",												/* 3 */
	[X86_TRAP_OF] = "Overflow",													/* 4 */
	[X86_TRAP_BR] = "Bound Range Exceeded",										/* 5 */
	[X86_TRAP_UD] = "Invalid Opcode",											/* 6 */
	[X86_TRAP_NM] = "Device Not Available",										/* 7 */
	[X86_TRAP_DF] = "Double Fault",												/* 8 */
	[X86_TRAP_OLD_MF] = "Coprocessor Segment Overrun",							/* 9 */
	[X86_TRAP_TS] = "Invalid TSS",												/* 10 */
	[X86_TRAP_NP] = "Segment Not Present",										/* 11 */
	[X86_TRAP_SS] = "Stack Segment Fault",										/* 12 */
	[X86_TRAP_GP] = "General Protection Fault",									/* 13 */
	[X86_TRAP_PF] = "Page Fault",												/* 14 */
	[X86_TRAP_SPURIOUS] = "Spurious Interrupt",									/* 15 */
	[X86_TRAP_MF] = "x87 Floating-Point Exception",								/* 16 */
	[X86_TRAP_AC] = "Alignment Check",											/* 17 */
#ifdef CONFIG_X86_MCE
	[X86_TRAP_MC] = "Machine Check",											/* 18 */
#endif
	[X86_TRAP_XF] = "SIMD Floating-Point Exception",							/* 19 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	[X86_TRAP_VE] = "Virtualization Exception",									/* 20 */
	[X86_TRAP_CP] = "Control Protection Exception",								/* 21 */
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	[X86_TRAP_VC] = "VMM Communication Exception",								/* 29 */
#endif
	[IRQ_MOVE_CLEANUP_VECTOR] = "IRQ Move Cleanup",								/* 32 */
	[48 ... 63] = "ISA Interrupt",												/* 48 ... 63 */
	[IA32_SYSCALL_VECTOR] = "IA32 Syscall",										/* 128 */
	[LOCAL_TIMER_VECTOR] = "Local APIC Timer Interrupt",						/* 236 */
#if IS_ENABLED(CONFIG_HYPERV)
	[HYPERV_STIMER0_VECTOR] = "Hypervisor STimer0 Interrupt",					/* 237 */
	[HYPERV_REENLIGHTENMENT_VECTOR] = "Hypervisor Re-enlightement Interrupt",	/* 238 */
#endif
	[MANAGED_IRQ_SHUTDOWN_VECTOR] = "Managed IRQ Shutdown",						/* 239 */
#ifdef CONFIG_HAVE_KVM
	[POSTED_INTR_NESTED_VECTOR] = "Posted Interrupt Nested",					/* 240 */
	[POSTED_INTR_WAKEUP_VECTOR] = "Posted Interrupt Wakeup",					/* 241 */
	[POSTED_INTR_VECTOR] = "Posted Interrupt",									/* 242 */
#endif
	[HYPERVISOR_CALLBACK_VECTOR] = "Hypervisor Interrupt",						/* 243*/
	[DEFERRED_ERROR_VECTOR] = "Deferred Error Interrupt",						/* 244 */
	[UV_BAU_MESSAGE] = "UV BAU Message",										/* 245 */
	[IRQ_WORK_VECTOR] = "IRQ Work",												/* 246 */
	[X86_PLATFORM_IPI_VECTOR] = "x86 Platform IPI",								/* 247 */
	[REBOOT_VECTOR] = "Reboot Interrupt",										/* 248 */
	[THRESHOLD_APIC_VECTOR] = "Threshold APIC Interrupt",						/* 249 */
	[THERMAL_APIC_VECTOR] = "Thermal APIC Interrupt",							/* 250 */
	[CALL_FUNCTION_SINGLE_VECTOR] = "Call Function Single Interrupt",			/* 251 */
	[CALL_FUNCTION_VECTOR] = "Call Function Interrupt",							/* 252 */
	[RESCHEDULE_VECTOR] = "Reschedule INterrupt",								/* 253 */
	[ERROR_APIC_VECTOR] = "Error APIC Interrupt",								/* 254 */
	[SPURIOUS_APIC_VECTOR] = "Spurious APIC Interrupt",							/* 255 */
};


unsigned int disassemble(unsigned char *bytes, unsigned int max, int offset, char *output);


static long resolve_jmp_address(unsigned char *byte, unsigned int count)
{
	unsigned int rip;
	unsigned int operand;

	if (byte[0] == 0xE9 && count == 5) /* jmp imm32 */
	{
		rip = (unsigned int) (((unsigned long) &byte[count]) & 0xffffffffUL);
		operand = ((unsigned int) byte[1]) | (((unsigned int) byte[2]) << 8) |
			(((unsigned int) byte[3]) << 16) | (((unsigned int) byte[4]) << 24);

		if ((1U << 31) & operand)
		{
			operand = (1U << 31) - (operand & ~(1U << 31));
			return ((long) (rip - operand)) | ~(0xffffffffL);
		}
		else
		{
			return ((long) (rip + operand)) | ~(0xffffffffL);
		}
	}
	else if (byte[0] == 0xEB && count == 2) /* jmp imm8 */
	{
		rip = (unsigned int) (((unsigned long) &byte[count]) & 0xffffffffUL);
		operand = ((unsigned int) byte[1]) & 0xff;

		if ((1U << 7) & operand)
		{
			operand = (1U << 7) - (operand & ~(1U << 7));
			return ((long) (rip - operand)) | ~(0xffffffffL);
		}
		else
		{
			return ((long) (rip + operand)) | ~(0xffffffffL);
		}

		return (((long) &byte[count]) + (long) operand) | ~(0xffffffffUL); /* RIP + operand */
	}
	else
	{
		return 0;
	}
}

static long resolve_call_address(unsigned char *byte, unsigned int count)
{
	unsigned int rip;
	unsigned int operand;

	if (byte[0] == 0xE8 && count == 5) /* call imm32 */
	{
		rip = (unsigned int) (((unsigned long) &byte[count]) & 0xffffffffUL);
		operand = ((unsigned int) byte[1]) | (((unsigned int) byte[2]) << 8) |
			(((unsigned int) byte[3]) << 16) | (((unsigned int) byte[4]) << 24);

		if ((1U << 31) & operand)
		{
			operand = (1U << 31) - (operand & ~(1U << 31));
			return ((long) (rip - operand)) | ~(0xffffffffL);
		}
		else
		{
			return ((long) (rip + operand)) | ~(0xffffffffL);
		}
	}
	else
	{
		return 0;
	}
}

static int check_page_is_valid_get_frame_number(unsigned long address)
{
    void *target_address;

    pud_t *pdp;
    pmd_t *pde;
    pte_t *pte;
    pgd_t *pml4;

    int frame_number;
    unsigned long frame_addr;


    target_address = (void *) address;

    pml4  = PAGE_TABLE_ADDRESS;

    if(!(((ulong)(pml4[PML4(target_address)].pgd)) & VALID))
        return -1;

    pdp = __va((ulong)(pml4[PML4(target_address)].pgd) & PT_ADDRESS_MASK);

    if(!((ulong)(pdp[PDP(target_address)].pud) & VALID))
        return -1;

    pde = __va((ulong)(pdp[PDP(target_address)].pud) & PT_ADDRESS_MASK);

    if(!((ulong)(pde[PDE(target_address)].pmd) & VALID))
        return -1;

    if((ulong)pde[PDE(target_address)].pmd & LH_MAPPING)
    {
        frame_addr = (ulong)(pde[PDE(target_address)].pmd) & PT_ADDRESS_MASK;

        frame_number = frame_addr >> 12;

        return frame_number;
    }

    pte = __va((ulong)(pde[PDE(target_address)].pmd) & PT_ADDRESS_MASK);

    if(!((ulong)(pte[PTE(target_address)].pte) & VALID))
        return -1;

    frame_addr = (ulong)(pte[PTE(target_address)].pte) & PT_ADDRESS_MASK;

    frame_number = frame_addr >> 12;

    return frame_number;
}

static void binary_inspection(entry_info *idt_entry)
{
	unsigned int b;
	unsigned int e;
	unsigned int count;
	unsigned int level = 0;

#ifdef CONFIG_KALLSYMS
	int symbol_size;
	char symbol_buffer[BUFFER_SIZE];
#endif

	unsigned char instruction[BUFFER_SIZE];
	unsigned char disassembled[BUFFER_SIZE];

	unsigned char *byte;
	unsigned long level_address[MAX_LEVEL + 1] = { 0UL };

	unsigned char prefix[MAX_LEVEL + 2];

	if (idt_entry && idt_entry->address)
	{
		if (idt_entry->name)
		{
			pr_info("[Kernel Inspection] : Binary inspection starting from the \"%s\" routine (IDT index: %hu)", idt_entry->name, idt_entry->index);
		}
#ifdef CONFIG_KALLSYMS
		else if ((symbol_size = sprint_symbol(symbol_buffer, idt_entry->address)) > 0)
		{
			pr_info("[Kernel Inspection] : Binary inspection starting from the \"%s\" routine (IDT index: %hu)", symbol_buffer, idt_entry->index);
		}
#endif
		else
		{
			pr_info("[Kernel Inspection] : Binary inspection starting from a routine with unknown name (IDT index: %hu)", idt_entry->index);
		}

		if (check_page_is_valid_get_frame_number(idt_entry->address) == -1)
		{
			pr_err("[Kernel Inspection] : The address stored within the IDT entry with index %hu is in a non-mapped page\n", idt_entry->index);
			return;
		}

		level_address[level] = idt_entry->address;

level_switch:
		for (b=0; b<=level; b++)
		{
			prefix[b] = '-';
		}
		prefix[b] = '\0';

follow_jump:
		byte = (unsigned char *) level_address[level];

		for (b=0, count=0; b<SEQUENCE_MAX_BYTES; b+=count)
		{
			count = disassemble(&byte[b], SEQUENCE_MAX_BYTES - b, ((unsigned int) (((unsigned long) &byte[b]) & 0xffffffffUL)), disassembled);

			instruction[0] = '\0';

			for (e=0; e<count; e++)
			{
				sprintf(instruction + strlen(instruction), "%02x ", byte[b + e]);
			}

			pr_info("%s %08x: %-24s %s", prefix, ((unsigned int) (((unsigned long) &byte[b]) & 0xffffffffUL)), instruction, disassembled);

			if (byte[b] == 0xC2 || byte[b] == 0xC3 || byte[b] == 0xCA || byte[b] == 0xCB || byte[b] == 0xCF) // RET
			{
				if (level)
				{
					level_address[level--] = 0UL;
					goto level_switch;
				}
				
				pr_info("[Kernel Inspection] : Binary inspection finished\n");
				break;
			}
			else if (byte[b] == 0xE9 || byte[b] == 0xEA || byte[b] == 0xEB) // JMP
			{
				long jmp_address = resolve_jmp_address(&byte[b], count);

				if (jmp_address)
				{
					unsigned char *jmp_opcode = (unsigned char *) (*((unsigned long *) &jmp_address));

					if (jmp_opcode[0] == 0xF2 || jmp_opcode[0] == 0xF3) // REP
					{
						continue;
					}

#ifdef CONFIG_KALLSYMS
					if ((symbol_size = sprint_symbol(symbol_buffer, jmp_address)) > 0)
					{
						pr_cont("      \x1B[33m[%s]", symbol_buffer);
					}
#endif
					if (check_page_is_valid_get_frame_number(jmp_address) != -1)
					{
						level_address[level] = *((unsigned long *) &jmp_address);
						goto follow_jump;
					}
					else
					{
						pr_info("%s --------: %s", prefix, "\x1B[37m[The destination address of JMP instruction is in a non-mapped page. Inspection is stopped.]\n");
						break;
					}
				}
				else
				{
					if (level)
					{
						pr_info("%s --------: %s", prefix, "\x1B[37m[Unable to resolve the destination address of JMP instruction. Return to the caller function.]\n");
						level_address[level--] = 0UL;
						goto level_switch;
					}
					else
					{
						pr_info("%s --------: %s", prefix, "\x1B[37m[Unable to resolve the destination address of JMP instruction. Inspection is stopped.]\n");
						break;
					}
				}
			}
			else if (byte[b] == 0x9A || byte[b] == 0xE8) // CALL
			{
				long call_address = resolve_call_address(&byte[b], count);

				if (call_address)
				{
#ifdef CONFIG_KALLSYMS
					if ((symbol_size = sprint_symbol(symbol_buffer, call_address)) > 0)
					{
						pr_cont("      \x1B[33m[%s]", symbol_buffer);
					}
#endif
					if (check_page_is_valid_get_frame_number(call_address) != -1)
					{
						if (level < MAX_LEVEL)
						{
							level_address[level++] = (unsigned long) &byte[b + count];
							level_address[level] = *((unsigned long *) &call_address);
							goto level_switch;
						}
						
						pr_info("%s --------: %s", prefix, "\x1B[37m[The destination address of CALL instruction is beyond the maximum level. Not expended.]");
					}
					else
					{
						pr_info("%s --------: %s", prefix, "\x1B[37m[The destination address of CALL instruction is in a non-mapped page. Not expanded.]");
					}
				}
				else
				{
					pr_info("%s --------: %s", prefix, "\x1B[37m[Unable to resolve the destination address of CALL instruction. Not expanded.]");
				}
			}
		}
	}
}

static int collect_IDT_entry_info(void)
{
	unsigned short i;

	gate_desc *gate_ptr;
	struct desc_ptr idtr;

	idt_entries = NULL;

	store_idt(&idtr);

	if (idtr.address)
	{
		if ((idt_entries = (entry_info *) kcalloc(NR_VECTORS, sizeof(entry_info), GFP_KERNEL)) != NULL)
		{
			for (i=0; i<NR_VECTORS; i++)
			{
				gate_ptr = (gate_desc *) (idtr.address + (i * sizeof(gate_desc)));

				idt_entries[i].name = (idt_entry_names[i]) ? (char *) idt_entry_names[i] : NULL;
				idt_entries[i].index = i;
				idt_entries[i].address = (((unsigned long) gate_ptr->offset_low) |
											((unsigned long) gate_ptr->offset_middle << 16) |
												((unsigned long) gate_ptr->offset_high << 32));
			}

			return 0;
		}

		pr_err("[Kernel Inspection] : Cannot allocate space to maintain information from IDT entries\n");
	}
	else
	{
		pr_err("[Kernel Inspection] : Cannot access the \"idtr\" register in order to diplace within the IDT table\n");
	}

	return -1;
}

static void clean_IDT_entry_info(void)
{
	if (idt_entries)
		kfree((const void *) idt_entries);
}
#endif

static __init int kernel_inspection_init(void)
{
	pr_info("[Kernel Inspection] : Initialization\n");

#ifdef CONFIG_X86_64
	if (collect_IDT_entry_info())
	{
		pr_err("[Kernel Inspection] : Cannot proceed with a binary inspection\n");
		return -1;
	}
# if defined IDT_INDEX && IDT_INDEX >= 0 && IDT_INDEX < 256
	binary_inspection(&idt_entries[IDT_INDEX]);
# else
	binary_inspection(&idt_entries[SPURIOUS_APIC_VECTOR]);
# endif
#else
	pr_err("[Kernel Inspection] : Works only on x86_64 architectures\n");
#endif

	return 0;
}

static __exit void kernel_inspection_exit(void)
{
#ifdef CONFIG_X86_64
	clean_IDT_entry_info();
#endif

	pr_info("[Kernel Inspection] : Finalization\n");
}

module_init(kernel_inspection_init);
module_exit(kernel_inspection_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Emiliano Silvestri <silvestri@diag.uniroma1.it>");
MODULE_DESCRIPTION("Inspection of x86_64 kernel's binaries exploiting the addresses kept by IDT entries");
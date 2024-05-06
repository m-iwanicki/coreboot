/* SPDX-License-Identifier: GPL-2.0-only */

#include <acpi/acpi.h>
#include <bootmem.h>
#include <bootstate.h>
#include <console/console.h>
#include <dasharo/uefi_capsules.h>
#include <drivers/efi/efivars.h>
#include <string.h>
#include <stdio.h>
#include <smmstore.h>
#include <types.h>

#include <vendorcode/intel/edk2/UDK2017/MdePkg/Include/Uefi/UefiSpec.h>
#include <vendorcode/intel/edk2/UDK2017/MdePkg/Include/Guid/GlobalVariable.h>
#include <vendorcode/intel/edk2/UDK2017/MdePkg/Include/Guid/FmpCapsule.h>
#include <vendorcode/intel/edk2/UDK2017/MdePkg/Include/IndustryStandard/WindowsUxCapsule.h>

/*
 * Overview
 *
 * SG stands for scatter-gather.  SG list consists of SG blocks that describe a
 * potentially discontinuous sequence of memory blocks while not necessarily
 * lying in continuous memory themselves.
 *
 * SG list is basically a linked list of arrays of block descriptors (SG
 * blocks).  Each of SG blocks can be:
 *  - a data block, which points to capsule's data
 *  - a continuation block, which says where other SG blocks are to be found
 *  - end-of-list block, which indicates there are no more blocks
 *
 * Each of the CapsuleUpdateData* EFI variables point to some SG list which
 * might contain one or more update capsules.  SG blocks never contain data of
 * more than one of the capsules.  Boundary between capsules in an SG list is
 * determined by parsing capsule headers and counting amount of data seen so
 * far.
 *
 * There can be multiple CapsuleUpdateData* variables (CapsuleUpdateData,
 * CapsuleUpdateData1, etc.) in which case their SG lists are chained together
 * after sanity checks.
 */

// XXX: to make it easier to adjust code if it will be 32-bit 
typedef uintptr_t fake_ptr_t;
#define DEBUG_STUFF 1 // XXX: to find things to remove later 

/* This should be more than enough. */
#define MAX_CAPSULES 32

/* For passing data to/out of in_unused_ram() and maintaining list of known
 * UEFI capsules in a global array. */
struct mem_range {
	const void *base;
	uint64_t len;
};

/* Input/output structure for pick_capsule_buffer(). */
struct capsule_buf {
	/* Input. */
	const resource_t size; /* Desired size of a buffer. */

	/* Output. */
	resource_t start; /* Buffer location. */
};

static const EFI_GUID global_variables_guid = EFI_GLOBAL_VARIABLE;
static const EFI_GUID windows_ux_capsule_guid = WINDOWS_UX_CAPSULE_GUID;
static const EFI_GUID edk2_capsule_on_disk_name_guid = {
	0x98C80A4F, 0xE16B, 0x4D11, { 0x93, 0x9A, 0xAB, 0xE5, 0x61, 0x26, 0x3, 0x30 }
};
static const EFI_GUID efi_fmp_capsule_guid = EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID;

/* Have to have global state for adding capsules to coreboot table. */
static struct mem_range uefi_capsules[MAX_CAPSULES];
static int uefi_capsule_count;

static bool is_data_block(const EFI_CAPSULE_BLOCK_DESCRIPTOR *block)
{
	return (block->Length != 0);
}

static bool is_final_block(const EFI_CAPSULE_BLOCK_DESCRIPTOR *block)
{
	return (block->Length == 0 && block->Union.ContinuationPointer == 0);
}

static void advance_block(EFI_CAPSULE_BLOCK_DESCRIPTOR **block)
{
	EFI_CAPSULE_BLOCK_DESCRIPTOR *b = *block;
	if (is_final_block(b))
		die("dasharo: attempt to advance beyond final SG block of UEFI capsules.\n");

	if (is_data_block(b)) {
		/* That was at least part of a capsule. */
		*block = b + 1;
	} else {
		/* End of continuous sequence of descriptors, but there are more. */
		uint64_t ptr = b->Union.ContinuationPointer;
		*block = (EFI_CAPSULE_BLOCK_DESCRIPTOR *)(fake_ptr_t)ptr;
	}
}

static bool is_good_capsule(const EFI_CAPSULE_HEADER *capsule)
{
	if (!(capsule->Flags & CAPSULE_FLAGS_PERSIST_ACROSS_RESET))
		return false;
	if (capsule->HeaderSize < sizeof(*capsule))
		return false;
	if (capsule->CapsuleImageSize <= capsule->HeaderSize)
		return false;

	const EFI_GUID *guid = &capsule->CapsuleGuid;
	if (memcmp(guid, &windows_ux_capsule_guid, sizeof(*guid)) == 0)
		return true;
	if (memcmp(guid, &edk2_capsule_on_disk_name_guid, sizeof(*guid)) == 0)
		return true;
	if (memcmp(guid, &efi_fmp_capsule_guid, sizeof(*guid)) == 0)
		return true;

	return false;
}

/* Callback for bootmem_walk() that checks for a BM_MEM_RAM range that contains
 * a specific address range. */
static bool in_unused_ram(const struct range_entry *r, void *arg)
{
	const struct mem_range *mr = arg;

	resource_t start = (fake_ptr_t)mr->base;
	resource_t end = start + mr->len;

	if (range_entry_tag(r) == BM_MEM_RAM &&
	    start >= range_entry_base(r) &&
	    end <= range_entry_end(r))
		return false;

	return true;
}

static bool is_in_unused_ram(const void *base, uint64_t len)
{
	struct mem_range range = { .base = base, .len = len };

	if (len == 0)
		die("dasharo: %s() was passed an empty range.\n", __func__);
	if ((fake_ptr_t)base + len < (fake_ptr_t)base)
		die("dasharo: %s() was passed an invalid range.\n", __func__);

	return bootmem_walk(in_unused_ram, &range);
}

static bool is_good_block(const EFI_CAPSULE_BLOCK_DESCRIPTOR *block)
{
	if ((fake_ptr_t)block % sizeof(uint64_t) != 0) {
		printk(BIOS_WARNING, "dasharo: misaligned SG block.\n");
		return false;
	}

	if (!is_in_unused_ram(block, sizeof(*block))) {
		printk(BIOS_ERR, "dasharo: SG block is not in unused memory.\n");
		return false;
	}

	return true;
}

static bool is_good_capsule_head(const EFI_CAPSULE_BLOCK_DESCRIPTOR *block)
{
	if (!is_data_block(block)) {
		printk(BIOS_ERR,
		       "dasharo: first capsule SG block is not a data block.\n");
		return false;
	}

	if (block->Length < sizeof(EFI_CAPSULE_HEADER)) {
		printk(BIOS_WARNING, "dasharo: first SG block of a capsule is too small.\n");
		return false;
	}

	void *ptr = (void *)(fake_ptr_t)block->Union.DataBlock;
	if (!is_in_unused_ram(ptr, block->Length)) {
		printk(BIOS_ERR, "dasharo: capsule header is not in unused memory.\n");
		return false;
	}

	return true;
}

static bool is_good_capsule_block(const EFI_CAPSULE_BLOCK_DESCRIPTOR *block, uint32_t size_left)
{
	if (is_final_block(block)) {
		printk(BIOS_WARNING, "dasharo: not enough SG blocks to cover a capsule.\n");
		return false;
	}

	if (!is_data_block(block)) {
		printk(BIOS_ERR, "dasharo: capsule SG block is not a data block.\n");
		return false;
	}

	if (block->Length > size_left) {
		printk(BIOS_WARNING, "dasharo: SG blocks reach beyond a capsule.\n");
		return false;
	}

	void *ptr = (void *)(fake_ptr_t)block->Union.DataBlock;
	if (!is_in_unused_ram(ptr, block->Length)) {
		printk(BIOS_ERR, "dasharo: capsule data is not in unused memory.\n");
		return false;
	}

	return true;
}

/* Checks a single SG list for sanity.  Returns address of its end-of-list
 * descriptor or NULL on error. */
static EFI_CAPSULE_BLOCK_DESCRIPTOR *check_capsule_block(EFI_CAPSULE_BLOCK_DESCRIPTOR *block,
							 uint64_t *total_data_size)
{
	if (!is_good_block(block))
		return NULL;

	while (!is_final_block(block)) {
		/*
		 * This results in dropping of this capsule block if any of
		 * contained capsule headers looks weird.  An alternative is to
		 * cut the capsule block upon finding a bad header.  Maybe
		 * could even jump over a broken capsule, temporarily trusting
		 * size field in its header because invalid value should not
		 * break parsing anyway, and then cut it out of the sequence of
		 * blocks.  EDK doesn't bother, so only noting the possibility.
		 */
		if (!is_good_capsule_head(block))
			return NULL;

		const EFI_CAPSULE_HEADER *capsule = (void *)(fake_ptr_t)block->Union.DataBlock;
		if (!is_good_capsule(capsule))
			return NULL;

		/* EDK doesn't seem to care, but let's align capsule headers (4
		 * should be enough, but 8 won't hurt). */
		*total_data_size += ALIGN_UP(capsule->CapsuleImageSize, 8);

		uint32_t size_left = capsule->CapsuleImageSize;
		while (size_left != 0) {
			/*
			 * is_good_block() holds here whether its the first
			 * iteration or not.
			 */

			if (!is_good_capsule_block(block, size_left))
				return NULL;

			size_left -= block->Length;

			advance_block(&block);
			if (!is_good_block(block))
				return NULL;

			if (!is_final_block(block) && !is_data_block(block)) {
				/* Advance to the next page of block descriptors. */
				advance_block(&block);
				/* Not expecting a continuation to be followed by another
				 * continuation or an end-of-list. */
				if (!is_good_block(block) || !is_data_block(block))
					return NULL;
			}
		}
	}

	return block;
}

/*
 * This function connects tail of one block of descriptors with the head of the
 * next one and returns pointer to the head of the whole chain.  While at it:
 *  - validate structures and pointers for sanity
 *  - compute total amount of memory needed for coalesced capsules
 */
static EFI_CAPSULE_BLOCK_DESCRIPTOR *verify_and_chain_blocks(
	EFI_CAPSULE_BLOCK_DESCRIPTOR **blocks,
	int block_count,
	uint64_t *total_data_size)
{
	/* This won't be blocks[0] if there is something wrong with the first
	 * capsule block. */
	EFI_CAPSULE_BLOCK_DESCRIPTOR *head = NULL;

	/* End-of-list descriptor of the last chained block. */
	EFI_CAPSULE_BLOCK_DESCRIPTOR *tail = NULL;

	*total_data_size = 0;

	int i;
	for (i = 0; i < block_count; ++i) {
		EFI_CAPSULE_BLOCK_DESCRIPTOR *last_block =
			check_capsule_block(blocks[i], total_data_size);
		if (last_block == NULL) {
			/* Fail hard instead?  EDK just keeps going, as if
			 * capsule blocks are always independent. */
			printk(BIOS_WARNING,
			       "dasharo: skipping damaged capsule block #%d @ %p.\n",
			       i, blocks[i]);
			continue;
		}

		if (head == NULL)
			head = blocks[i];
		else
			tail->Union.ContinuationPointer = (uint64_t)(fake_ptr_t)blocks[i];

		tail = last_block;
	}

	return head;
}

/* Callback for bootmem_walk() that finds a suitable BM_MEM_RAM range that is
 * below 4 GiB boundary. */
static bool pick_capsule_buffer(const struct range_entry *r, void *arg)
{
	struct capsule_buf *buf = arg;

	if (range_entry_tag(r) != BM_MEM_RAM)
		return true;

	if (range_entry_size(r) < buf->size)
		return true;

	if (range_entry_base(r) + buf->size > 4ULL * GiB)
		return true;

	buf->start = range_entry_base(r);
	return false;
}

/* Marks structures and data of SG lists as BM_MEM_RAMSTAGE so that bootmem
 * won't consider corresponding ranges unused.  BM_MEM_RAMSTAGE is effectively
 * discarded after coreboot is done, so this is really a temporary
 * reservation. */
static void reserve_capsules(EFI_CAPSULE_BLOCK_DESCRIPTOR *block_chain)
{
	EFI_CAPSULE_BLOCK_DESCRIPTOR *block = block_chain;

	/* This is the first block of a continuous sequence of blocks. */
	EFI_CAPSULE_BLOCK_DESCRIPTOR *seq_start = NULL;

	/* The code reserves sequences of blocks to avoid invoking
	 * bootmem_add_range() on each on a bunch of adjacent 16-byte
	 * blocks. */

	for (; !is_final_block(block); advance_block(&block)) {
		if (seq_start == NULL)
			seq_start = block;

		if (is_data_block(block)) {
			/* Reserve capsule data. */
			bootmem_add_range(block->Union.DataBlock,
					  block->Length,
					  BM_MEM_RAMSTAGE);
		} else {
			/* This isn't the final or a data block, so it must be
			 * the last block of a continuous sequence.  Reserve
			 * the whole sequence. */
			bootmem_add_range((fake_ptr_t)seq_start,
					  (block - seq_start + 1)*sizeof(*block),
					  BM_MEM_RAMSTAGE);

			/* Will be set on the next iteration if there will be
			 * one. */
			seq_start = NULL;
		}
	}

	/* If continuations never show up in a row as checked by
	 * check_capsule_block(), seq_start must be non-NULL here. */
	bootmem_add_range((fake_ptr_t)seq_start,
			  (block - seq_start + 1)*sizeof(*block),
			  BM_MEM_RAMSTAGE);
}

/* Puts capsules into continuous physical memory. */
static void coalesce_capsules(EFI_CAPSULE_BLOCK_DESCRIPTOR *block_chain, uint8_t *target)
{
	EFI_CAPSULE_BLOCK_DESCRIPTOR *block = block_chain;
	uint8_t *capsule_start = NULL;
	uint32_t size_left = 0;

	/* No safety checks in this function, as all of them were done earlier. */

	for (; !is_final_block(block); advance_block(&block)) {
		void *data = (void *)(fake_ptr_t)block->Union.DataBlock;
		uint32_t len = block->Length;

		/* Advance over a continuation. */
		if (!is_data_block(block))
			continue;

		/* This must be the first block of a capsule. */
		if (size_left == 0) {
			const EFI_CAPSULE_HEADER *capsule_header = data;
			capsule_start = data;
			size_left = capsule_header->CapsuleImageSize;
		}

		memcpy(target, data, len);
		size_left -= len;

		/* This must be the last block of a capsule, record it. */
		if (size_left == 0) {
			/* If we can just ignore corrupted capsules, then we
			 * can simply drop those which don't fit. */
			if (uefi_capsule_count == MAX_CAPSULES) {
				printk(BIOS_WARNING,
				       "dasharo: ignoring all capsules after #%d.\n",
				       MAX_CAPSULES);
				break;
			}

			uefi_capsules[uefi_capsule_count].base = capsule_start;
			uefi_capsules[uefi_capsule_count].len = len;
			uefi_capsule_count++;

			/* This is to align start of the next capsule (assumes
			 * that initial value of target was suitably aligned). */
			len = ALIGN_UP(len, 8);
		}

		/* This must be done after possibly aligning the length. */
		target += len;
	}
}

void dasharo_parse_capsules(void)
{
	/* EDK2 starts with 20 items and then grows the list, but it's unlikely
	 * to be necessary in practice. */
	enum { MAX_CAPSULE_BLOCKS = MAX_CAPSULES };

	/* Blocks are collected here when traversing CapsuleUpdateData*
	 * variables, duplicates are skipped. */
	EFI_CAPSULE_BLOCK_DESCRIPTOR *blocks[MAX_CAPSULE_BLOCKS];

	struct region_device rdev;
	if (!CONFIG(SMMSTORE_V2) || smmstore_lookup_region(&rdev)) {
		printk(BIOS_INFO, "dasharo: no SMMSTORE region, no update capsules.\n");
		return;
	}

	int i;
	int block_count = 0;
	for (i = 0; i < MAX_CAPSULE_BLOCKS; ++i) {
		char var_name[32];
		if (i == 0)
			strcpy(var_name, "CapsuleUpdateData");
		else
			snprintf(var_name, sizeof(var_name), "CapsuleUpdateData%d", i);

		EFI_CAPSULE_BLOCK_DESCRIPTOR *block;
		uint32_t size = sizeof(block);
		enum cb_err ret = efi_fv_get_option(&rdev,
						    &global_variables_guid,
						    var_name, &block, &size);
		if (ret != CB_SUCCESS) {
			/* No more variables. */
			break;
		}
		if (size != sizeof(block)) {
			printk(BIOS_ERR,
			       "dasharo: unexpected capsule data size (%d).\n",
			       (int)size);
			return;
		}

		/*
		 * EDK2 checks for duplicates probably because we'll get into
		 * trouble with chaining if there are any, so do the check.
		 */
		int j;
		for (j = 0; j < block_count; ++j) {
			if (blocks[j] == block)
				break;
		}
		if (j < block_count) {
			printk(BIOS_INFO, "dasharo: skipping duplicated %s.\n",
			       var_name);
			continue;
		}

		printk(BIOS_INFO, "dasharo: capsule block #%d at %p.\n", block_count, block);
		blocks[block_count++] = block;

#if DEBUG_STUFF
		// this must be removed because it accesses blocks without sanity checks 
		for (; !is_final_block(block); advance_block(&block)) {
			if (is_data_block(block)) {
				printk(BIOS_SPEW,
				       "dasharo: capsule data @ %#16llx (%#16llx).\n",
				       block->Union.DataBlock, block->Length);
			}
		}
#endif
	}

	if (i == 0) {
		printk(BIOS_INFO, "dasharo: no UEFI capsules were discovered.\n");
		return;
	}

	/* Broken capsules are ignored, ignore those which didn't fit as well. */
	if (block_count == MAX_CAPSULE_BLOCKS) {
		printk(BIOS_WARNING,
		       "dasharo: hit limit on capsule blocks, some might be ignored.\n");
	}

	/* Chaining is done to not pass around and update an array of pointers. */
	uint64_t total_data_size;
	EFI_CAPSULE_BLOCK_DESCRIPTOR *block_chain =
		verify_and_chain_blocks(blocks, i, &total_data_size);
	if (block_chain == NULL) {
		printk(BIOS_ERR, "dasharo: no valid capsules to process.\n");
		return;
	}

	/* Mark all blocks and the data they point to as BM_MEM_RAMSTAGE so
	 * that there is no need to check for overlaps when looking for a
	 * buffer. */
	reserve_capsules(block_chain);

	/* Keeping it simple and allocating a single buffer.  However, there is
	 * no requirement to put all the capsules together, only that each of
	 * them is continuous in memory.  So if this is bad for some reason,
	 * can allocate a separate block for each. */
	struct capsule_buf capsule_buf = { .size = total_data_size };
	if (!bootmem_walk(pick_capsule_buffer, &capsule_buf)) {
		printk(BIOS_ERR,
		       "dasharo: failed to find a buffer for coalesced UEFI capsules.\n");
		return;
	}

	bootmem_add_range(capsule_buf.start, capsule_buf.size, BM_MEM_RESERVED);
	coalesce_capsules(block_chain, (void *)(uintptr_t)capsule_buf.start);
}

void lb_uefi_capsules(struct lb_header *header)
{
	int i;
	for (i = 0; i < uefi_capsule_count; ++i) {
		struct lb_range *capsule = (void *)lb_new_record(header);
		capsule->tag = LB_TAG_CAPSULE;
		capsule->size = sizeof(*capsule);
		capsule->range_start = (uintptr_t)uefi_capsules[i].base;
		capsule->range_size = uefi_capsules[i].len;
	}
}

/*
 * The code from this unit is typically executed by clear_memory() which is run
 * after DEV_INIT.  However, clear_memory() might not be compiled in in which
 * case we still want to process capsules.
 *
 * Doing this conditionally because state machine doesn't enforce any
 * particular ordering for callbacks and running before DEV_INIT is too early
 * due to MTTRs not being initialized.
 */
#if !CONFIG(PLATFORM_HAS_DRAM_CLEAR)

static void parse_capsules(void *unused)
{
	if (!acpi_is_wakeup_s3())
		dasharo_parse_capsules();
}

BOOT_STATE_INIT_ENTRY(BS_DEV_INIT, BS_ON_EXIT, parse_capsules, NULL);

#endif

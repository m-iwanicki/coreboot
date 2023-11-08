/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vendorcode/intel/edk2/UDK2017/MdePkg/Include/Uefi/UefiBaseType.h"
#include "vendorcode/intel/edk2/UDK2017/MdePkg/Include/Uefi/UefiMultiPhase.h"
#include "vendorcode/intel/edk2/UDK2017/MdePkg/Include/Pi/PiFirmwareVolume.h"
#include "vendorcode/intel/edk2/UDK2017/MdeModulePkg/Include/Guid/VariableFormat.h"

#include "smmstoretool.h"

#define PREFIX "EFIVARS: "

static const EFI_GUID EfiVariableGuid = {
	0xddcf3616, 0x3275, 0x4164, { 0x98, 0xb6, 0xfe, 0x85, 0x70, 0x7f, 0xfe, 0x7d } };
static const EFI_GUID EfiAuthenticatedVariableGuid = {
	0xaaf32c78, 0x947b, 0x439a, { 0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77, 0x92 } };
static const EFI_GUID EfiSystemNvDataFvGuid = {
	0xfff12b8d, 0x7696, 0x4c8b, { 0xa9, 0x85, 0x27, 0x47, 0x07, 0x5b, 0x4f, 0x50 } };

#define printk(level, ...)	printf(__VA_ARGS__)

/**
 * coreboot error codes
 *
 * Common error definitions that can be used for any function. All error values
 * should be negative -- when useful, positive values can also be used to denote
 * success. Allocate a new group or errors every 100 values.
 */
enum cb_err {
	CB_SUCCESS = 0,			/**< Call completed successfully */
	CB_ERR = -1,			/**< Generic error code */
	CB_ERR_ARG = -2,		/**< Invalid argument */
	CB_ERR_NOT_IMPLEMENTED = -3,	/**< Function not implemented */

	/* NVRAM/CMOS errors */
	CB_CMOS_OTABLE_DISABLED = -100,		/**< Option table disabled */
	CB_CMOS_LAYOUT_NOT_FOUND = -101,	/**< Layout file not found */
	CB_CMOS_OPTION_NOT_FOUND = -102,	/**< Option string not found */
	CB_CMOS_ACCESS_ERROR = -103,		/**< CMOS access error */
	CB_CMOS_CHECKSUM_INVALID = -104,	/**< CMOS checksum is invalid */

	/* Keyboard test failures */
	CB_KBD_CONTROLLER_FAILURE = -200,
	CB_KBD_INTERFACE_FAILURE = -201,

	/* I2C controller failures */
	CB_I2C_NO_DEVICE	= -300,	/**< Device is not responding */
	CB_I2C_BUSY		= -301,	/**< Device tells it's busy */
	CB_I2C_PROTOCOL_ERROR	= -302,	/**< Data lost or spurious slave
					     device response, try again? */
	CB_I2C_TIMEOUT		= -303, /**< Transmission timed out */

	/* CBFS errors */
	CB_CBFS_IO		= -400, /**< Underlying I/O error */
	CB_CBFS_NOT_FOUND	= -401, /**< File not found in directory */
	CB_CBFS_HASH_MISMATCH	= -402, /**< Master hash validation failed */
	CB_CBFS_CACHE_FULL	= -403, /**< Metadata cache overflowed */

	/* EFI errors */
	CB_EFI_FVH_INVALID		= -500, /**< UEFI FVH (Firmware Volume Header) is corrupted */
	CB_EFI_CHECKSUM_INVALID		= -501, /**< UEFI FVH checksum is invalid */
	CB_EFI_VS_NOT_FORMATTED_INVALID	= -502, /**< UEFI variable store not formatted */
	CB_EFI_VS_CORRUPTED_INVALID	= -503, /**< UEFI variable store is corrupted */
	CB_EFI_ACCESS_ERROR		= -504, /**< UEFI variable store access error */
	CB_EFI_STORE_FULL		= -505, /**< UEFI variable store is full */
	CB_EFI_OPTION_NOT_FOUND		= -506, /**< UEFI variable not found */
	CB_EFI_BUFFER_TOO_SMALL		= -507, /**< UEFI Buffer is too small. */
};

static void print_guid(int log_level, const EFI_GUID *g)
{
	printk(log_level, "GUID: %08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x",
		g->Data1, g->Data2, g->Data3, g->Data4[0], g->Data4[1], g->Data4[2],
		g->Data4[3], g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);

}

static bool compare_guid(const EFI_GUID *a, const EFI_GUID *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

/* Reads the CHAR16 string from rdev at offset and prints it */
static enum cb_err rdev_print_wchar(int log_level, int rdev, ssize_t offset)
{
	CHAR16 c;
	int i = 0;

	/* Convert ASCII to UTF-16 */
	do {
		if (pread(rdev, &c, offset + i * sizeof(c), sizeof(c)) != sizeof(c))
			return CB_EFI_ACCESS_ERROR;
		if (c < 0x80)
			printk(log_level, "%c", (char)c);
		else
			printk(log_level, "\\u%04x", c);

		i++;
	} while (c);
	return CB_SUCCESS;
}

/* Convert an ASCII string to UTF-16 and write it to the rdev starting at offset. */
static enum cb_err rdev_write_wchar(int rdev, ssize_t offset, const char *msg)
{
	size_t i;
	CHAR16 c;

	/* Convert ASCII to UTF-16 */
	for (i = 0; i < strlen(msg) + 1; i++) {
		c = msg[i];

		if (pwrite(rdev, &c, offset + i * sizeof(c), sizeof(c)) != sizeof(c))
			return CB_EFI_ACCESS_ERROR;
	}
	return CB_SUCCESS;
}

/* Read an UTF-16 string from rdev at offset and compare it to ASCII string */
static int rdev_strcmp_wchar_ascii(int rdev, ssize_t offset, const char *msg)
{
	ssize_t i;
	CHAR16 c;
	int r;

	i = 0;
	/* Compare UTF-16 and ASCII */
	while (1) {
		if (pread(rdev, &c, offset + i * sizeof(c), sizeof(c)) != sizeof(c))
			return CB_EFI_ACCESS_ERROR;
		if ((r = (c - msg[i])) != 0 || !c)
			break;

		i++;
	}
	return r;
}

/* Compare an rdev region and a data buffer */
static int rdev_memcmp(int rdev, ssize_t offset, uint8_t *data, ssize_t size)
{
	uint8_t buf[16];
	size_t i;
	int r;

	i = 0;
	while (size >= sizeof(buf)) {
		if (pread(rdev, buf, offset + i, sizeof(buf)) != sizeof(buf))
			return CB_EFI_ACCESS_ERROR;
		r = memcmp(buf, data + i, sizeof(buf));
		if (r != 0)
			return r;
		i += sizeof(buf);
		size -= sizeof(buf);
	}
	while (size > 0) {
		if (pread(rdev, buf, offset + i, 1) != 1)
			return CB_EFI_ACCESS_ERROR;
		r = buf[0] - data[i];
		if (r != 0)
			return r;
		i++;
		size--;
	}
	return 0;
}


static enum cb_err validate_fv_header(const int rdev,
				      EFI_FIRMWARE_VOLUME_HEADER *fw_vol_hdr)
{
	uint16_t checksum, data;
	ssize_t i;

	if (pread(rdev, fw_vol_hdr, 0, sizeof(*fw_vol_hdr)) != sizeof(*fw_vol_hdr))
		return CB_EFI_ACCESS_ERROR;

	/*
	 * Verify the header revision, header signature, length
	 * Length of FvBlock cannot be 2**64-1
	 * HeaderLength cannot be an odd number
	 */
	if ((fw_vol_hdr->Revision != EFI_FVH_REVISION)
	    || (fw_vol_hdr->Signature != EFI_FVH_SIGNATURE)
	    || (fw_vol_hdr->FvLength > region_device_sz(rdev))
	    || (fw_vol_hdr->HeaderLength > region_device_sz(rdev))
	    || (fw_vol_hdr->HeaderLength & 1)) {
		printk(0, PREFIX "No Firmware Volume header present\n");
		return CB_EFI_FVH_INVALID;
	}

	/* Check the Firmware Volume Guid */
	if (!compare_guid(&fw_vol_hdr->FileSystemGuid, &EfiSystemNvDataFvGuid)) {
		printk(0, PREFIX "Firmware Volume Guid non-compatible\n");
		return CB_EFI_FVH_INVALID;
	}

	/* Verify the header checksum */
	checksum = 0;
	for (i = 0; i < fw_vol_hdr->HeaderLength; i += 2) {
		if (pread(rdev, &data, i, sizeof(data)) != sizeof(data))
			return CB_EFI_ACCESS_ERROR;
		checksum = (uint16_t)(checksum + data); /* intentionally overflows */
	}
	if (checksum != 0) {
		printk(0, PREFIX "FV checksum is invalid: 0x%X\n", checksum);
		return CB_EFI_CHECKSUM_INVALID;
	}

	printk(0, PREFIX "UEFI FV with size %lld found\n", fw_vol_hdr->FvLength);

	return CB_SUCCESS;

}

static enum cb_err
validate_variable_store_header(const EFI_FIRMWARE_VOLUME_HEADER  *fv_hdr,
			       int rdev,
			       bool *auth_format)
{
	VARIABLE_STORE_HEADER hdr;
	ssize_t length;

	if (pread(rdev, &hdr, fv_hdr->HeaderLength, sizeof(hdr)) != sizeof(hdr))
		return CB_EFI_ACCESS_ERROR;

	/* Check the Variable Store Guid */
	if (!compare_guid(&hdr.Signature, &EfiVariableGuid) &&
	    !compare_guid(&hdr.Signature, &EfiAuthenticatedVariableGuid)) {
		printk(0, PREFIX "Variable Store Guid non-compatible\n");
		return CB_EFI_VS_CORRUPTED_INVALID;
	}

	*auth_format = compare_guid(&hdr.Signature, &EfiAuthenticatedVariableGuid);

	length = region_device_sz(rdev) - fv_hdr->HeaderLength;
	if (hdr.Size > length) {
		printk(0, PREFIX "Variable Store Length does not match\n");
		return CB_EFI_VS_CORRUPTED_INVALID;
	}

	if (hdr.Format != VARIABLE_STORE_FORMATTED)
		return CB_EFI_VS_NOT_FORMATTED_INVALID;

	if (hdr.State != VARIABLE_STORE_HEALTHY)
		return CB_EFI_VS_CORRUPTED_INVALID;

	if (rdev_chain(rdev, rdev, fv_hdr->HeaderLength + sizeof(hdr), hdr.Size)) {
		printk(0, PREFIX "rdev_chain failed\n");
		return CB_EFI_ACCESS_ERROR;
	}

	printk(0, PREFIX "UEFI variable store with size %zu found\n",
		region_device_sz(rdev));

	return CB_SUCCESS;
}

struct efi_find_args {
	const EFI_GUID *guid;
	const char *name;
	uint32_t *size;
	void *data;
};

static bool match(int rdev, VARIABLE_HEADER *hdr, ssize_t hdr_size,
		  const char *name, const EFI_GUID *guid)
{
	/* Only search for valid or in transition to be deleted variables */
	if ((hdr->State != VAR_ADDED) &&
	    (hdr->State != (VAR_IN_DELETED_TRANSITION & VAR_ADDED)))
		return false;

	if ((!compare_guid(&hdr->VendorGuid, guid)) ||
	    !hdr->NameSize ||
	    !hdr->DataSize)
		return false;

	if (rdev_strcmp_wchar_ascii(rdev, hdr_size, name) != 0)
		return false;

	return true;
}

static
enum cb_err find_and_copy(int rdev, VARIABLE_HEADER *hdr, ssize_t hdr_size,
			  void *arg, bool *stop)
{
	struct efi_find_args *fa = (struct efi_find_args *)arg;

	if (!match(rdev, hdr, hdr_size, fa->name, fa->guid))
		return CB_SUCCESS;

	*stop = true;
	if (*(fa->size) < hdr->DataSize)
		return CB_EFI_BUFFER_TOO_SMALL;

	if (pread(rdev, fa->data, hdr_size + hdr->NameSize, hdr->DataSize) !=
			hdr->DataSize)
		return CB_EFI_ACCESS_ERROR;

	*(fa->size) = hdr->DataSize;
	return CB_SUCCESS;
}

struct efi_find_compare_args {
	const EFI_GUID *guid;
	const char *name;
	uint32_t size;
	void *data;
	bool match;
};

static
enum cb_err find_and_compare(int rdev, VARIABLE_HEADER *hdr, ssize_t hdr_size,
			     void *arg, bool *stop)
{
	struct efi_find_compare_args *fa = (struct efi_find_compare_args *)arg;

	if (!match(rdev, hdr, hdr_size, fa->name, fa->guid))
		return CB_SUCCESS;

	*stop = true;
	if (fa->size != hdr->DataSize) {
		fa->match = false;
		return CB_SUCCESS;
	}

	fa->match = rdev_memcmp(rdev, hdr_size + hdr->NameSize, fa->data, hdr->DataSize) == 0;

	return CB_SUCCESS;
}

static enum cb_err noop(int rdev, VARIABLE_HEADER *hdr, ssize_t hdr_size,
			void *arg, bool *stop)
{
	/* Does nothing. */
	return CB_SUCCESS;
}

static enum cb_err print_var(int rdev, VARIABLE_HEADER *hdr, ssize_t hdr_size,
			     void *arg, bool *stop)
{
	uint8_t buf[16];
	ssize_t len, i;

	printk(0, "%08zx: Var ", region_device_offset(rdev));
	print_guid(0, &hdr->VendorGuid);

	printk(0, "-");

	rdev_print_wchar(0, rdev, hdr_size);

	printk(0, ", State %02x, Size %02x\n", hdr->State, hdr->DataSize);

	if (hdr->DataSize && hdr->NameSize) {
		len = sizeof(buf) < hdr->DataSize ? sizeof(buf) : hdr->DataSize;
		if (pread(rdev, buf, hdr_size + hdr->NameSize, len) != len)
			return CB_EFI_ACCESS_ERROR;
		printk(0, "  Data: ");

		for (i = 0; i < len; i++)
			printk(0, "0x%02x ", buf[i]);

		if (hdr->DataSize > len)
			printk(0, "...");

		printk(0, "\n");
	}

	return CB_SUCCESS;
}

static enum cb_err walk_variables(int rdev,
				  bool auth_format,
				  enum cb_err (*walker)(int rdev,
						   VARIABLE_HEADER *hdr,
						   ssize_t hdr_size,
						   void *arg,
						   bool *stop),
				  void *walker_arg)
{
	AUTHENTICATED_VARIABLE_HEADER auth_hdr;
	ssize_t header_size, var_size;
	VARIABLE_HEADER hdr;
	bool stop;
	enum cb_err ret;

	if (auth_format)
		header_size = sizeof(AUTHENTICATED_VARIABLE_HEADER);
	else
		header_size = sizeof(VARIABLE_HEADER);

	do {
		if (auth_format) {
			if (pread(rdev, &auth_hdr, 0, sizeof(auth_hdr))
					!= sizeof(auth_hdr))
				return CB_EFI_ACCESS_ERROR;
			hdr.Reserved = auth_hdr.Reserved;
			hdr.StartId = auth_hdr.StartId;
			hdr.State = auth_hdr.State;
			hdr.Attributes = auth_hdr.Attributes;
			hdr.NameSize = auth_hdr.NameSize;
			hdr.DataSize = auth_hdr.DataSize;
			memcpy(&hdr.VendorGuid, &auth_hdr.VendorGuid, sizeof(hdr.VendorGuid));
		} else if (pread(rdev, &hdr, 0, sizeof(hdr)) != sizeof(hdr)) {
			return CB_EFI_ACCESS_ERROR;
		}
		if (hdr.StartId != VARIABLE_DATA)
			break;

		if (hdr.State == UINT8_MAX ||
		    hdr.DataSize == UINT32_MAX ||
		    hdr.NameSize == UINT32_MAX ||
		    hdr.Attributes == UINT32_MAX) {
			hdr.NameSize = 0;
			hdr.DataSize = 0;
		}

		printk(0, "Found variable with state %02x and ", hdr.State);
		print_guid(0, &hdr.VendorGuid);
		printk(0, "\n");

		stop = false;

		ret = walker(rdev, &hdr, header_size, walker_arg, &stop);

		if (ret != CB_SUCCESS || stop)
			return ret;

		var_size = ALIGN_UP(header_size + hdr.NameSize + hdr.DataSize,
				    HEADER_ALIGNMENT);
	} while (!rdev_chain(rdev, rdev, var_size, region_device_sz(rdev) - var_size));

	return CB_EFI_OPTION_NOT_FOUND;
}

static enum cb_err efi_fv_init(int rdev, bool *auth_format)
{
	EFI_FIRMWARE_VOLUME_HEADER fv_hdr;
	enum cb_err ret;

	ret = validate_fv_header(rdev, &fv_hdr);
	if (ret != CB_SUCCESS) {
		printk(0, PREFIX "Failed to validate firmware header\n");

		return ret;
	}
	ret = validate_variable_store_header(&fv_hdr, rdev, auth_format);
	if (ret != CB_SUCCESS)
		printk(0, PREFIX "Failed to validate variable store header\n");

	return ret;
}

enum cb_err efi_fv_print_options(int rdev)
{
	enum cb_err ret;
	bool auth_format;

	ret = efi_fv_init(rdev, &auth_format);
	if (ret != CB_SUCCESS)
		return ret;

	return walk_variables(rdev, auth_format, print_var, NULL);
}

/*
 * efi_fv_get_option
 * - writes up to *size bytes into a buffer pointed to by *dest
 * - rdev is the spi flash region to operate on
 * - the FVH and variable store header must have been initialized by a third party
 */
enum cb_err efi_fv_get_option(int rdev,
			      const EFI_GUID *guid,
			      const char *name,
			      void *dest,
			      uint32_t *size)
{
	struct efi_find_args args;
	bool auth_format;
	enum cb_err ret;

	ret = efi_fv_init(rdev, &auth_format);
	if (ret != CB_SUCCESS)
		return ret;

	args.guid = guid;
	args.name = name;
	args.size = size;
	args.data = dest;

	return walk_variables(rdev, auth_format, find_and_copy, &args);
}

static enum cb_err write_auth_hdr(int rdev, const EFI_GUID *guid,
				  const char *name, void *data, ssize_t size)
{
	AUTHENTICATED_VARIABLE_HEADER auth_hdr;
	ssize_t name_size, var_size;
	enum cb_err ret;

	name_size = (strlen(name) + 1) * sizeof(CHAR16);
	var_size = name_size + size + sizeof(auth_hdr);

	if (var_size > region_device_sz(rdev))
		return CB_EFI_STORE_FULL;

	/* Sanity check. flash must be blank */
	if (pread(rdev, &auth_hdr, 0, sizeof(auth_hdr)) != sizeof(auth_hdr))
		return CB_EFI_ACCESS_ERROR;

	if (auth_hdr.StartId != UINT16_MAX ||
	    auth_hdr.State != UINT8_MAX ||
	    auth_hdr.DataSize != UINT32_MAX ||
	    auth_hdr.NameSize != UINT32_MAX ||
	    auth_hdr.Attributes != UINT32_MAX) {
		return CB_EFI_ACCESS_ERROR;
	}

	memset(&auth_hdr, 0xff, sizeof(auth_hdr));

	auth_hdr.StartId = VARIABLE_DATA;
	auth_hdr.Attributes = EFI_VARIABLE_NON_VOLATILE|
			      EFI_VARIABLE_BOOTSERVICE_ACCESS|
			      EFI_VARIABLE_RUNTIME_ACCESS;
	auth_hdr.NameSize = name_size;
	auth_hdr.DataSize = size;
	memcpy(&auth_hdr.VendorGuid, guid, sizeof(EFI_GUID));

	/* Write header with no State */
	if (pwrite(rdev, &auth_hdr, 0, sizeof(auth_hdr)) != sizeof(auth_hdr))
		return CB_EFI_ACCESS_ERROR;

	/* Set header State to valid header */
	auth_hdr.State = VAR_HEADER_VALID_ONLY;
	if (pwrite(rdev, &auth_hdr.State, offsetof(AUTHENTICATED_VARIABLE_HEADER, State),
			 sizeof(auth_hdr.State)) != sizeof(auth_hdr.State))
		return CB_EFI_ACCESS_ERROR;

	/* Write the name */
	ret = rdev_write_wchar(rdev, sizeof(auth_hdr), name);
	if (ret != CB_SUCCESS)
		return ret;

	/* Write the data */
	if (pwrite(rdev, data, sizeof(auth_hdr) + name_size, size) != size)
		return CB_EFI_ACCESS_ERROR;

	/* Set header State to valid data */
	auth_hdr.State = VAR_ADDED;
	if (pwrite(rdev, &auth_hdr.State, offsetof(AUTHENTICATED_VARIABLE_HEADER, State),
				sizeof(auth_hdr.State)) != sizeof(auth_hdr.State))
		return CB_EFI_ACCESS_ERROR;

	return CB_SUCCESS;
}

static enum cb_err write_hdr(int rdev, const EFI_GUID *guid,
			     const char *name,
			     void *data,
			     ssize_t size)
{
	VARIABLE_HEADER hdr;
	ssize_t name_size, var_size;
	enum cb_err ret;

	name_size = (strlen(name) + 1) * sizeof(CHAR16);
	var_size = name_size + size + sizeof(hdr);
	if (var_size > region_device_sz(rdev))
		return CB_EFI_STORE_FULL;

	/* Sanity check. flash must be blank */
	if (pread(rdev, &hdr, 0, sizeof(hdr)) != sizeof(hdr))
		return CB_EFI_ACCESS_ERROR;

	if (hdr.StartId != UINT16_MAX ||
	    hdr.State != UINT8_MAX ||
	    hdr.DataSize != UINT32_MAX ||
	    hdr.NameSize != UINT32_MAX ||
	    hdr.Attributes != UINT32_MAX) {
		return CB_EFI_ACCESS_ERROR;
	}

	memset(&hdr, 0xff, sizeof(hdr));

	hdr.StartId = VARIABLE_DATA;
	hdr.Attributes = EFI_VARIABLE_NON_VOLATILE|
			 EFI_VARIABLE_BOOTSERVICE_ACCESS|
			 EFI_VARIABLE_RUNTIME_ACCESS;
	hdr.NameSize = name_size;
	hdr.DataSize = size;
	memcpy(&hdr.VendorGuid, guid, sizeof(EFI_GUID));

	/* Write header with no State */
	if (pwrite(rdev, &hdr, 0, sizeof(hdr)) != sizeof(hdr))
		return CB_EFI_ACCESS_ERROR;

	/* Set header State to valid header */
	hdr.State = VAR_HEADER_VALID_ONLY;
	if (pwrite(rdev, &hdr.State, offsetof(VARIABLE_HEADER, State),
			 sizeof(hdr.State)) != sizeof(hdr.State))
		return CB_EFI_ACCESS_ERROR;

	/* Write the name */
	ret = rdev_write_wchar(rdev, sizeof(hdr), name);
	if (ret != CB_SUCCESS)
		return ret;

	/* Write the data */
	if (pwrite(rdev, data, sizeof(hdr) + name_size, size) != size)
		return CB_EFI_ACCESS_ERROR;

	/* Set header State to valid data */
	hdr.State = VAR_ADDED;
	if (pwrite(rdev, &hdr.State, offsetof(VARIABLE_HEADER, State),
				sizeof(hdr.State)) != sizeof(hdr.State))
		return CB_EFI_ACCESS_ERROR;

	return CB_SUCCESS;
}

/*
 * efi_fv_set_option
 * - writes size bytes read from the buffer pointed to by *data
 * - rdev is the spi flash region to operate on
 * - the FVH and variable store header must have been initialized by a third party
 */
enum cb_err efi_fv_set_option(int rdev,
			      const EFI_GUID *guid,
			      const char *name,
			      void *data,
			      uint32_t size)
{
	struct efi_find_compare_args args;
	bool found_existing;
	VARIABLE_HEADER hdr;
	bool auth_format;
	enum cb_err ret;

	ret = efi_fv_init(rdev, &auth_format);
	if (ret != CB_SUCCESS)
		return ret;

	/* Find existing variable */
	args.guid = guid;
	args.name = name;
	args.size = size;
	args.match = false;
	args.data = data;

	ret = walk_variables(rdev, auth_format, find_and_compare, &args);
	found_existing = ret == CB_SUCCESS;

	if (found_existing) {
		printk(0, "found existing variable %s, match =%d\n", name, args.match);

		if (args.match)
			return CB_SUCCESS;


		/* Mark as to be deleted */
		hdr.State = VAR_IN_DELETED_TRANSITION;
		if (pwrite(rdev, &hdr.State, offsetof(VARIABLE_HEADER, State),
			sizeof(hdr.State)) != sizeof(hdr.State))
			return CB_EFI_ACCESS_ERROR;
	}

	/* Walk to end of variable store */
	ret = walk_variables(rdev, auth_format, noop, NULL);
	if (ret != CB_EFI_OPTION_NOT_FOUND)
		return ret;

	/* Now append new variable:
	 * 1. Write the header without State field.
	 * 2. Write the State field and set it to HEADER_VALID.
	 * 3. Write data
	 * 4. Write the State field and set it to VAR_ADDED
	 */

	if (auth_format)
		ret = write_auth_hdr(rdev, guid, name, data, size);
	else
		ret = write_hdr(rdev, guid, name, data, size);
	if (ret != CB_SUCCESS)
		return ret;

	if (found_existing) {
		/* Mark old variable as deleted */
		hdr.State = VAR_DELETED;
		if (pwrite(rdev, &hdr.State, offsetof(VARIABLE_HEADER, State),
			sizeof(hdr.State)) != sizeof(hdr.State))
			return CB_EFI_ACCESS_ERROR;
	}

	return CB_SUCCESS;
}

/* SPDX-License-Identifier: GPL-2.0-only */

#include <console/console.h>
#include <dasharo/options.h>
#include <drivers/efi/efivars.h>
#include <intelblocks/cse.h>
#include <option.h>
#include <soc/intel/common/reset.h>
#include <smmstore.h>
#include <types.h>
#include <uuid.h>

static const EFI_GUID dasharo_system_features_guid = {
	0xd15b327e, 0xff2d, 0x4fc1, { 0xab, 0xf6, 0xc1, 0x2b, 0xd0, 0x8c, 0x13, 0x59 }
};

/* Value of *var is not changed on failure, so it's safe to initialize it with
 * a default before the call. */
static enum cb_err read_u8_var(const char *var_name, uint8_t *var)
{
	struct region_device rdev;

	if (!smmstore_lookup_region(&rdev)) {
		uint8_t tmp;
		uint32_t size = sizeof(tmp);
		enum cb_err ret = efi_fv_get_option(&rdev, &dasharo_system_features_guid,
						    var_name, &tmp, &size);
		if (ret == CB_SUCCESS) {
			if (size == sizeof(tmp)) {
				*var = tmp;
				return CB_SUCCESS;
			}

			printk(BIOS_WARNING,
			       "dasharo: EFI variable \"%s\" of wrong size (%d instead of 1)\n",
			       var_name, size);
		}
	}

	return CB_ERR;
}

/* Value of *var is not changed on failure, so it's safe to initialize it with
 * a default before the call. */
static enum cb_err read_bool_var(const char *var_name, bool *var)
{
	uint8_t tmp;

	if (read_u8_var(var_name, &tmp) == CB_SUCCESS) {
		*var = tmp != 0;
		return CB_SUCCESS;
	}

	return CB_ERR;
}

enum cb_err dasharo_reset_options(void)
{
	struct region_device rdev;
	ssize_t res;

	if (smmstore_lookup_region(&rdev))
		return CB_ERR;

	res = rdev_eraseat(&rdev, 0, region_device_sz(&rdev));
	if (res != region_device_sz(&rdev))
		return CB_ERR;

	return CB_SUCCESS;
}

uint8_t dasharo_get_power_on_after_fail(void)
{
	uint8_t power_status;

	power_status = get_uint_option("power_on_after_fail",
				       CONFIG_MAINBOARD_POWER_FAILURE_STATE);

	/* When present, EFI variable has higher priority. */
	if (CONFIG(DRIVERS_EFI_VARIABLE_STORE))
		read_u8_var("PowerFailureState", &power_status);

	return power_status;
}

bool dasharo_resizeable_bars_enabled(void)
{
	static bool enabled = false;
	static bool read_once = false;

	if (CONFIG(DRIVERS_EFI_VARIABLE_STORE) &&
	    CONFIG(PCIEXP_SUPPORT_RESIZABLE_BARS) &&
	    !read_once) {
		read_bool_var("PCIeResizeableBarsEnabled", &enabled);
		/*
		 * This variable would be read for each PCIe device.
		 * Avoid it by reading the variable only once.
		 */
		read_once = true;
	}

	return enabled;
}

bool is_vboot_locking_permitted(void)
{
	bool lock = true;
	bool fum = false;

	if (CONFIG(DRIVERS_EFI_VARIABLE_STORE))
		read_bool_var("FirmwareUpdateMode", &fum);

	/* Disable lock if in Firmware Update Mode */
	if (fum)
		return false;

	if (CONFIG(DRIVERS_EFI_VARIABLE_STORE))
		read_bool_var("LockBios", &lock);

	return lock;
}

bool dma_protection_enabled(void)
{
	struct region_device rdev;
	enum cb_err ret = CB_EFI_OPTION_NOT_FOUND;
	struct iommu_config {
		bool iommu_enable;
		bool iommu_handoff;
	} __packed iommu_var;
	uint32_t size;

	if (smmstore_lookup_region(&rdev))
		return false;

	size = sizeof(iommu_var);
	if (CONFIG(DRIVERS_EFI_VARIABLE_STORE))
		ret = efi_fv_get_option(&rdev, &dasharo_system_features_guid, "IommuConfig",
				&iommu_var, &size);

	if (ret != CB_SUCCESS)
		return false;

	return iommu_var.iommu_enable;
}

static void disable_me_hmrfpo(uint8_t *var)
{
	int hmrfpo_sts = cse_hmrfpo_get_status();

	if (hmrfpo_sts == -1) {
		printk (BIOS_DEBUG, "ME HMRFPO Get Status failed\n");
		goto hmrfpo_error;
	}

	printk (BIOS_DEBUG, "ME HMRFPO status: ");
	switch (hmrfpo_sts) {
	case 0: 
		printk (BIOS_DEBUG, "DISABLED\n");
		if (cse_hmrfpo_enable() != CB_SUCCESS)
			goto hmrfpo_error;
		else
			do_global_reset(); /* No return */
		break;
	case 1: 
		printk (BIOS_DEBUG, "LOCKED\n");
		goto hmrfpo_error;
	case 2: 
		printk (BIOS_DEBUG, "ENABLED\n");
		/* Override ME disable method to not switch ME mode */
		*var =  ME_MODE_DISABLE_HMRFPO;
		/* TODO: disable HMRFPO here if not in FUM? Reboot disables HMRFPO. */
		break;
	default:
		printk (BIOS_DEBUG, "UNKNOWN\n");
		goto hmrfpo_error;
	}

	return;

hmrfpo_error:
	/* Try other available methods if something goes wrong */
	*var = CONFIG(HAVE_INTEL_ME_HAP) ? ME_MODE_DISABLE_HAP
					 : ME_MODE_DISABLE_HECI;
}

uint8_t cse_get_me_disable_mode(void)
{
	uint8_t var = CONFIG_INTEL_ME_DEFAULT_STATE;
	bool fum = false;

	if (CONFIG(DRIVERS_EFI_VARIABLE_STORE)) {
		read_bool_var("FirmwareUpdateMode", &fum);
		read_u8_var("MeMode", &var);
	}

	/* Disable ME via HMRPFO if in Firmware Update Mode */
	if (fum) {
		/* Check if already in HMRFPO mode */
		if (cse_is_hfs1_com_secover_mei_msg())
			return ME_MODE_DISABLE_HMRFPO;
		else
			disable_me_hmrfpo(&var);
	}

	return var;
}

bool is_smm_bwp_permitted(void)
{
	bool smm_bwp = false;
	bool fum = false;

	if (CONFIG(DRIVERS_EFI_VARIABLE_STORE))
		read_bool_var("FirmwareUpdateMode", &fum);

	/* Disable SMM BWP if in Firmware Update Mode */
	if (fum)
		return false;

	if (CONFIG(DRIVERS_EFI_VARIABLE_STORE))
		read_bool_var("SmmBwp", &smm_bwp);

	return smm_bwp;
}

void get_watchdog_config(struct watchdog_config *wdt_cfg)
{
	struct region_device rdev;
	enum cb_err ret = CB_EFI_OPTION_NOT_FOUND;
	uint32_t size;

	wdt_cfg->wdt_enable = false;
	wdt_cfg->wdt_timeout = CONFIG_SOC_INTEL_COMMON_OC_WDT_TIMEOUT_SECONDS;

	if (smmstore_lookup_region(&rdev))
		return;

	size = sizeof(*wdt_cfg);
	if (CONFIG(DRIVERS_EFI_VARIABLE_STORE))
		ret = efi_fv_get_option(&rdev, &dasharo_system_features_guid, "WatchdogConfig",
					wdt_cfg, &size);

	if (ret != CB_SUCCESS || size != sizeof(*wdt_cfg)) {
		wdt_cfg->wdt_enable = false;
		wdt_cfg->wdt_timeout = CONFIG_SOC_INTEL_COMMON_OC_WDT_TIMEOUT_SECONDS;
	}
}

bool get_ps2_option(void)
{
	bool ps2_en = true;

	if (CONFIG(DRIVERS_EFI_VARIABLE_STORE))
		read_bool_var("Ps2Controller", &ps2_en);

	return ps2_en;
}

uint8_t get_sleep_type_option(void)
{
	uint8_t sleep_type = CONFIG(DASHARO_PREFER_S3_SLEEP) ? SLEEP_TYPE_OPTION_S3
							     : SLEEP_TYPE_OPTION_S0IX;

	if (CONFIG(DRIVERS_EFI_VARIABLE_STORE))
		read_u8_var("SleepType", &sleep_type);

	return sleep_type;
}


uint8_t get_fan_curve_option(void)
{
	uint8_t fan_curve = FAN_CURVE_OPTION_SILENT;

	if (CONFIG(DRIVERS_EFI_VARIABLE_STORE))
		read_u8_var("FanCurveOption", &fan_curve);

	return fan_curve;
}

bool get_camera_option(void)
{
	bool cam_en = CAMERA_ENABLED_OPTION;

	if (CONFIG(DRIVERS_EFI_VARIABLE_STORE))
		read_bool_var("EnableCamera", &cam_en);

	return cam_en;
}

bool get_wireless_option(void)
{
	bool wireless_en = true;

	if (CONFIG(DRIVERS_EFI_VARIABLE_STORE))
		read_bool_var("EnableWifiBt", &wireless_en);

	return wireless_en;
}

void get_battery_config(struct battery_config *bat_cfg)
{
	struct region_device rdev;
	enum cb_err ret = CB_EFI_OPTION_NOT_FOUND;
	uint32_t size;

	bat_cfg->start_threshold = BATTERY_START_THRESHOLD_DEFAULT;
	bat_cfg->stop_threshold = BATTERY_STOP_THRESHOLD_DEFAULT;

	if (smmstore_lookup_region(&rdev))
		return;

	size = sizeof(*bat_cfg);
	if (CONFIG(DRIVERS_EFI_VARIABLE_STORE))
		ret = efi_fv_get_option(&rdev, &dasharo_system_features_guid, "BatteryConfig",
					bat_cfg, &size);

	if (ret != CB_SUCCESS || size != sizeof(*bat_cfg)) {
		bat_cfg->start_threshold = BATTERY_START_THRESHOLD_DEFAULT;
		bat_cfg->stop_threshold = BATTERY_STOP_THRESHOLD_DEFAULT;
	}
}

#define MAX_SERIAL_LENGTH 0x100

bool get_serial_number_from_efivar(char *serial_number)
{
	struct region_device rdev;
	enum cb_err ret = CB_EFI_OPTION_NOT_FOUND;
	uint32_t size;

	if (smmstore_lookup_region(&rdev))
		return false;

	size = MAX_SERIAL_LENGTH;
	if (CONFIG(DRIVERS_EFI_VARIABLE_STORE))
		ret = efi_fv_get_option(&rdev, &dasharo_system_features_guid, "Type2SN", serial_number, &size);

	if (ret != CB_SUCCESS || size > MAX_SERIAL_LENGTH)
		return false;

	serial_number[size] = '\0';

	return true;
}


bool get_uuid_from_efivar(uint8_t *uuid)
{
	struct region_device rdev;
	enum cb_err ret = CB_EFI_OPTION_NOT_FOUND;
	uint32_t size;

	if (smmstore_lookup_region(&rdev))
		return false;

	size = UUID_LEN;
	ret = efi_fv_get_option(&rdev, &dasharo_system_features_guid, "Type1UUID", uuid, &size);
	if (ret != CB_SUCCESS || size != UUID_LEN)
		return false;

	return true;
}

uint8_t dasharo_get_memory_profile(void)
{
	/* Using default SPD/JEDEC profile by default. */
	uint8_t profile = 0;
	read_u8_var("MemoryProfile", &profile);
	return profile;
}

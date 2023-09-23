/* SPDX-License-Identifier: GPL-2.0-only */

#include <bootblock_common.h>
#include <device/pnp_ops.h>
#include <soc/gpio.h>
#include <superio/nuvoton/common/nuvoton.h>
#include <superio/nuvoton/nct6687d/nct6687d.h>
#include "include/gpio.h"

#define SERIAL_DEV PNP_DEV(0x2e, NCT6687D_SP1)
#define POWER_DEV PNP_DEV(0x2e, NCT6687D_SLEEP_PWR)

static void early_config_gpio(void)
{
	if (CONFIG(INTEL_LPSS_UART_FOR_CONSOLE))
		gpio_configure_pads(uart_gpio_table, ARRAY_SIZE(uart_gpio_table));
}

void bootblock_mainboard_init(void)
{
	early_config_gpio();
}

void bootblock_mainboard_early_init(void)
{
	/* Replicate vendor settings for multi-function pins in global config LDN */
	nuvoton_pnp_enter_conf_state(SERIAL_DEV);
	pnp_write_config(SERIAL_DEV, 0x13, 0x0c);

	/* Below are multi-pin function */
	pnp_write_config(SERIAL_DEV, 0x1d, 0x08);
	pnp_write_config(SERIAL_DEV, 0x1f, 0xf0);
	pnp_write_config(SERIAL_DEV, 0x22, 0xbc);
	pnp_write_config(SERIAL_DEV, 0x23, 0xdf);
	pnp_write_config(SERIAL_DEV, 0x24, 0x81);
	pnp_write_config(SERIAL_DEV, 0x25, 0xff);
	pnp_write_config(SERIAL_DEV, 0x29, 0x6d);
	pnp_write_config(SERIAL_DEV, 0x2a, 0x8f);

	pnp_set_logical_device(POWER_DEV);
	/* Configure pin for PECI */
	pnp_write_config(POWER_DEV, 0xf3, 0x0c);

	nuvoton_pnp_exit_conf_state(POWER_DEV);

	/* Enable serial only if COM1 header is populated */
	if (CONFIG(CONSOLE_SERIAL) && !gpio_get(GPP_A22))
		nuvoton_enable_serial(SERIAL_DEV, CONFIG_TTYS0_BASE);
}

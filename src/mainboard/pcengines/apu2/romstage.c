/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2012 Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdint.h>
#include <string.h>
#include <device/pci_def.h>
#include <arch/io.h>
#include <arch/mmio.h>
#include <device/pci_ops.h>
#include <device/pnp.h>
#include <arch/cpu.h>
#include <cpu/x86/lapic.h>
#include <console/console.h>
#include <northbridge/amd/agesa/state_machine.h>
#include <southbridge/amd/pi/hudson/hudson.h>
#include <superio/nuvoton/common/nuvoton.h>
#include <superio/nuvoton/nct5104d/nct5104d.h>
#include <Fch/Fch.h>
#include <smp/node.h>
#include <superio/nuvoton/common/nuvoton.h>
#include <superio/nuvoton/nct5104d/nct5104d.h>
#include <build.h>

#include "bios_knobs.h"
#include "gpio_ftns.h"

#define SIO_PORT 0x2e
#define SERIAL1_DEV PNP_DEV(SIO_PORT, NCT5104D_SP1)
#define SERIAL2_DEV PNP_DEV(SIO_PORT, NCT5104D_SP2)

static void early_lpc_init(void);
static void print_sign_of_life(void);
extern char coreboot_dmi_date[];
extern char coreboot_version[];

void board_BeforeAgesa(struct sysinfo *cb)
{
	u32 val;
	pci_devfn_t dev;
	u32 data;

	/*
	 *  In Hudson RRG, PMIOxD2[5:4] is "Drive strength control for
	 *  LpcClk[1:0]".  This following register setting has been
	 *  replicated in every reference design since Parmer, so it is
	 *  believed to be required even though it is not documented in
	 *  the SoC BKDGs.  Without this setting, there is no serial
	 *  output.
	 */
	outb(0xd2, 0xcd6);
	outb(0x00, 0xcd7);

	hudson_lpc_port80();

	volatile u8 *CF9_shadow;
	CF9_shadow = (u8 *)(ACPI_MMIO_BASE + PMIO_BASE + FCH_PMIOA_REGC5);
	*CF9_shadow = 0x0;

	post_code(0x30);
	early_lpc_init();

	hudson_clk_output_48Mhz();
	post_code(0x31);

	dev = PCI_DEV(0, 0x14, 3);
	data = pci_read_config32(dev, LPC_IO_OR_MEM_DECODE_ENABLE);
	/* enable 0x2e/0x4e IO decoding before configuring SuperIO */
	pci_write_config32(dev, LPC_IO_OR_MEM_DECODE_ENABLE, data | 3);

	/* COM2 on apu5 is reserved so only COM1 should be supported */
	if ((CONFIG_UART_FOR_CONSOLE == 1) && !CONFIG(BOARD_PCENGINES_APU5))
		nuvoton_enable_serial(SERIAL2_DEV, CONFIG_TTYS0_BASE);
	else if (CONFIG_UART_FOR_CONSOLE == 0)
		nuvoton_enable_serial(SERIAL1_DEV, CONFIG_TTYS0_BASE);

	/* Disable SVI2 controller to wait for command completion */
	val = pci_read_config32(PCI_DEV(0, 0x18, 5), 0x12C);
	if (!(val & (1 << 30))) {
		val |= (1 << 30);
		pci_write_config32(PCI_DEV(0, 0x18, 5), 0x12C, val);
	}

	/* Disable PCI-PCI bridge and release GPIO32/33 for other uses. */
	outb(0xea, 0xcd6);
	outb(0x1, 0xcd7);

	dev = PCI_DEV(0, 0x14, 3);
	data = pci_read_config32(dev, LPC_IO_OR_MEM_DECODE_ENABLE);
	/* enable 0x2e/0x4e IO decoding before configuring SuperIO */
	pci_write_config32(dev, LPC_IO_OR_MEM_DECODE_ENABLE, data | 3);

	if ((check_com2() || (CONFIG_UART_FOR_CONSOLE == 1)) &&
	    !CONFIG(BOARD_PCENGINES_APU5))
		nuvoton_enable_serial(SERIAL2_DEV, 0x2f8);
}

static void early_lpc_init(void)
{
	u32 setting = 0x0;

	/* Configure output disabled, value low, pull up/down disabled */

	if (CONFIG(BOARD_PCENGINES_APU5))
		configure_gpio(IOMUX_GPIO_22, Function0, GPIO_22, setting);

	if (CONFIG(BOARD_PCENGINES_APU2) || CONFIG(BOARD_PCENGINES_APU3) ||
	    CONFIG(BOARD_PCENGINES_APU4))
		configure_gpio(IOMUX_GPIO_32, Function0, GPIO_32, setting);

	configure_gpio(IOMUX_GPIO_49, Function2, GPIO_49, setting);
	configure_gpio(IOMUX_GPIO_50, Function2, GPIO_50, setting);
	configure_gpio(IOMUX_GPIO_71, Function0, GPIO_71, setting);

	/* Configure output enabled, value low, pull up/down disabled */
	setting = GPIO_OUTPUT_ENABLE;
	if (CONFIG(BOARD_PCENGINES_APU3) || CONFIG(BOARD_PCENGINES_APU4))
		configure_gpio(IOMUX_GPIO_33, Function0, GPIO_33, setting);

	configure_gpio(IOMUX_GPIO_57, Function1, GPIO_57, setting);
	configure_gpio(IOMUX_GPIO_58, Function1, GPIO_58, setting);
	configure_gpio(IOMUX_GPIO_59, Function3, GPIO_59, setting);

	/* Configure output enabled, value high, pull up/down disabled */
	setting = GPIO_OUTPUT_ENABLE | GPIO_OUTPUT_VALUE;

	if (CONFIG(BOARD_PCENGINES_APU5)) {
		configure_gpio(IOMUX_GPIO_32, Function0, GPIO_32, setting);
		configure_gpio(IOMUX_GPIO_33, Function0, GPIO_33, setting);
	}

	configure_gpio(IOMUX_GPIO_51, Function2, GPIO_51, setting);
	configure_gpio(IOMUX_GPIO_55, Function3, GPIO_55, setting);

	/* W_DIS# pins are connected directly to the SoC GPIOs without
	 * any external pull-ups. This causes issues with certain mPCIe
	 * modems. Configure pull-ups and output high in order to
	 * prevent disabling WLAN on the modules. APU5 has hardware
	 * pull-ups on the PCB.
	 */
	if (!CONFIG(BOARD_PCENGINES_APU5))
		setting = GPIO_PULL_UP_ENABLE | GPIO_OUTPUT_VALUE;

	configure_gpio(IOMUX_GPIO_64, Function2, GPIO_64, setting);
	configure_gpio(IOMUX_GPIO_68, Function0, GPIO_68, setting);
}

static const char *mainboard_bios_version(void)
{
	if (strlen(CONFIG_LOCALVERSION))
		return CONFIG_LOCALVERSION;
	else
		return coreboot_version;
}

static void print_sign_of_life()
{
	char tmp[9];
	strncpy(tmp,   coreboot_dmi_date+6, 4);
	strncpy(tmp+4, coreboot_dmi_date+3, 2);
	strncpy(tmp+6, coreboot_dmi_date,   2);
	tmp[8] = '\0';
	printk(BIOS_ALERT, CONFIG_MAINBOARD_VENDOR " "
	                   CONFIG_MAINBOARD_PART_NUMBER "\n");
	printk(BIOS_ALERT, "coreboot build %s\n", tmp);
	printk(BIOS_ALERT, "BIOS version %s\n", mainboard_bios_version());
}

void board_BeforeInitReset(struct sysinfo *cb, AMD_RESET_PARAMS *Reset)
{
	u32 val, data;

	if (boot_cpu()) {
		volatile u8 *CF9_shadow;
		CF9_shadow = (u8 *)(ACPI_MMIO_BASE + PMIO_BASE +
				    FCH_PMIOA_REGC5);
		*CF9_shadow = 0x0;

		/* Check if cold boot was requested */
		val = pci_read_config32(PCI_DEV(0, 0x18, 0), 0x6C);
		if (val & (1 << 4)) {
			volatile u32 *ptr;
			printk(BIOS_ALERT, "Forcing cold boot path\n");
			val &= ~(0x630); // ColdRstDet[4], BiosRstDet[10:9, 5]
			pci_write_config32(PCI_DEV(0, 0x18, 0), 0x6C, val);

			ptr = (u32*)FCH_PMIOxC0_S5ResetStatus;
			*ptr = 0x3fff003f;	// Write-1-to-clear

			*CF9_shadow = 0xe;	// FullRst, SysRst, RstCmd
			printk(BIOS_ALERT, "Did not reset (yet)\n");
		}

		data = *(u32*)FCH_PMIOxC0_S5ResetStatus;
		// do not print SOL if reset will take place in FchInit
		if (check_console() &&
		    !(data & FCH_PMIOxC0_S5ResetStatus_All_Status))
			print_sign_of_life();

		if ((check_mpcie2_clk() || CONFIG(FORCE_MPCIE2_CLK)) &&
		     CONFIG(BOARD_PCENGINES_APU2)) {
			// make GFXCLK to ignore CLKREQ# input
			// force it to be always on
			data = read32((const volatile void *)
				(ACPI_MMIO_BASE + MISC_BASE +
				FCH_MISC_REG04));
			data &= 0xFFFFFF0F;
			data |= 0xF << (1 * 4); // CLKREQ GFX to GFXCLK
			write32((volatile void *)
				(ACPI_MMIO_BASE + MISC_BASE + FCH_MISC_REG04),
				data);
			printk(BIOS_DEBUG, "force mPCIe clock enabled\n");
		}

		volatile u32 *ptr = (u32 *)(ACPI_MMIO_BASE + WATCHDOG_BASE);
		u16 watchdog_timeout = get_watchdog_timeout();

		if (watchdog_timeout == 0) {
			//disable watchdog
			printk(BIOS_WARNING, "Watchdog is disabled\n");
			*ptr |= (1 << 3);
		} else {
			// enable
			*ptr &= ~(1 << 3);
			*ptr |= (1 << 0);
			// configure timeout
			*(ptr + 1) = (u16) watchdog_timeout;
			// trigger
			*ptr |= (1 << 7);

			printk(BIOS_WARNING, "Watchdog is enabled, state = 0x%x, time = %d\n", *ptr, *(ptr + 1));
		}
	}
}
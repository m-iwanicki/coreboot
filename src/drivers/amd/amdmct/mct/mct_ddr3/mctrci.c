/* SPDX-License-Identifier: GPL-2.0-only */

#include <arch/cpu.h>
#include <stdint.h>
#include <console/console.h>

#include <drivers/amd/amdmct/wrappers/mcti.h>
#include "mct_d_gcc.h"

static u8 fam15h_rdimm_rc2_ibt_code(struct DCTStatStruc *p_dct_stat, u8 dct)
{
	u8 MaxDimmsInstallable = mct_get_nv_bits(NV_MAX_DIMMS_PER_CH);

	u8 package_type;
	u8 control_code = 0;

	package_type = mct_get_nv_bits(NV_PACK_TYPE);
	u16 MemClkFreq = Get_NB32_DCT(p_dct_stat->dev_dct, dct, 0x94) & 0x1f;

	/* Obtain number of DIMMs on channel */
	u8 dimm_count = p_dct_stat->ma_dimms[dct];

	/* FIXME
	 * Assume there is only one register on the RDIMM for now
	 */
	u8 num_registers = 1;

	if (package_type == PT_GR) {
		/* Socket G34 */
		/* Fam15h BKDG Rev. 3.14 section 2.10.5.7.1.2.1 Table 85 */
		if (MaxDimmsInstallable == 1) {
			if ((MemClkFreq == 0x4) || (MemClkFreq == 0x6)) {
				/* DDR3-667 - DDR3-800 */
				control_code = 0x1;
			} else if ((MemClkFreq == 0xa) || (MemClkFreq == 0xe)) {
				/* DDR3-1066 - DDR3-1333 */
				if (num_registers == 1) {
					control_code = 0x0;
				} else {
					control_code = 0x1;
				}
			} else if ((MemClkFreq == 0x12) || (MemClkFreq == 0x16)) {
				/* DDR3-1600 - DDR3-1866 */
				control_code = 0x0;
			}
		} else if (MaxDimmsInstallable == 2) {
			if (dimm_count == 1) {
				/* 1 DIMM detected */
				if ((MemClkFreq == 0x4) || (MemClkFreq == 0x6)) {
					/* DDR3-667 - DDR3-800 */
					control_code = 0x1;
				} else if ((MemClkFreq >= 0xa) && (MemClkFreq <= 0x12)) {
					/* DDR3-1066 - DDR3-1600 */
					if (num_registers == 1) {
						control_code = 0x0;
					} else {
						control_code = 0x1;
					}
				}
			} else if (dimm_count == 2) {
				/* 2 DIMMs detected */
				if (num_registers == 1) {
					control_code = 0x1;
				} else {
					control_code = 0x8;
				}
			}
		} else if (MaxDimmsInstallable == 3) {
			/* TODO
			 * 3 DIMM/channel support unimplemented
			 */
		}
	} else if (package_type == PT_C3) {
		/* Socket C32 */
		/* Fam15h BKDG Rev. 3.14 section 2.10.5.7.1.2.1 Table 86 */
		if (MaxDimmsInstallable == 1) {
			if ((MemClkFreq == 0x4) || (MemClkFreq == 0x6)) {
				/* DDR3-667 - DDR3-800 */
				control_code = 0x1;
			} else if ((MemClkFreq == 0xa) || (MemClkFreq == 0xe)) {
				/* DDR3-1066 - DDR3-1333 */
				if (num_registers == 1) {
					control_code = 0x0;
				} else {
					control_code = 0x1;
				}
			} else if ((MemClkFreq == 0x12) || (MemClkFreq == 0x16)) {
				/* DDR3-1600 - DDR3-1866 */
				control_code = 0x0;
			}
		} else if (MaxDimmsInstallable == 2) {
			if (dimm_count == 1) {
				/* 1 DIMM detected */
				if ((MemClkFreq == 0x4) || (MemClkFreq == 0x6)) {
					/* DDR3-667 - DDR3-800 */
					control_code = 0x1;
				} else if ((MemClkFreq >= 0xa) && (MemClkFreq <= 0x12)) {
					/* DDR3-1066 - DDR3-1600 */
					if (num_registers == 1) {
						control_code = 0x0;
					} else {
						control_code = 0x1;
					}
				}
			} else if (dimm_count == 2) {
				/* 2 DIMMs detected */
				if (num_registers == 1) {
					control_code = 0x1;
				} else {
					control_code = 0x8;
				}
			}
		} else if (MaxDimmsInstallable == 3) {
			/* TODO
			 * 3 DIMM/channel support unimplemented
			 */
		}
	} else {
		/* TODO
		 * Other socket support unimplemented
		 */
	}

	printk(BIOS_SPEW, "%s: DCT %d IBT code: %01x\n", __func__, dct, control_code);
	return control_code;
}

static u16 memclk_to_freq(u16 memclk) {
	u16 fam10h_freq_tab[] = {0, 0, 0, 400, 533, 667, 800};
	u16 fam15h_freq_tab[] = {0, 0, 0, 0, 333, 0, 400, 0, 0, 0, 533, 0, 0, 0, 667, 0, 0, 0, 800, 0, 0, 0, 933};

	u16 mem_freq = 0;

	if (is_fam15h()) {
		if (memclk < 0x17) {
			mem_freq = fam15h_freq_tab[memclk];
		}
	} else {
		if ((memclk > 0x0) && (memclk < 0x8)) {
			mem_freq = fam10h_freq_tab[memclk - 1];
		}
	}

	return mem_freq;
}

static u8 rc_word_chip_select_lower_bit(void) {
	if (is_fam15h()) {
		return 21;
	} else {
		return 20;
	}
}

static u32 rc_word_address_to_ctl_bits(u32 address) {
	if (is_fam15h()) {
		return (((address >> 3) & 0x1) << 2) << 18 | (address & 0x7);
	} else {
		return (((address >> 3) & 0x1) << 2) << 16 | (address & 0x7);
	}
}

static u32 rc_word_value_to_ctl_bits(u32 value) {
	if (is_fam15h()) {
		return ((value >> 2) & 0x3) << 18 | ((value & 0x3) << 3);
	} else {
		return ((value >> 2) & 0x3) << 16 | ((value & 0x3) << 3);
	}
}

static u32 mct_ControlRC(struct MCTStatStruc *p_mct_stat,
			struct DCTStatStruc *p_dct_stat, u8 dct, u32 MrsChipSel, u32 CtrlWordNum)
{
	u8 Dimms, DimmNum;
	u32 val;
	u8 ddr_voltage_index;
	u16 mem_freq;
	u8 package_type = mct_get_nv_bits(NV_PACK_TYPE);
	u8 MaxDimmsInstallable = mct_get_nv_bits(NV_MAX_DIMMS_PER_CH);

	DimmNum = (MrsChipSel >> rc_word_chip_select_lower_bit()) & 0x7;

	if (dct == 1)
		DimmNum++;

	mem_freq = memclk_to_freq(p_dct_stat->dimm_auto_speed);
	Dimms = p_dct_stat->ma_dimms[dct];

	ddr_voltage_index = dct_ddr_voltage_index(p_dct_stat, dct);

	val = 0;
	if (CtrlWordNum == 0)
		val = 0x2;
	else if (CtrlWordNum == 1) {
		if (!((p_dct_stat->dimm_dr_present | p_dct_stat->dimm_qr_present) & (1 << DimmNum)))
			val = 0xc; /* if single rank, set DBA1 and DBA0 */
	} else if (CtrlWordNum == 2) {
		if (is_fam15h()) {
			val = (fam15h_rdimm_rc2_ibt_code(p_dct_stat, dct) & 0x1) << 2;
		} else {
			if (package_type == PT_GR) {
				/* Socket G34 */
				if (MaxDimmsInstallable == 2) {
					if (Dimms > 1)
						val = 0x4;
				}
			}
			else if (package_type == PT_C3) {
				/* Socket C32 */
				if (MaxDimmsInstallable == 2) {
					if (Dimms > 1)
						val = 0x4;
				}
			}
		}
	} else if (CtrlWordNum == 3) {
		val = (p_dct_stat->ctrl_wrd_3 >> (DimmNum << 2)) & 0xff;
	} else if (CtrlWordNum == 4) {
		val = (p_dct_stat->ctrl_wrd_4 >> (DimmNum << 2)) & 0xff;
	} else if (CtrlWordNum == 5) {
		val = (p_dct_stat->ctrl_wrd_5 >> (DimmNum << 2)) & 0xff;
	} else if (CtrlWordNum == 6) {
		val = ((p_dct_stat->spd_data.spd_bytes[DimmNum][72] & 0xf) >> (DimmNum << 2)) & 0xff;
	} else if (CtrlWordNum == 7) {
		val = (((p_dct_stat->spd_data.spd_bytes[DimmNum][72] >> 4) & 0xf) >> (DimmNum << 2)) & 0xff;
	} else if (CtrlWordNum == 8) {
		if (is_fam15h()) {
			val = (fam15h_rdimm_rc2_ibt_code(p_dct_stat, dct) & 0xe) >> 1;
		} else {
			if (package_type == PT_GR) {
				/* Socket G34 */
				if (MaxDimmsInstallable == 2) {
					val = 0x0;
				}
			}
			else if (package_type == PT_C3) {
				/* Socket C32 */
				if (MaxDimmsInstallable == 2) {
					val = 0x0;
				}
			}
		}
	} else if (CtrlWordNum == 9) {
		val = 0xd;	/* DBA1, DBA0, DA3 = 0 */
	} else if (CtrlWordNum == 10) {
		val = 0x0;	/* Lowest operating frequency */
	} else if (CtrlWordNum == 11) {
		if (ddr_voltage_index & 0x4)
			val = 0x2;	/* 1.25V */
		else if (ddr_voltage_index & 0x2)
			val = 0x1;	/* 1.35V */
		else
			val = 0x0;	/* 1.5V */
	} else if (CtrlWordNum == 12) {
		val = ((p_dct_stat->spd_data.spd_bytes[DimmNum][75] & 0xf) >> (DimmNum << 2)) & 0xff;
	} else if (CtrlWordNum == 13) {
		val = (((p_dct_stat->spd_data.spd_bytes[DimmNum][75] >> 4) & 0xf) >> (DimmNum << 2)) & 0xff;
	} else if (CtrlWordNum == 14) {
		val = ((p_dct_stat->spd_data.spd_bytes[DimmNum][76] & 0xf) >> (DimmNum << 2)) & 0xff;
	} else if (CtrlWordNum == 15) {
		val = (((p_dct_stat->spd_data.spd_bytes[DimmNum][76] >> 4) & 0xf) >> (DimmNum << 2)) & 0xff;
	}
	val &= 0xf;

	printk(BIOS_SPEW, "%s: Preparing to send DCT %d DIMM %d RC%d: %02x\n", __func__, dct, DimmNum >> 1, CtrlWordNum, val);

	val = MrsChipSel | rc_word_value_to_ctl_bits(val);
	val |= rc_word_address_to_ctl_bits(CtrlWordNum);

	return val;
}

static void mct_SendCtrlWrd(struct MCTStatStruc *p_mct_stat,
			struct DCTStatStruc *p_dct_stat, u8 dct, u32 val)
{
	u32 dev = p_dct_stat->dev_dct;

	val |= Get_NB32_DCT(dev, dct, 0x7c) & ~0xffffff;
	val |= 1 << SEND_CONTROL_WORD;
	Set_NB32_DCT(dev, dct, 0x7c, val);

	do {
		val = Get_NB32_DCT(dev, dct, 0x7c);
	} while (val & (1 << SEND_CONTROL_WORD));
}

void mct_dram_control_reg_init_d(struct MCTStatStruc *p_mct_stat,
				struct DCTStatStruc *p_dct_stat, u8 dct)
{
	u8 MrsChipSel;
	u32 dev = p_dct_stat->dev_dct;
	u32 val, cw;

	printk(BIOS_SPEW, "%s: Start\n", __func__);

	if (!is_fam15h()) {
		mct_wait(1600);
		mct_wait(1200);
	}

	p_dct_stat->cs_present = p_dct_stat->cs_present_dct[dct];
	if (p_dct_stat->ganged_mode & 1)
		p_dct_stat->cs_present = p_dct_stat->cs_present_dct[0];

	for (MrsChipSel = 0; MrsChipSel < 8; MrsChipSel += 2) {
		if (p_dct_stat->cs_present & (1 << MrsChipSel)) {
			val = Get_NB32_DCT(dev, dct, 0xa8);
			val &= ~(0xff << 8);

			switch (MrsChipSel) {
				case 0:
				case 1:
					val |= 3 << 8;
					break;
				case 2:
				case 3:
					val |= (3 << 2) << 8;
					break;
				case 4:
				case 5:
					val |= (3 << 4) << 8;
					break;
				case 6:
				case 7:
					val |= (3 << 6) << 8;
					break;
			}
			Set_NB32_DCT(dev, dct, 0xa8, val);
			printk(BIOS_SPEW, "%s: F2xA8: %08x\n", __func__, val);

			if (is_fam15h()) {
				for (cw = 0; cw <=15; cw ++) {
					val = mct_ControlRC(p_mct_stat, p_dct_stat, dct, MrsChipSel << rc_word_chip_select_lower_bit(), cw);
					mct_SendCtrlWrd(p_mct_stat, p_dct_stat, dct, val);
					if ((cw == 2) || (cw == 8) || (cw == 10))
						precise_ndelay_fam15(p_mct_stat, 6000);
				}
			} else {
				for (cw = 0; cw <=15; cw ++) {
					mct_wait(1600);
					val = mct_ControlRC(p_mct_stat, p_dct_stat, dct, MrsChipSel << rc_word_chip_select_lower_bit(), cw);
					mct_SendCtrlWrd(p_mct_stat, p_dct_stat, dct, val);
				}
			}
		}
	}

	mct_wait(1200);

	printk(BIOS_SPEW, "%s: Done\n", __func__);
}

void freq_chg_ctrl_wrd(struct MCTStatStruc *p_mct_stat,
			struct DCTStatStruc *p_dct_stat, u8 dct)
{
	u32 SaveSpeed = p_dct_stat->dimm_auto_speed;
	u32 MrsChipSel;
	u32 dev = p_dct_stat->dev_dct;
	u32 val;
	u16 mem_freq;

	p_dct_stat->cs_present = p_dct_stat->cs_present_dct[dct];
	if (p_dct_stat->ganged_mode & 1)
		p_dct_stat->cs_present = p_dct_stat->cs_present_dct[0];

	p_dct_stat->dimm_auto_speed = p_dct_stat->target_freq;
	mem_freq = memclk_to_freq(p_dct_stat->target_freq);
	for (MrsChipSel = 0; MrsChipSel < 8; MrsChipSel += 2) {
		if (p_dct_stat->cs_present & (1 << MrsChipSel)) {
			/* 2. Program F2x[1, 0]A8[CtrlWordCS]=bit mask for target chip selects. */
			val = Get_NB32_DCT(dev, dct, 0xa8);
			val &= ~(0xff << 8);

			switch (MrsChipSel) {
				case 0:
				case 1:
					val |= 3 << 8;
					break;
				case 2:
				case 3:
					val |= (3 << 2) << 8;
					break;
				case 4:
				case 5:
					val |= (3 << 4) << 8;
					break;
				case 6:
				case 7:
					val |= (3 << 6) << 8;
					break;
			}
			Set_NB32_DCT(dev, dct, 0xa8, val);

			/* Resend control word 10 */
			u8 freq_ctl_val = 0;
			mct_wait(1600);
			switch (mem_freq) {
				case 333:
				case 400:
					freq_ctl_val = 0x0;
					break;
				case 533:
					freq_ctl_val = 0x1;
					break;
				case 667:
					freq_ctl_val = 0x2;
					break;
				case 800:
					freq_ctl_val = 0x3;
					break;
				case 933:
					freq_ctl_val = 0x4;
					break;
			}

			printk(BIOS_SPEW, "Preparing to send DCT %d DIMM %d RC%d: %02x (F2xA8: %08x)\n", dct, MrsChipSel >> 1, 10, freq_ctl_val, val);

			mct_SendCtrlWrd(p_mct_stat, p_dct_stat, dct, (MrsChipSel << rc_word_chip_select_lower_bit()) | rc_word_address_to_ctl_bits(10) | rc_word_value_to_ctl_bits(freq_ctl_val));

			if (is_fam15h())
				precise_ndelay_fam15(p_mct_stat, 6000);
			else
				mct_wait(1600);

			/* Resend control word 2 */
			val = mct_ControlRC(p_mct_stat, p_dct_stat, dct, MrsChipSel << rc_word_chip_select_lower_bit(), 2);
			mct_SendCtrlWrd(p_mct_stat, p_dct_stat, dct, val);

			if (is_fam15h())
				precise_ndelay_fam15(p_mct_stat, 6000);
			else
				mct_wait(1600);

			/* Resend control word 8 */
			val = mct_ControlRC(p_mct_stat, p_dct_stat, dct, MrsChipSel << rc_word_chip_select_lower_bit(), 8);
			mct_SendCtrlWrd(p_mct_stat, p_dct_stat, dct, val);

			if (is_fam15h())
				precise_ndelay_fam15(p_mct_stat, 6000);
			else
				mct_wait(1600);
		}
	}
	p_dct_stat->dimm_auto_speed = SaveSpeed;
}

/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <baseboard/gpio.h>
#include <baseboard/variants.h>
#include <types.h>
#include <soc/gpio.h>
#include <vendorcode/google/chromeos/chromeos.h>

/* Pad configuration in ramstage */
static const struct pad_config gpio_table[] = {
	/* A0 thru A5, A9 and A10 come configured out of reset, do not touch */
	/* A0  : ESPI_IO0 ==> ESPI_IO_0 */
	/* A1  : ESPI_IO1 ==> ESPI_IO_1 */
	/* A2  : ESPI_IO2 ==> ESPI_IO_2 */
	/* A3  : ESPI_IO3 ==> ESPI_IO_3 */
	/* A4  : ESPI_CS# ==> ESPI_CS_L */
	/* A5  : ESPI_ALERT0# ==> TP78 */
	PAD_NC(GPP_A5, NONE),
	/* A6  : ESPI_ALERT1# ==> TP88 */
	PAD_NC(GPP_A6, NONE),
	/* A7  : SRCCLK_OE7# ==> LAN_WAKE_ODL */
	PAD_CFG_GPI_SCI_LOW(GPP_A7, NONE, DEEP, EDGE_SINGLE),
	/* A8  : SRCCLKREQ7# ==> CLKREQ_7 */
	PAD_NC(GPP_A8, NONE),
	/* A9  : ESPI_CLK ==> ESPI_CLK */
	/* A10 : ESPI_RESET# ==> ESPI_PCH_RST_EC_L */
	/* A11 : PMC_I2C_SDA ==> NC */
	PAD_NC(GPP_A11, NONE),
	/* A12 : SATAXPCIE1 ==> CLKREQ_9B */
	PAD_NC(GPP_A12, NONE),
	/* A13 : PMC_I2C_SCL ==> GSC_PCH_INT_ODL */
	PAD_CFG_GPI_APIC_LOCK(GPP_A13, NONE, LEVEL, INVERT, LOCK_CONFIG),
	/* A14 : USB_OC1# ==> USB_C1_OC_ODL */
	PAD_CFG_NF(GPP_A14, NONE, DEEP, NF1),
	/* A15 : USB_OC2# ==> USB_C2_OC_ODL */
	PAD_CFG_NF(GPP_A15, NONE, DEEP, NF1),
	/* A16 : USB_OC3# ==> USB_A0_OC_ODL */
	PAD_CFG_NF_LOCK(GPP_A16, NONE, NF1, LOCK_CONFIG),
	/* A17 : DISP_MISCC ==> NC */
	PAD_NC(GPP_A17, NONE),
	/* A18 : DDSP_HPDB ==> HDMI_HPD */
	PAD_CFG_NF(GPP_A18, NONE, DEEP, NF1),
	/* A19 : DDSP_HPD1 ==> USB_C2_AUX_DC_P */
	PAD_CFG_NF(GPP_A19, NONE, DEEP, NF6),
	/* A20 : DDSP_HPD2 ==> USB_C2_AUX_DC_N */
	PAD_CFG_NF(GPP_A20, NONE, DEEP, NF6),
	/* A21 : DDPC_CTRCLK ==> USB_C1_AUX_DC_P */
	PAD_CFG_NF(GPP_A21, NONE, DEEP, NF6),
	/* A22 : DDPC_CTRLDATA ==> USB_C1_AUX_DC_N */
	PAD_CFG_NF(GPP_A22, NONE, DEEP, NF6),
	/* A23 : ESPI_CS1# ==> AUD_HP_INT_L */
	PAD_CFG_GPI_INT(GPP_A23, NONE, PLTRST, EDGE_BOTH),

	/* B0  : SOC_VID0 */
	PAD_CFG_NF(GPP_B0, NONE, DEEP, NF1),
	/* B1  : SOC_VID1 */
	PAD_CFG_NF(GPP_B1, NONE, DEEP, NF1),
	/* B2  : VRALERT# ==> M2_SSD_PLA_L */
	PAD_CFG_GPO(GPP_B2, 1, PLTRST),
	/* B3  : PROC_GP2 ==> NC */
	PAD_NC_LOCK(GPP_B3, NONE, LOCK_CONFIG),
	/* B4  : PROC_GP3 ==> SSD_PERST_L */
	PAD_CFG_GPO_LOCK(GPP_B4, 1, LOCK_CONFIG),
	/* B5  : ISH_I2C0_SDA ==> PCH_I2C_MISC_SDA */
	PAD_CFG_NF_LOCK(GPP_B5, NONE, NF2, LOCK_CONFIG),
	/* B6  : ISH_I2C0_SCL ==> PCH_I2C_MISC_SCL */
	PAD_CFG_NF_LOCK(GPP_B6, NONE, NF2, LOCK_CONFIG),
	/* B7  : ISH_12C1_SDA ==> NC */
	PAD_NC_LOCK(GPP_B7, NONE, LOCK_CONFIG),
	/* B8  : ISH_I2C1_SCL ==> NC */
	PAD_NC_LOCK(GPP_B8, NONE, LOCK_CONFIG),
	/* B9  : NC */
	PAD_NC(GPP_B9, NONE),
	/* B10 : NC */
	PAD_NC(GPP_B10, NONE),
	/* B11 : PMCALERT# ==> EN_PP3300_WLAN */
	PAD_CFG_GPO(GPP_B11, 1, DEEP),
	/* B12 : SLP_S0# ==> SLP_S0_L */
	PAD_CFG_NF(GPP_B12, NONE, DEEP, NF1),
	/* B13 : PLTRST# ==> PLT_RST_L */
	PAD_CFG_NF(GPP_B13, NONE, DEEP, NF1),
	/* B14 : SPKR ==> PWM_PP3300_BUZZER */
	PAD_CFG_NF_LOCK(GPP_B14, NONE, NF1, LOCK_CONFIG),
	/* B15 : TIME_SYNC0 ==> TP159 */
	PAD_NC_LOCK(GPP_B15, NONE, LOCK_CONFIG),
	/* B16 : I2C5_SDA ==> NC */
	PAD_NC_LOCK(GPP_B16, NONE, LOCK_CONFIG),
	/* B17 : I2C5_SCL ==> NC */
	PAD_NC_LOCK(GPP_B17, NONE, LOCK_CONFIG),
	/* B18 : ADR_COMPLETE ==> GPP_B18_STRAP */
	PAD_NC(GPP_B18, NONE),
	/* B19 : NC */
	PAD_NC(GPP_B19, NONE),
	/* B20 : NC */
	PAD_NC(GPP_B20, NONE),
	/* B21 : NC */
	PAD_NC(GPP_B21, NONE),
	/* B22 : NC */
	PAD_NC(GPP_B22, NONE),
	/* B23 : SML1ALERT# ==> PCHHOT_ODL_STRAP */
	PAD_NC(GPP_B23, NONE),

	/* C0  : SMBCLK ==> DDR_SMB_CLK */
	PAD_CFG_NF(GPP_C0, NONE, DEEP, NF1),
	/* C1  : SMBDATA ==> DDR_SMB_DATA */
	PAD_CFG_NF(GPP_C1, NONE, DEEP, NF1),
	/* C2  : SMBALERT# ==> GPP_C2_STRAP */
	PAD_NC(GPP_C2, NONE),
	/* C3 : SML0CLK ==> USB_C0_AUX_DC_P */
	PAD_NC(GPP_C3, NONE),
	/* C4 : SML0DATA ==> USB_C0_AUX_DC_N */
	PAD_NC(GPP_C4, NONE),
	/* C5  : SML0ALERT# ==> GPP_C5_BOOT_STRAP0 */
	PAD_NC(GPP_C5, NONE),
	/* C6  : SML1CLK ==> NC */
	PAD_NC(GPP_C6, NONE),
	/* C7  : SML1DATA ==> NC */
	PAD_NC(GPP_C7, NONE),

	/* D0  : ISH_GP0 ==> PCH_FP_BOOT0 */
	PAD_CFG_GPO_LOCK(GPP_D0, 0, LOCK_CONFIG),
	/* D1  : ISH_GP1 ==> FP_RST_ODL */
	PAD_CFG_GPO_LOCK(GPP_D1, 1, LOCK_CONFIG),
	/* D2  : ISH_GP2 ==> EN_FP_PWR */
	PAD_CFG_GPO_LOCK(GPP_D2, 1, LOCK_CONFIG),
	/* D3  : ISH_GP3 ==> EN_NFC_PWR */
	PAD_CFG_GPO_LOCK(GPP_D3, 1, LOCK_CONFIG),
	/* D4  : IMGCLKOUT0 ==> BT_DISABLE_L */
	PAD_CFG_GPO(GPP_D4, 1, DEEP),
	/* D5  : SRCCLKREQ0# ==> SSD_CLKREQ_ODL */
	PAD_CFG_NF(GPP_D5, NONE, DEEP, NF1),
	/* D6  : SRCCLKREQ1# ==> CLKREQ_1 */
	PAD_NC(GPP_D6, NONE),
	/* D7  : SRCCLKREQ2# ==> WLAN_CLKREQ_ODL */
	PAD_CFG_NF(GPP_D7, NONE, DEEP, NF1),
	/* D8  : SRCCLKREQ3# ==> SD_CLKREQ_ODL */
	PAD_CFG_NF(GPP_D8, NONE, DEEP, NF1),
	/* D9  : ISH_SPI_CS# ==> USB_C2_LSX_TX */
	PAD_CFG_NF_LOCK(GPP_D9, NONE, NF4, LOCK_CONFIG),
	/* D10 : ISH_SPI_CLK ==> USB_C2_LSX_RX_STRAP */
	PAD_CFG_NF_LOCK(GPP_D10, NONE, NF4, LOCK_CONFIG),
	/* D11 : ISH_SPI_MISO ==> DDIA_DP_CTRLCLK */
	PAD_CFG_NF_LOCK(GPP_D11, NONE, NF2, LOCK_CONFIG),
	/* D12 : ISH_SPI_MOSI ==> DDIA_DP_CTRLDATA */
	PAD_CFG_NF_LOCK(GPP_D12, NONE, NF2, LOCK_CONFIG),
	/* D13 : ISH_UART0_RXD ==> TP97 */
	PAD_NC_LOCK(GPP_D13, NONE, LOCK_CONFIG),
	/* D14 : ISH_UART0_TXD ==> TP93 */
	PAD_NC_LOCK(GPP_D14, NONE, LOCK_CONFIG),
	/* D15 : ISH_UART0_RTS# ==> NC */
	PAD_NC_LOCK(GPP_D15, NONE, LOCK_CONFIG),
	/* D16 : ISH_UART0_CTS# ==> NC */
	PAD_NC_LOCK(GPP_D16, NONE, LOCK_CONFIG),
	/* D17 : UART1_RXD ==> SD_PE_PRSNT_L */
	PAD_CFG_GPI_LOCK(GPP_D17, NONE, LOCK_CONFIG),
	/* D18 : UART1_TXD ==> SD_PE_RST_L */
	PAD_CFG_GPO_LOCK(GPP_D18, 1, LOCK_CONFIG),
	/* D19 : I2S_MCLK1_OUT ==> I2S_MCLK_R */
	PAD_CFG_NF(GPP_D19, NONE, DEEP, NF1),

	/* E0  : SATAXPCIE0 ==> CLKREQ_9 */
	PAD_NC(GPP_E0, NONE),
	/* E1  : THC0_SPI1_IO2 ==> NC */
	PAD_NC_LOCK(GPP_E1, NONE, LOCK_CONFIG),
	/* E2  : THC0_SPI1_IO3 ==> NC */
	PAD_NC_LOCK(GPP_E2, NONE, LOCK_CONFIG),
	/* E3  : PROC_GP0 ==> TP94644 */
	PAD_NC(GPP_E3, NONE),
	/* E4  : SATA_DEVSLP0 ==> USB4_BB_RT_FORCE_PWR */
	PAD_CFG_GPO(GPP_E4, 0, DEEP),
	/* E5  : SATA_DEVSLP1 ==> NC */
	PAD_NC(GPP_E5, NONE),
	/* E6  : THC0_SPI1_RST# ==> GPPE6_STRAP */
	PAD_NC_LOCK(GPP_E6, NONE, LOCK_CONFIG),
	/* E7  : PROC_GP1 ==> TP94643 */
	PAD_NC(GPP_E7, NONE),
	/* E8  : SLP_DRAM# ==> WIFI_DISABLE_L */
	PAD_CFG_GPO(GPP_E8, 1, DEEP),
	/* E9  : USB_OC0# ==> USB_C0_OC_ODL */
	PAD_CFG_NF_LOCK(GPP_E9, NONE, NF1, LOCK_CONFIG),
	/* E10 : THC0_SPI1_CS# ==> NC */
	PAD_NC_LOCK(GPP_E10, NONE, LOCK_CONFIG),
	/* E11 : THC0_SPI1_CLK ==> NC */
	PAD_NC_LOCK(GPP_E11, NONE, LOCK_CONFIG),
	/* E12 : THC0_SPI1_IO1 ==> NC */
	PAD_NC_LOCK(GPP_E12, NONE, LOCK_CONFIG),
	/* E13 : THC0_SPI1_IO2 ==> NC */
	PAD_NC_LOCK(GPP_E13, NONE, LOCK_CONFIG),
	/* E14 : DDSP_HPDA ==> SOC_DP_HPD */
	PAD_CFG_NF(GPP_E14, NONE, DEEP, NF1),
	/* E15 : RSVD_TP ==> PCH_WP_OD */
	PAD_CFG_GPI_GPIO_DRIVER_LOCK(GPP_E15, NONE, LOCK_CONFIG),
	/* E16 : RSVD_TP ==> CLKREQ_8 */
	PAD_NC(GPP_E16, NONE),
	/* E17 : THC0_SPI1_INT# ==> TP102 */
	PAD_NC_LOCK(GPP_E17, NONE, LOCK_CONFIG),
	/* E18 : DDP1_CTRLCLK ==> USB_C0_LSX_TX */
	PAD_CFG_NF(GPP_E18, NONE, DEEP, NF4),
	/* E19 : DDP1_CTRLDATA ==> USB0_C0_LSX_RX_STRAP */
	PAD_CFG_NF(GPP_E19, NONE, DEEP, NF4),
	/* E20 : DDP2_CTRLCLK ==> USB_C1_LSX_TX */
	PAD_CFG_NF(GPP_E20, NONE, DEEP, NF4),
	/* E21 : DDP2_CTRLDATA ==> USB_C1_LSX_RX_STRAP */
	PAD_CFG_NF(GPP_E21, NONE, DEEP, NF4),
	/* E22 : DDPA_CTRLCLK ==> NC */
	PAD_NC(GPP_E22, NONE),
	/* E23 : DDPA_CTRLDATA ==> NC */
	PAD_NC(GPP_E23, NONE),

	/* F0  : CNV_BRI_DT ==> CNV_BRI_DT_STRAP */
	PAD_CFG_NF(GPP_F0, NONE, DEEP, NF1),
	/* F1  : CNV_BRI_RSP ==> CNV_BRI_RSP */
	PAD_CFG_NF(GPP_F1, UP_20K, DEEP, NF1),
	/* F2  : CNV_RGI_DT ==> CNV_RGI_DT_STRAP */
	PAD_CFG_NF(GPP_F2, NONE, DEEP, NF1),
	/* F3  : CNV_RGI_RSP ==> CNV_RGI_RSP */
	PAD_CFG_NF(GPP_F3, UP_20K, DEEP, NF1),
	/* F4  : CNV_RF_RESET# ==> CNV_RF_RST_L */
	PAD_CFG_NF(GPP_F4, NONE, DEEP, NF1),
	/* F5  : MODEM_CLKREQ ==> CNV_CLKREQ0 */
	PAD_CFG_NF(GPP_F5, NONE, DEEP, NF3),
	/* F6  : CNV_PA_BLANKING ==> WWAN_WLAN_COEX3 */
	PAD_CFG_NF(GPP_F6, NONE, DEEP, NF1),
	/* F7  : GPPF7_STRAP */
	PAD_NC(GPP_F7, NONE),
	/* F8  : NC */
	PAD_NC(GPP_F8, NONE),
	/* F9  : BOOTMPC ==> SLP_S0_GATE_R */
	PAD_CFG_GPO(GPP_F9, 1, PLTRST),
	/* F10 : GPPF10_STRAP */
	PAD_NC(GPP_F10, DN_20K),
	/* F11 : THC1_SPI2_CLK ==> GSPI_PCH_CLK_FPMCU_R */
	PAD_CFG_NF_LOCK(GPP_F11, NONE, NF4, LOCK_CONFIG),
	/* F12 : GSXDOUT ==> GSPI_PCH_DO_FPMCU_DI_R */
	PAD_CFG_NF_LOCK(GPP_F12, NONE, NF4, LOCK_CONFIG),
	/* F13 : GSXDOUT ==> GSPI_PCH_DI_FPMCU_DO */
	PAD_CFG_NF_LOCK(GPP_F13, NONE, NF4, LOCK_CONFIG),
	/* F14 : GSXDIN ==> EN_PP3300_SSD */
	PAD_CFG_GPO_LOCK(GPP_F14, 1, LOCK_CONFIG),
	/* F15 : GSXSRESET# ==> FPMCU_INT_L */
	PAD_CFG_GPI_IRQ_WAKE_LOCK(GPP_F15, NONE, LEVEL, INVERT, LOCK_CONFIG),
	/* F16 : GSXCLK ==> GSPI_PCH_CS_FPMCU_R_L */
	PAD_CFG_NF_LOCK(GPP_F16, NONE, NF4, LOCK_CONFIG),
	/* F17 : THC1_SPI2_RST# ==> EC_PCH_INT_ODL */
	PAD_CFG_GPI_IRQ_WAKE_LOCK(GPP_F17, NONE, LEVEL, INVERT, LOCK_CONFIG),
	/* F18 : THC1_SPI2_INT# ==> EC_IN_RW_OD */
	PAD_CFG_GPI_LOCK(GPP_F18, NONE, LOCK_CONFIG),
	/* F19 : SRCCLKREQ6# ==> LAN_CLKREQ_ODL */
	PAD_CFG_NF(GPP_F19, NONE, DEEP, NF1),
	/* F20 : EXT_PWR_GATE# ==> TP94669 */
	PAD_NC(GPP_F20, NONE),
	/* F21 : EXT_PWR_GATE2# ==> TP94579 */
	PAD_NC(GPP_F21, NONE),
	/* F22 : VNN_CTRL ==> TP153 */
	PAD_NC(GPP_F22, NONE),
	/* F23 : V1P05_CTRL ==> TP154 */
	PAD_NC(GPP_F23, NONE),

	/* H0  : GPPH0_BOOT_STRAP1 */
	PAD_NC(GPP_H0, NONE),
	/* H1  : GPPH1_BOOT_STRAP2 */
	PAD_NC(GPP_H1, NONE),
	/* H2  : GPPH2_BOOT_STRAP3 */
	PAD_NC(GPP_H2, NONE),
	/* H3  : SX_EXIT_HOLDOFF# ==> WLAN_PCIE_WAKE_ODL */
	PAD_CFG_GPI_LOCK(GPP_H3, NONE, LOCK_CONFIG),
	/* H4  : I2C0_SDA ==> PCH_I2C_AUD_SDA */
	PAD_CFG_NF(GPP_H4, NONE, DEEP, NF1),
	/* H5  : I2C0_SCL ==> PCH_I2C_AUD_SCL */
	PAD_CFG_NF(GPP_H5, NONE, DEEP, NF1),
	/* H6  : I2C1_SDA ==> PCH_I2C_TPM_SDA */
	PAD_CFG_NF_LOCK(GPP_H6, NONE, NF1, LOCK_CONFIG),
	/* H7  : I2C1_SCL ==> PCH_I2C_TPM_SCL */
	PAD_CFG_NF_LOCK(GPP_H7, NONE, NF1, LOCK_CONFIG),
	/* H8  : I2C4_SDA ==> WWAN_WLAN_COEX1 */
	PAD_CFG_NF(GPP_H8, NONE, DEEP, NF2),
	/* H9  : I2C4_SCL ==> WWAN_WLAN_COEX2 */
	PAD_CFG_NF(GPP_H9, NONE, DEEP, NF2),
	/* H10 : UART0_RXD ==> UART_PCH_RX_DBG_TX */
	PAD_CFG_NF(GPP_H10, NONE, DEEP, NF2),
	/* H11 : UART0_TXD ==> UART_PCH_TX_DBG_RX */
	PAD_CFG_NF(GPP_H11, NONE, DEEP, NF2),
	/* H12 : I2C7_SDA ==> SD_PE_WAKE_ODL */
	PAD_CFG_GPI_LOCK(GPP_H12, NONE, LOCK_CONFIG),
	/* H13 : I2C7_SCL ==> EN_PP3300_SD */
	PAD_CFG_GPO_LOCK(GPP_H13, 1, LOCK_CONFIG),
	/* H14 : NC */
	PAD_NC(GPP_H14, NONE),
	/* H15 : DDPB_CTRLCLK ==> DDIB_HDMI_CTRLCLK */
	PAD_CFG_NF(GPP_H15, NONE, DEEP, NF1),
	/* H16 : NC */
	PAD_NC(GPP_H16, NONE),
	/* H17 : DDPB_CTRLDATA ==> DDIB_HDMI_CTRLDATA */
	PAD_CFG_NF(GPP_H17, NONE, DEEP, NF1),
	/* H18 : PROC_C10_GATE# ==> CPU_C10_GATE_L */
	PAD_CFG_NF(GPP_H18, NONE, DEEP, NF1),
	/* H19 : SRCCLKREQ4# ==> CLKREQ_4 */
	PAD_NC(GPP_H19, NONE),
	/* H20 : IMGCLKOUT1 ==> WLAN_PERST_L */
	PAD_CFG_GPO(GPP_H20, 1, DEEP),
	/* H21 : IMGCLKOUT2 ==>  TP94574 */
	PAD_NC(GPP_H21, NONE),
	/* H22 : IMGCLKOUT3 ==> LAN_PE_ISOLATE_ODL */
	PAD_CFG_GPO(GPP_H22, 1, DEEP),
	/* H23 : SRCCLKREQ5# ==> M2_SSD_PLN_L */
	PAD_CFG_GPO(GPP_H23, 1, PLTRST),

	/* R0 : HDA_BCLK ==> I2S_HP_SCLK_R */
	PAD_CFG_NF(GPP_R0, NONE, DEEP, NF2),
	/* R1 : HDA_SYNC ==> I2S_HP_SFRM_R */
	PAD_CFG_NF(GPP_R1, NONE, DEEP, NF2),
	/* R2 : HDA_SDO ==> I2S_PCH_TX_HP_RX_STRAP */
	PAD_CFG_NF(GPP_R2, DN_20K, DEEP, NF2),
	/* R3 : HDA_SDIO ==> I2S_PCH_RX_HP_TX */
	PAD_CFG_NF(GPP_R3, NONE, DEEP, NF2),
	/* R4 : HDA_RST# ==> DMIC_CLK0_R */
	PAD_CFG_NF(GPP_R4, NONE, DEEP, NF3),
	/* R5 : HDA_SDI1 ==> DMIC_DATA0_R */
	PAD_CFG_NF(GPP_R5, NONE, DEEP, NF3),
	/* R6 : I2S2_TXD ==> DMIC_CLK1_R */
	PAD_CFG_NF(GPP_R6, NONE, DEEP, NF3),
	/* R7 : I2S2_RXD ==> DMIC_DATA1_R */
	PAD_CFG_NF(GPP_R7, NONE, DEEP, NF3),

	/* S0 : SNDW0_CLK ==> NC */
	PAD_NC(GPP_S0, NONE),
	/* S1 : SNDW0_DATA ==> NC */
	PAD_NC(GPP_S1, NONE),
	/* S2 : SNDW1_CLK ==> NC */
	PAD_NC(GPP_S2, NONE),
	/* S3 : SNDW1_DATA ==> NC */
	PAD_NC(GPP_S3, NONE),
	/* S4 : SNDW2_CLK ==> NC */
	PAD_NC(GPP_S4, NONE),
	/* S5 : SNDW2_DATA ==> NC */
	PAD_NC(GPP_S5, NONE),
	/* S6 : SNDW3_CLK ==> NC */
	PAD_NC(GPP_S6, NONE),
	/* S7 : SNDW3_DATA ==> NC */
	PAD_NC(GPP_S7, NONE),

	/* GPD0: BATLOW# ==> BATLOW_L */
	PAD_CFG_NF(GPD0, NONE, DEEP, NF1),
	/* GPD1: ACPRESENT ==> ACPRESENT */
	PAD_CFG_NF(GPD1, NONE, DEEP, NF1),
	/* GPD2 : LAN_WAKE# ==> EC_PCH_WAKE_ODL */
	PAD_CFG_NF(GPD2, NONE, DEEP, NF1),
	/* GPD3: PWRBTN# ==> EC_PCH_PWR_BTN_ODL */
	PAD_CFG_NF(GPD3, NONE, DEEP, NF1),
	/* GPD4: SLP_S3# ==> SLP_S3_L */
	PAD_CFG_NF(GPD4, NONE, DEEP, NF1),
	/* GPD5: SLP_S4# ==> SLP_S4_L */
	PAD_CFG_NF(GPD5, NONE, DEEP, NF1),
	/* GPD6: SLP_A# ==> SLP_A_L_CAP_SITE */
	PAD_CFG_NF(GPD6, NONE, DEEP, NF1),
	/* GPD7: GPD7_STRAP */
	PAD_NC(GPD7, NONE),
	/* GPD8: SUSCLK ==> PCH_SUSCLK */
	PAD_CFG_NF(GPD8, NONE, DEEP, NF1),
	/* GPD9: SLP_WLAN# ==> SLP_WLAN_L_CAP_SITE */
	PAD_CFG_NF(GPD9, NONE, DEEP, NF1),
	/* GPD10: SLP_S5# ==> SLP_S5_L */
	PAD_CFG_NF(GPD10, NONE, DEEP, NF1),
	/* GPD11: LANPHYC ==> TP99 */
	PAD_NC(GPD11, NONE),
};

/* Early pad configuration in bootblock */
static const struct pad_config early_gpio_table[] = {
	/* A13 : PMC_I2C_SCL ==> GSC_PCH_INT_ODL */
	PAD_CFG_GPI_APIC(GPP_A13, NONE, PLTRST, LEVEL, INVERT),
	/* B4  : PROC_GP3 ==> SSD_PERST_L */
	PAD_CFG_GPO(GPP_B4, 0, DEEP),
	/*
	 * D1  : ISH_GP1 ==> FP_RST_ODL
	 * FP_RST_ODL comes out of reset as hi-z and does not have an external pull-down.
	 * To ensure proper power sequencing for the FPMCU device, reset signal is driven low
	 * early on in bootblock, followed by enabling of power. Reset signal is deasserted
	 * later on in ramstage. Since reset signal is asserted in bootblock, it results in
	 * FPMCU not working after a S3 resume. This is a known issue.
	 */
	PAD_CFG_GPO(GPP_D1, 0, DEEP),
	/* D2  : ISH_GP2 ==> EN_FP_PWR */
	PAD_CFG_GPO(GPP_D2, 1, DEEP),
	/* E15 : RSVD_TP ==> PCH_WP_OD */
	PAD_CFG_GPI_GPIO_DRIVER(GPP_E15, NONE, DEEP),
	/* F14 : GSXDIN ==> EN_PP3300_SSD */
	PAD_CFG_GPO(GPP_F14, 1, DEEP),
	/* H6  : I2C1_SDA ==> PCH_I2C_TPM_SDA */
	PAD_CFG_NF(GPP_H6, NONE, DEEP, NF1),
	/* H7  : I2C1_SCL ==> PCH_I2C_TPM_SCL */
	PAD_CFG_NF(GPP_H7, NONE, DEEP, NF1),
	/* H10 : UART0_RXD ==> UART_PCH_RX_DBG_TX */
	PAD_CFG_NF(GPP_H10, NONE, DEEP, NF2),
	/* H11 : UART0_TXD ==> UART_PCH_TX_DBG_RX */
	PAD_CFG_NF(GPP_H11, NONE, DEEP, NF2),
	/* H13 : I2C7_SCL ==> EN_PP3300_SD */
	PAD_CFG_GPO(GPP_H13, 1, DEEP),
};

static const struct pad_config romstage_gpio_table[] = {
	/* B4  : PROC_GP3 ==> SSD_PERST_L */
	PAD_CFG_GPO(GPP_B4, 1, DEEP),
};

const struct pad_config *__weak variant_gpio_table(size_t *num)
{
	*num = ARRAY_SIZE(gpio_table);
	return gpio_table;
}

const struct pad_config *__weak variant_gpio_override_table(size_t *num)
{
	*num = 0;
	return NULL;
}

const struct pad_config *__weak variant_early_gpio_table(size_t *num)
{
	*num = ARRAY_SIZE(early_gpio_table);
	return early_gpio_table;
}

static const struct cros_gpio cros_gpios[] = {
	CROS_GPIO_REC_AL(CROS_GPIO_VIRTUAL, CROS_GPIO_DEVICE_NAME),
	CROS_GPIO_WP_AH(GPIO_PCH_WP, CROS_GPIO_DEVICE_NAME),
};

DECLARE_WEAK_CROS_GPIOS(cros_gpios);

const struct pad_config *__weak variant_romstage_gpio_table(size_t *num)
{
	*num = ARRAY_SIZE(romstage_gpio_table);
	return romstage_gpio_table;
}

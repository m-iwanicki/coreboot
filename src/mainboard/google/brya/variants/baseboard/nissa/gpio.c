/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <baseboard/gpio.h>
#include <baseboard/variants.h>
#include <types.h>
#include <soc/gpio.h>
#include <vendorcode/google/chromeos/chromeos.h>

/* Pad configuration in ramstage */
static const struct pad_config gpio_table[] = {
	/* A0 thru A4, A9 and A10 come configured out of reset, do not touch */
	/* A0  : ESPI_IO0 ==> ESPI_SOC_D0_EC */
	/* A1  : ESPI_IO1 ==> ESPI_SOC_D1_EC */
	/* A2  : ESPI_IO2 ==> ESPI_SOC_D2_EC */
	/* A3  : ESPI_IO3 ==> ESPI_SOC_D3_EC */
	/* A4  : ESPI_CS0# ==> ESPI_SOC_CS_EC_L */
	/* A5  : ESPI_ALERT0# ==> NC */
	PAD_NC(GPP_A5, NONE),
	/* A6  : ESPI_ALERT1# ==> NC */
	PAD_NC(GPP_A6, NONE),
	/* A7  : NC */
	PAD_NC(GPP_A7, NONE),
	/* A8  : GPP_A8 ==> WWAN_RF_DISABLE_ODL */
	PAD_CFG_GPO(GPP_A8, 1, DEEP),
	/* A9  : ESPI_CLK ==> ESPI_SOC_CLK */
	/* A10 : ESPI_RESET# ==> ESPI_SOC_RST_EC_L */
	/* A11 : GPP_A11 ==> EN_SPK_PA */
	PAD_CFG_GPO(GPP_A11, 1, DEEP),
	/* A12 : NC */
	PAD_NC(GPP_A12, NONE),
	/* A13 : GPP_A13 ==> GSC_SOC_INT_ODL */
	PAD_CFG_GPI_APIC(GPP_A13, NONE, PLTRST, LEVEL, INVERT),
	/* A14 : USB_OC1# ==> NC */
	PAD_NC(GPP_A14, NONE),
	/* A15 : USB_OC2# ==> NC */
	PAD_NC(GPP_A15, NONE),
	/* A16 : USB_OC3# ==> NC */
	PAD_NC(GPP_A16, NONE),
	/* A17 : NC */
	PAD_NC(GPP_A17, NONE),
	/* A18 : NC */
	PAD_NC(GPP_A18, NONE),
	/* A19 : NC */
	PAD_NC(GPP_A19, NONE),
	/* A20 : DDSP_HPD2 ==> EC_SOC_HDMI_HPD */
	PAD_CFG_NF(GPP_A20, NONE, DEEP, NF1),
	/* A21 : GPP_A21 ==> USB_C1_AUX_DC_P */
	PAD_CFG_NF(GPP_A21, NONE, DEEP, NF6),
	/* A22 : GPP_A22 ==> USB_C1_AUX_DC_N */
	PAD_CFG_NF(GPP_A22, NONE, DEEP, NF6),
	/* A23 : GPP_A23 ==> HP_INT_ODL */
	PAD_CFG_GPI_INT(GPP_A23, NONE, PLTRST, EDGE_BOTH),

	/* B0  : CORE_VID0 ==> VCCIN_AUX_VID0 */
	PAD_CFG_NF(GPP_B0, NONE, DEEP, NF1),
	/* B1  : CORE_VID1 ==> VCCIN_AUX_VID1 */
	PAD_CFG_NF(GPP_B1, NONE, DEEP, NF1),
	/* B2  : NC */
	PAD_NC(GPP_B2, NONE),
	/* B3  : NC */
	PAD_NC(GPP_B3, NONE),
	/* B4  : NC */
	PAD_NC(GPP_B4, NONE),
	/* B5  : I2C2_SDA ==> SOC_I2C_SUB_SDA */
	PAD_CFG_NF(GPP_B5, NONE, DEEP, NF2),
	/* B6  : I2C2_SCL ==> SOC_I2C_SUB_SCL */
	PAD_CFG_NF(GPP_B6, NONE, DEEP, NF2),
	/* B7  : I2C3_SDA ==> SOC_I2C_AUDIO_SDA */
	PAD_CFG_NF(GPP_B7, NONE, DEEP, NF2),
	/* B8  : I2C3_SCL ==> SOC_I2C_AUDIO_SCL */
	PAD_CFG_NF(GPP_B8, NONE, DEEP, NF2),
	/* B9  : Not available */
	PAD_NC(GPP_B9, NONE),
	/* B10 : Not available */
	PAD_NC(GPP_B10, NONE),
	/* B11 : PMCALERT# ==> EN_PP3300_WLAN_X */
	PAD_CFG_GPO(GPP_B11, 1, DEEP),
	/* B12 : SLP_S0# ==> SLP_S0_L */
	PAD_CFG_NF(GPP_B12, NONE, DEEP, NF1),
	/* B13 : PLTRST# ==> PLT_RST_L */
	PAD_CFG_NF(GPP_B13, NONE, DEEP, NF1),
	/* B14 : SPKR ==> GPP_B14_STRAP */
	PAD_NC(GPP_B14, NONE),
	/* B15 : NC */
	PAD_NC(GPP_B15, NONE),
	/* B16 : I2C5_SDA ==> SOC_I2C_TCHPAD_SDA */
	PAD_CFG_NF(GPP_B16, NONE, DEEP, NF2),
	/* B17 : I2C5_SCL ==> SOC_I2C_TCHPAD_SCL */
	PAD_CFG_NF(GPP_B17, NONE, DEEP, NF2),
	/* B18 : GPP_B18 ==> GPP_B18_STRAP */
	PAD_NC(GPP_B18, NONE),
	/* B19 : Not available */
	PAD_NC(GPP_B19, NONE),
	/* B20 : Not available */
	PAD_NC(GPP_B20, NONE),
	/* B21 : Not available */
	PAD_NC(GPP_B21, NONE),
	/* B22 : Not available */
	PAD_NC(GPP_B22, NONE),
	/* B23 : SML1ALERT# ==> PCHHOT_ODL_STRAP */
	PAD_NC(GPP_B23, NONE),

	/* C0  : SMBCLK ==> EN_PP3300_TCHSCR_X */
	PAD_CFG_GPO(GPP_C0, 1, DEEP),
	/* C1  : SMBDATA ==> TCHSCR_RST_L */
	PAD_CFG_GPO(GPP_C1, 0, DEEP),
	/* C2  : SMBALERT# ==> GPP_C2_STRAP */
	PAD_NC(GPP_C2, NONE),
	/* C3  : SML0CLK ==> EN_PP3300_UCAM_X */
	PAD_CFG_GPO(GPP_C3, 1, DEEP),
	/* C4  : NC */
	PAD_NC(GPP_C4, NONE),
	/* C5  : SML0ALERT# ==> GPP_C5_STRAP */
	PAD_NC(GPP_C5, NONE),
	/* C6  : SML1CLK ==> TCHSCR_REPORT_EN */
	PAD_CFG_GPO(GPP_C6, 0, DEEP),
	/* C7  : SML1DATA ==> TCHSCR_INT_ODL */
	PAD_CFG_GPI_APIC(GPP_C7, NONE, PLTRST, LEVEL, INVERT),

	/* D0  : NC */
	PAD_NC(GPP_D0, NONE),
	/* D1  : NC */
	PAD_NC(GPP_D1, NONE),
	/* D2  : NC */
	PAD_NC(GPP_D2, NONE),
	/* D3  : ISH_GP3 ==> WCAM_RST_L */
	PAD_CFG_GPO(GPP_D3, 0, DEEP),
	/* D4  : IMGCLKOUT0 ==> BT_DISABLE_L */
	PAD_CFG_GPO(GPP_D4, 1, DEEP),
	/* D5  : NC */
	PAD_NC(GPP_D5, NONE),
	/* D6  : SRCCLKREQ1# ==> WWAN_EN */
	PAD_CFG_GPO(GPP_D6, 1, DEEP),
	/* D7  : SRCCLKREQ2# ==> WLAN_CLKREQ_ODL */
	PAD_CFG_NF(GPP_D7, NONE, DEEP, NF1),
	/* D8  : SRCCLKREQ3# ==> SD_CLKREQ_ODL */
	PAD_CFG_NF(GPP_D8, NONE, DEEP, NF1),
	/* D9  : NC */
	PAD_NC(GPP_D9, NONE),
	/* D10 : ISH_SPI_CLK ==> GPP_D10_STRAP */
	PAD_NC(GPP_D10, NONE),
	/* D11 : NC */
	PAD_NC(GPP_D11, NONE),
	/* D12 : ISH_SPI_MOSI ==> GPP_D12_STRAP */
	PAD_NC(GPP_D12, NONE),
	/* D13 : NC */
	PAD_NC(GPP_D13, NONE),
	/* D14 : NC */
	PAD_NC(GPP_D14, NONE),
	/* D15 : ISH_UART0_RTS# ==> EN_PP2800_WCAM_X */
	PAD_CFG_GPO(GPP_D15, 0, DEEP),
	/* D16 : ISH_UART0_CTS# ==> EN_PP1800_PP1200_WCAM_X */
	PAD_CFG_GPO(GPP_D16, 0, DEEP),
	/* D17 : NC */
	PAD_NC(GPP_D17, NONE),
	/* D18 : NC */
	PAD_NC(GPP_D18, NONE),
	/* D19 : I2S_MCLK1_OUT ==> I2S_MCLK_R */
	PAD_CFG_NF(GPP_D19, NONE, DEEP, NF1),

	/* E0  : NC */
	PAD_NC(GPP_E0, NONE),
	/* E1  : THC0_SPI1_IO2 ==> MEM_STRAP_0 */
	PAD_CFG_GPI(GPP_E1, NONE, DEEP),
	/* E2  : THC0_SPI1_IO3 ==> MEM_STRAP_1 */
	PAD_CFG_GPI(GPP_E2, NONE, DEEP),
	/* E3  : PROC_GP0 ==> MEM_STRAP_2 */
	PAD_CFG_GPI(GPP_E3, NONE, DEEP),
	/* E4  : NC */
	PAD_NC(GPP_E4, NONE),
	/* E5  : NC */
	PAD_NC(GPP_E5, NONE),
	/* E6  : THC0_SPI1_RST# ==> GPP_E6_STRAP */
	PAD_NC(GPP_E6, NONE),
	/* E7  : NC */
	PAD_NC(GPP_E7, NONE),
	/* E8  : GPP_E8 ==> WLAN_DISABLE_L */
	PAD_CFG_GPO(GPP_E8, 1, DEEP),
	/* E9  : NC */
	PAD_NC(GPP_E9, NONE),
	/* E10 : NC */
	PAD_NC(GPP_E10, NONE),
	/* E11 : NC */
	PAD_NC(GPP_E11, NONE),
	/* E12 : THC0_SPI1_IO1 ==> SOC_WP_OD */
	PAD_CFG_GPI_GPIO_DRIVER(GPP_E12, NONE, DEEP),
	/* E13 : NC */
	PAD_NC(GPP_E13, NONE),
	/* E14 : DDSP_HPDA ==> EDP_HPD */
	PAD_CFG_NF(GPP_E14, NONE, DEEP, NF1),
	/* E15 : NC */
	PAD_NC(GPP_E15, NONE),
	/* E16 : NC */
	PAD_NC(GPP_E16, NONE),
	/* E17 : NC */
	PAD_NC(GPP_E17, NONE),
	/* E18 : NC */
	PAD_NC(GPP_E18, NONE),
	/* E19 : DDP1_CTRLDATA ==> GPP_E19_STRAP */
	PAD_NC(GPP_E19, NONE),
	/* E20 : DDP2_CTRLCLK ==> HDMI_DDC_SCL */
	PAD_CFG_NF(GPP_E20, NONE, DEEP, NF1),
	/* E21 : DDP2_CTRLDATA ==> HDMI_DDC_SDA_STRAP */
	PAD_CFG_NF(GPP_E21, NONE, DEEP, NF1),
	/* E22 : DDPA_CTRLCLK ==> USB_C0_AUX_DC_P */
	PAD_CFG_NF(GPP_E22, NONE, DEEP, NF6),
	/* E23 : DDPA_CTRLDATA ==> USB_C0_AUX_DC_N */
	PAD_CFG_NF(GPP_E23, NONE, DEEP, NF6),

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
	/* F5  : CRF_XTAL_CLKREQ ==> CNV_CLKREQ0 */
	PAD_CFG_NF(GPP_F5, NONE, DEEP, NF3),
	/* F6  : CNV_PA_BLANKING ==> WLAN_WWAN_COEX_3 */
	PAD_CFG_NF(GPP_F6, NONE, DEEP, NF1),
	/* F7  : GPP_F7 ==> GPP_F7_STRAP */
	PAD_NC(GPP_F7, NONE),
	/* F8  : Not available */
	PAD_NC(GPP_F8, NONE),
	/* F9  : Not available */
	PAD_NC(GPP_F9, NONE),
	/* F10 : GPP_F10 ==> GPP_F10_STRAP */
	PAD_NC(GPP_F10, NONE),
	/* F11 : NC */
	PAD_NC(GPP_F11, NONE),
	/* F12 : GSXDOUT ==> WWAN_RST_L */
	PAD_CFG_GPO(GPP_F12, 1, DEEP),
	/* F13 : GSXSLOAD ==> SOC_PEN_DETECT_R_ODL */
	PAD_CFG_GPI_GPIO_DRIVER(GPP_F13, NONE, DEEP),
	/* F14 : GSXDIN ==> TCHPAD_INT_ODL */
	PAD_CFG_GPI_IRQ_WAKE(GPP_F14, NONE, PLTRST, LEVEL, INVERT),
	/* F15 : GSXSRESET# ==> SOC_PEN_DETECT_ODL */
	PAD_CFG_GPI_SCI_HIGH(GPP_F15, NONE, DEEP, EDGE_SINGLE),
	/* F16 : NC */
	PAD_NC(GPP_F16, NONE),
	/* F17 : THC1_SPI2_RST# ==> EC_SOC_WAKE_ODL */
	PAD_CFG_GPI_SCI(GPP_F17, NONE, DEEP, LEVEL, INVERT),
	/* F18 : THC1_SPI2_INT# ==> EC_IN_RW_OD */
	PAD_CFG_GPI(GPP_F18, NONE, DEEP),
	/* F19 : Not available */
	PAD_NC(GPP_F19, NONE),
	/* F20 : Not available */
	PAD_NC(GPP_F20, NONE),
	/* F21 : Not available */
	PAD_NC(GPP_F21, NONE),
	/* F22 : NC */
	PAD_NC(GPP_F22, NONE),
	/* F23 : V1P05_CTRL ==> V1P05EXT_CTRL */
	PAD_CFG_NF(GPP_F23, NONE, DEEP, NF1),

	/* H0  : GPP_H0_STRAP */
	PAD_NC(GPP_H0, NONE),
	/* H1  : GPP_H1_STRAP */
	PAD_NC(GPP_H1, NONE),
	/* H2  : GPP_H2_STRAP */
	PAD_NC(GPP_H2, NONE),
	/* H3  : SX_EXIT_HOLDOFF# ==> WLAN_PCIE_WAKE_ODL */
	PAD_CFG_GPI_SCI_LOW(GPP_H3, NONE, DEEP, EDGE_SINGLE),
	/* H4  : I2C0_SDA ==> SOC_I2C_GSC_SDA */
	PAD_CFG_NF(GPP_H4, NONE, DEEP, NF1),
	/* H5  : I2C0_SCL ==> SOC_I2C_GSC_SCL */
	PAD_CFG_NF(GPP_H5, NONE, DEEP, NF1),
	/* H6  : I2C1_SDA ==> SOC_I2C_TCHSCR_SDA */
	PAD_CFG_NF(GPP_H6, NONE, DEEP, NF1),
	/* H7  : I2C1_SCL ==> SOC_I2C_TCHSCR_SCL */
	PAD_CFG_NF(GPP_H7, NONE, DEEP, NF1),
	/* H8  : CNV_MFUART2_RXD ==> WLAN_WWAN_COEX_1 */
	PAD_CFG_NF(GPP_H8, NONE, DEEP, NF2),
	/* H9  : CNV_MFUART2_TXD ==> WLAN_WWAN_COEX_2 */
	PAD_CFG_NF(GPP_H9, NONE, DEEP, NF2),
	/* H10 : UART0_RXD ==> UART_SOC_RX_DBG_TX */
	PAD_CFG_NF(GPP_H10, NONE, DEEP, NF2),
	/* H11 : UART0_TXD ==> UART_SOC_TX_DBG_RX */
	PAD_CFG_NF(GPP_H11, NONE, DEEP, NF2),
	/* H12 : UART0_RTS# ==> SD_PERST_L */
	PAD_CFG_GPO(GPP_H12, 1, DEEP),
	/* H13 : UART0_CTS# ==> EN_PP3300_SD_X */
	PAD_CFG_GPO(GPP_H13, 1, DEEP),
	/* H14 : Not available */
	PAD_NC(GPP_H14, NONE),
	/* H15 : NC */
	PAD_NC(GPP_H15, NONE),
	/* H16 : Not available */
	PAD_NC(GPP_H16, NONE),
	/* H17 : NC */
	PAD_NC(GPP_H17, NONE),
	/* H18 : PROC_C10_GATE# ==> CPU_C10_GATE_L */
	PAD_CFG_NF(GPP_H18, NONE, DEEP, NF1),
	/* H19 : SRCCLKREQ4# ==> SOC_I2C_SUB_INT_ODL */
	PAD_CFG_GPI_APIC(GPP_H19, NONE, PLTRST, LEVEL, NONE),
	/* H20 : IMGCLKOUT1 ==> WLAN_PERST_L */
	PAD_CFG_GPO(GPP_H20, 1, DEEP),
	/* H21 : NC */
	PAD_NC(GPP_H21, NONE),
	/* H22 : IMGCLKOUT3 ==> WCAM_MCLK_R */
	PAD_CFG_NF(GPP_H22, NONE, DEEP, NF1),
	/* H23 : GPP_H23 ==> WWAN_SAR_DETECT_ODL */
	PAD_CFG_GPO(GPP_H23, 1, DEEP),

	/* R0  : I2S0_SCLK ==> I2S_HP_BCLK_R */
	PAD_CFG_NF(GPP_R0, NONE, DEEP, NF2),
	/* R1  : I2S0_SFRM ==> I2S_HP_LRCK_R */
	PAD_CFG_NF(GPP_R1, NONE, DEEP, NF2),
	/* R2 : I2S0_TXD ==> I2S_HP_AUDIO_STRAP */
	PAD_CFG_NF(GPP_R2, NONE, DEEP, NF2),
	/* R3 : I2S0_RXD ==> I2S_HP_MIC */
	PAD_CFG_NF(GPP_R3, NONE, DEEP, NF2),
	/* R4 : DMIC_CLK_A_0A ==> DMIC_UCAM_CLK_R */
	PAD_CFG_NF(GPP_R4, NONE, DEEP, NF3),
	/* R5 : DMIC_DATA_0A ==> DMIC_UCAM_DATA */
	PAD_CFG_NF(GPP_R5, NONE, DEEP, NF3),
	/* R6 : DMIC_CLK_A_1A ==> DMIC_WCAM_CLK_R */
	PAD_CFG_NF(GPP_R6, NONE, DEEP, NF3),
	/* R7 : DMIC_DATA_1A ==> DMIC_WCAM_DATA */
	PAD_CFG_NF(GPP_R7, NONE, DEEP, NF3),

	/* S0 : I2S1_SCLK ==> I2S_SPK_BCLK_R */
	PAD_CFG_NF(GPP_S0, NONE, DEEP, NF4),
	/* S1 : I2S1_SFRM ==> I2S_SPK_LRCK_R */
	PAD_CFG_NF(GPP_S1, NONE, DEEP, NF4),
	/* S2 : I2S1_TXD ==> I2S_SPK_AUDIO_R */
	PAD_CFG_NF(GPP_S2, NONE, DEEP, NF4),
	/* S3 : I2S1_RXD ==> NC */
	PAD_NC(GPP_S3, NONE),
	/* S4  : NC */
	PAD_NC(GPP_S4, NONE),
	/* S5  : NC */
	PAD_NC(GPP_S5, NONE),
	/* S6  : NC */
	PAD_NC(GPP_S6, NONE),
	/* S7  : NC */
	PAD_NC(GPP_S7, NONE),

	/* I5  : NC */
	PAD_NC(GPP_I5, NONE),
	/* I7  : EMMC_CMD ==> EMMC_CMD */
	PAD_CFG_NF(GPP_I7, NONE, DEEP, NF1),
	/* I8  : EMMC_DATA0 ==> EMMC_D0 */
	PAD_CFG_NF(GPP_I8, NONE, DEEP, NF1),
	/* I9  : EMMC_DATA1 ==> EMMC_D1 */
	PAD_CFG_NF(GPP_I9, NONE, DEEP, NF1),
	/* I10 : EMMC_DATA2 ==> EMMC_D2 */
	PAD_CFG_NF(GPP_I10, NONE, DEEP, NF1),
	/* I11 : EMMC_DATA3 ==> EMMC_D3 */
	PAD_CFG_NF(GPP_I11, NONE, DEEP, NF1),
	/* I12 : EMMC_DATA4 ==> EMMC_D4 */
	PAD_CFG_NF(GPP_I12, NONE, DEEP, NF1),
	/* I13 : EMMC_DATA5 ==> EMMC_D5 */
	PAD_CFG_NF(GPP_I13, NONE, DEEP, NF1),
	/* I14 : EMMC_DATA6 ==> EMMC_D6 */
	PAD_CFG_NF(GPP_I14, NONE, DEEP, NF1),
	/* I15 : EMMC_DATA7 ==> EMMC_D7 */
	PAD_CFG_NF(GPP_I15, NONE, DEEP, NF1),
	/* I16 : EMMC_RCLK ==> EMMC_RCLK */
	PAD_CFG_NF(GPP_I16, NONE, DEEP, NF1),
	/* I17 : EMMC_CLK ==> EMMC_CLK */
	PAD_CFG_NF(GPP_I17, NONE, DEEP, NF1),
	/* I18 : EMMC_RESET# ==> EMMC_RST_L */
	PAD_CFG_NF(GPP_I18, NONE, DEEP, NF1),

	/* GPD0  : BATLOW# ==> SOC_BATLOW_L */
	PAD_CFG_NF(GPD0, NONE, DEEP, NF1),
	/* GPD1  : ACPRESENT ==> SOC_ACPRESENT */
	PAD_CFG_NF(GPD1, NONE, DEEP, NF1),
	/* GPD2  : EC_SOC_INT_ODL */
	PAD_CFG_GPI_APIC(GPD2, NONE, PLTRST, LEVEL, INVERT),
	/* GPD3  : PWRBTN# ==> EC_SOC_PWR_BTN_ODL */
	PAD_CFG_NF(GPD3, NONE, DEEP, NF1),
	/* GPD4  : SLP_S3# ==> SLP_S3_L */
	PAD_CFG_NF(GPD4, NONE, DEEP, NF1),
	/* GPD5  : SLP_S4# ==> SLP_S4_L */
	PAD_CFG_NF(GPD5, NONE, DEEP, NF1),
	/* GPD6  : SLP_A# ==> NC */
	PAD_NC(GPD6, NONE),
	/* GPD7  : GPD7_STRAP */
	PAD_NC(GPD7, NONE),
	/* GPD8  : SUSCLK ==> PCH_SUSCLK */
	PAD_CFG_NF(GPD8, NONE, DEEP, NF1),
	/* GPD9  : NC */
	PAD_NC(GPD9, NONE),
	/* GPD10 : SLP_S5# ==> NC */
	PAD_NC(GPD10, NONE),
	/* GPD11 : NC */
	PAD_NC(GPD11, NONE),
};

/* Early pad configuration in bootblock */
static const struct pad_config early_gpio_table[] = {
	/* A13 : GPP_A13 ==> GSC_SOC_INT_ODL */
	PAD_CFG_GPI_APIC(GPP_A13, NONE, PLTRST, LEVEL, INVERT),
	/* E12 : THC0_SPI1_IO1 ==> SOC_WP_OD */
	PAD_CFG_GPI_GPIO_DRIVER(GPP_E12, NONE, DEEP),
	/* F18 : THC1_SPI2_INT# ==> EC_IN_RW_OD */
	PAD_CFG_GPI(GPP_F18, NONE, DEEP),
	/* H4  : I2C0_SDA ==> SOC_I2C_GSC_SDA */
	PAD_CFG_NF(GPP_H4, NONE, DEEP, NF1),
	/* H5  : I2C0_SCL ==> SOC_I2C_GSC_SCL */
	PAD_CFG_NF(GPP_H5, NONE, DEEP, NF1),
	/* H10 : UART0_RXD ==> UART_SOC_RX_DBG_TX */
	PAD_CFG_NF(GPP_H10, NONE, DEEP, NF2),
	/* H11 : UART0_TXD ==> UART_SOC_TX_DBG_RX */
	PAD_CFG_NF(GPP_H11, NONE, DEEP, NF2),
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
DECLARE_CROS_GPIOS(cros_gpios);

const struct pad_config *__weak variant_romstage_gpio_table(size_t *num)
{
	*num = 0;
	return NULL;
}

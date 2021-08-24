/* Initially copied from System76: src/mainboard/system76/cml-u/acpi */
/* SPDX-License-Identifier: GPL-2.0-only */
/* This file is part of the coreboot project. */

OperationRegion (ERAM, EmbeddedControl, Zero, 0x0FF)
Field (ERAM, ByteAcc, Lock, Preserve)
{
	NMSG,   8,
	SLED,   4,
	Offset (0x02),
	MODE,   1,
	FAN0,   1,
	TME0,   1,
	TME1,   1,
	FAN1,   1,
	    ,   2,
	Offset (0x03),
	LSTE,   1,
	LSW0,   1,
	LWKE,   1,
	WAKF,   1,
	    ,   2,
	PWKE,   1,
	MWKE,   1,
	AC0,    8,
	PSV,    8,
	CRT,    8,
	TMP,    8,
	AC1,    8,
	BBST,   8,
	DPTT,   8,
	DPT1,   8,
	Offset (0x0D),
	Offset (0x0E),
	SLPT,   8,
	SWEJ,   1,
	SWCH,   1,
	Offset (0x10),
	ADP,    1,
	AFLT,   1,
	BAT0,   1,
	BAT1,   1,
	    ,   3,
	PWOF,   1,
	WFNO,   8,
	BPU0,   32,
	BDC0,   32,
	BFC0,   32,
	BTC0,   32,
	BDV0,   32,
	BST0,   32,
	BPR0,   32,
	BRC0,   32,
	BPV0,   32,
	BTP0,   16,
	BRS0,   16,
	BCW0,   32,
	BCL0,   32,
	BCG0,   32,
	BG20,   32,
	BMO0,   64,
	BIF0,   64,
	BSN0,   32,
	BTY0,   64,
	Offset (0x67),
	Offset (0x68),
	ECOS,   8,
	LNXD,   8,
	ECPS,   8,
	Offset (0x6C),
	BTMP,   16,
	EVTN,   8,
	Offset (0x72),
	PRCL,   8,
	PRC0,   8,
	PRC1,   8,
	PRCM,   8,
	PRIN,   8,
	PSTE,   8,
	PCAD,   8,
	PEWL,   8,
	PWRL,   8,
	PECD,   8,
	PEHI,   8,
	PECI,   8,
	PEPL,   8,
	PEPM,   8,
	PWFC,   8,
	PECC,   8,
	PDT0,   8,
	PDT1,   8,
	PDT2,   8,
	PDT3,   8,
	PRFC,   8,
	PRS0,   8,
	PRS1,   8,
	PRS2,   8,
	PRS3,   8,
	PRS4,   8,
	PRCS,   8,
	PEC0,   8,
	PEC1,   8,
	PEC2,   8,
	PEC3,   8,
	CMDR,   8,
	CVRT,   8,
	GTVR,   8,
	FANT,   8,
	SKNT,   8,
	AMBT,   8,
	MCRT,   8,
	DIM0,   8,
	DIM1,   8,
	PMAX,   8,
	PPDT,   8,
	PECH,   8,
	PMDT,   8,
	TSD0,   8,
	TSD1,   8,
	TSD2,   8,
	TSD3,   8,
	CPUP,   16,
	MCHP,   16,
	SYSP,   16,
	CPAP,   16,
	MCAP,   16,
	SYAP,   16,
	CFSP,   16,
	CPUE,   16,
	Offset (0xC6),
	Offset (0xC7),
	VGAT,   8,
	OEM1,   8,
	OEM2,   8,
	OEM3,   16,
	OEM4,   8,
	OEM5,   8,
	DUT1,   8,
	DUT2,   8,
	RPM1,   16,
	RPM2,   16,
	RPM4,   16,
	Offset (0xD7),
	DTHL,   8,
	DTBP,   8,
	AIRP,   8,
	WINF,   8,
	RINF,   8,
	Offset (0xDD),
	INF2,   8,
	MUTE,   1,
	Offset (0xE0),
	RPM3,   16,
	ECKS,   8,
	Offset (0xE4),
	    ,   4,
	XTUF,   1,
	EP12,   1,
	FN_G,   1,
	Offset (0xE5),
	INF3,   8,
	DFAL,   1,
	DFAE,   1,
	Offset (0xE7),
	XFAN,   8,
	    ,   2,
	MAXQ,   1,
	Offset (0xE9),
	EKBS,   1,
	Offset (0xEA),
	    ,   4,
	MSFG,   1,
	RCHG,   1,
	ACOT,   1,
	S5FG,   1,
	    ,   3,
	DGPT,   1,
	TOPN,   1,
	    ,   1,
	APRD,   1,
	Offset (0xF0),
	PL1T,   16,
	PL2T,   16,
	TAUT,   8,
	Offset (0xF8),
	FCMD,   8,
	FDAT,   8,
	FBUF,   8,
	FBF1,   8,
	FBF2,   8,
	FBF3,   8
}

OperationRegion (SIO, SystemIO, 0x2e, 0x02)
Field (SIO, ByteAcc, Lock, Preserve)
{
	SIOI,   8,
	SIOD,   8
}

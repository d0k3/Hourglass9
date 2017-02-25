#pragma once

#include "common.h"

// force slot 0x04 for CTRNAND padgen
#define PG_FORCESLOT4 (1<<0)

// anypadgen tags
#define AP_USE_NAND_CTR     (1<<0)
#define AP_USE_SD_CTR       (1<<1)

typedef struct {
    u32  keyslot;
    u32  setKeyY;
    u8   ctr[16];
    u8   keyY[16];
    u32  size_mb;
    u32  size_b; // only use this when size_mb == zero
    u32  mode;
    char filename[180];
} __attribute__((packed, aligned(16))) PadInfo;

typedef struct {
    u8   ctr[16];
    u32  size_mb;
    char filename[180];
} __attribute__((packed)) SdInfoEntry;

typedef struct {
    u32 n_entries;
    SdInfoEntry entries[MAX_ENTRIES];
} __attribute__((packed, aligned(16))) SdInfo;

typedef struct {
    u8   ctr[16];
    u8   keyY[16];
    u32  size_mb;
    u32  size_b; // this is only used if it is non-zero
    u32  ncchFlag7;
    u32  ncchFlag3;
    u64  titleId;
    char filename[112];
} __attribute__((packed)) NcchInfoEntry;

typedef struct {
    u32 padding;
    u32 ncch_info_version;
    u32 n_entries;
    u8  reserved[4];
    NcchInfoEntry entries[MAX_ENTRIES];
} __attribute__((packed, aligned(16))) NcchInfo;

typedef struct {
    u8   keyslot;
    u8   setNormalKey;
    u8   setKeyX;
    u8   setKeyY;
    u32  size_b;
    u32  flags;
    u32  mode;
    u8   ctr[16];
    u8   normalKey[16];
    u8   keyX[16];
    u8   keyY[16];
    char filename[48];
} __attribute__((packed)) AnyPadInfoEntry;

typedef struct {
    u32 n_entries;
    u8  reserved[12];
    AnyPadInfoEntry entries[MAX_ENTRIES];
} __attribute__((packed, aligned(16))) AnyPadInfo;


u32 CreatePad(PadInfo *info);
u32 SdInfoGen(SdInfo* info, const char* base_path);

// --> FEATURE FUNCTIONS <--
u32 NcchPadgen(u32 param);
u32 SdPadgen(u32 param);
u32 SdPadgenDirect(u32 param);
u32 AnyPadgen(u32 param);

u32 CtrNandPadgen(u32 param);
u32 TwlNandPadgen(u32 param);
u32 Firm0Firm1Padgen(u32 param);

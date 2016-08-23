#pragma once

#include "decryptor/nand.h"
#include "common.h"

#define MAX_ENTRIES 1024

typedef struct {
    char name[32];
    u32 tid_high;
    u32 tid_low[6];
} TitleListInfo;

u32 SeekFileInNand(u32* offset, u32* size, const char* path, PartitionInfo* partition);
u32 SeekTitleInNandDb(u32 tid_high, u32 tid_low, u32* tmd_id);
u32 DebugSeekTitleInNand(u32* offset_tmd, u32* size_tmd, u32* offset_app, u32* size_app, TitleListInfo* title_info, u32 max_cnt);
u32 GetRegion(void);

// --> FEATURE FUNCTIONS <--
u32 DumpHealthAndSafety(u32 param);
u32 InjectHealthAndSafety(u32 param);
u32 DumpNcchFirms(u32 param);

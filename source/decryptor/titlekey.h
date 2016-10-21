#pragma once

#include "common.h"

#define MAX_ENTRIES 1024

#define TK_ENCRYPTED (1<<0)
#define TK_TICKETS   (1<<1)

typedef struct {
    u32 commonKeyIndex;
    u8  reserved[4];
    u8  titleId[8];
    u8  titleKey[16];
} __attribute__((packed)) TitleKeyEntry;

typedef struct {
    u32 n_entries;
    u8  reserved[12];
    TitleKeyEntry entries[MAX_ENTRIES];
} __attribute__((packed, aligned(16))) TitleKeysInfo;


u32 CryptTitlekey(TitleKeyEntry* entry, bool encrypt);

// --> FEATURE FUNCTIONS <--
u32 CryptTitlekeysFile(u32 param);
u32 DumpTicketsTitlekeys(u32 param);

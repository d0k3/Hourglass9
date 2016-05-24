#pragma once

#include "decryptor/decryptor.h"
#include "decryptor/nand.h"
#include "common.h"

#define MAX_ENTRIES 1024

typedef struct {
    u64 titleId;
    u8 external_seed[16];
    u8 reserved[8];
} __attribute__((packed)) SeedInfoEntry;

typedef struct {
    u32 n_entries;
    u8 padding[12];
    SeedInfoEntry entries[MAX_ENTRIES];
} __attribute__((packed)) SeedInfo;

typedef struct {
    u8  signature[0x100];
    u8  magic[0x4];
    u32 size;
    u64 partitionId;
    u16 makercode;
    u16 version;
    u8  reserved0[0x4];
    u64 programId;
    u8  reserved1[0x10];
    u8  hash_logo[0x20];
    char productCode[0x10];
    u8  hash_exthdr[0x20];
    u32 size_exthdr;
    u8  reserved2[0x4];
    u8  flags[0x8];
    u32 offset_plain;
    u32 size_plain;
    u32 offset_logo;
    u32 size_logo;
    u32 offset_exefs;
    u32 size_exefs;
    u32 size_exefs_hash;
    u8  reserved3[0x4];
    u32 offset_romfs;
    u32 size_romfs;
    u32 size_romfs_hash;
    u8  reserved4[0x4];
    u8  hash_exefs[0x20];
    u8  hash_romfs[0x20];
} __attribute__((packed, aligned(16))) NcchHeader;

typedef struct {
    char name[32];
    u32 tid_high;
    u32 tid_low[6];
} TitleListInfo;

// Crypto stuff
u32 GetNcchCtr(u8* ctr, NcchHeader* ncch, u8 sub_id);
u32 CryptSdToSd(const char* filename, u32 offset, u32 size, CryptBufferInfo* info, bool handle_offset16);
u32 GetHashFromFile(const char* filename, u32 offset, u32 size, u8* hash);
u32 CheckHashFromFile(const char* filename, u32 offset, u32 size, const u8* hash);
u32 CryptNcch(const char* filename, u32 offset, u32 size, u64 seedId, u8* encrypt_flags);

// NAND FAT stuff
u32 SeekFileInNand(u32* offset, u32* size, const char* path, PartitionInfo* partition);
u32 SeekTitleInNandDb(u32* tid_low, u32* tmd_id, TitleListInfo* title_info);
u32 DebugSeekTitleInNand(u32* offset_tmd, u32* size_tmd, u32* offset_app, u32* size_app, TitleListInfo* title_info, u32 max_cnt);

// --> FEATURE FUNCTIONS <--
u32 DumpHealthAndSafety(u32 param);
u32 InjectHealthAndSafety(u32 param);

#pragma once

#include "common.h"

#define NAND_SECTOR_SIZE 0x200
#define SECTORS_PER_READ (BUFFER_MAX_SIZE / NAND_SECTOR_SIZE)

// NAND partition identifiers
#define P_TWLN      (1<<0)
#define P_TWLP      (1<<1)
#define P_AGBSAVE   (1<<2)
#define P_FIRM0     (1<<3)
#define P_FIRM1     (1<<4)
#define P_CTRNAND   (1<<5)
#define P_CTRFULL   (1<<8)

// options for NAND backup & restore
#define NB_MINSIZE  (1<<10)
#define NR_NOCHECKS (1<<11)
#define NR_KEEPA9LH (1<<12)

// these three are not handled by the feature functions
// they have to be handled by the menu system
#define N_EMUNAND   (1<<28)
#define N_FORCEEMU  (1<<29)
#define N_A9LHWRITE (1<<30)
#define N_NANDWRITE (1<<31)

// return values for the CheckEmuNAND() function
#define EMUNAND_NOT_READY 0 // must be zero
#define EMUNAND_READY     1
#define EMUNAND_GATEWAY   2
#define EMUNAND_REDNAND   3

typedef struct {
    char name[16];
    u8  magic[8];
    u32 offset;
    u32 size;
    u32 keyslot;
    u32 mode;
} __attribute__((packed)) PartitionInfo;

PartitionInfo* GetPartitionInfo(u32 partition_id);
u32 GetNandCtr(u8* ctr, u32 offset);

u32 CheckFirmSize(const u8* firm, u32 f_size);
u32 DecryptFirmArm9Mem(u8* firm, u32 f_size);

u32 OutputFileNameSelector(char* filename, const char* basename, char* extension);
u32 InputFileNameSelector(char* filename, const char* basename, char* extension, u8* magic, u32 msize, u32 fsize, bool accept_bigger);

u32 GetNandHeader(u8* header);
u32 PutNandHeader(u8* header);

u32 DecryptNandToMem(u8* buffer, u32 offset, u32 size, PartitionInfo* partition);
u32 DecryptNandToFile(const char* filename, u32 offset, u32 size, PartitionInfo* partition, u8* sha256);
u32 EncryptMemToNand(u8* buffer, u32 offset, u32 size, PartitionInfo* partition);
u32 EncryptFileToNand(const char* filename, u32 offset, u32 size, PartitionInfo* partition);

// --> FEATURE FUNCTIONS <--
u32 CheckEmuNand(void);
u32 SetNand(bool set_emunand, bool force_emunand);

u32 DumpNand(u32 param);
u32 DumpNandHeader(u32 param);
u32 RestoreNand(u32 param);
u32 RestoreNandHeader(u32 param);
u32 DecryptNandPartition(u32 param);
u32 InjectNandPartition(u32 param);
u32 DecryptSector0x96(u32 param);
u32 InjectSector0x96(u32 param);

u32 DumpGbaVcSave(u32 param);
u32 InjectGbaVcSave(u32 param);
u32 DecryptFirmArm9File(u32 param);
u32 ValidateNandDump(u32 param);

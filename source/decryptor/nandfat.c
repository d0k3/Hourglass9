#include "fs.h"
#include "draw.h"
#include "platform.h"
#include "decryptor/aes.h"
#include "decryptor/sha.h"
#include "decryptor/hashfile.h"
#include "decryptor/game.h"
#include "decryptor/keys.h"
#include "decryptor/nand.h"
#include "decryptor/nandfat.h"

// title list shortcuts - will change if the array changes!
#define TL_HS      (titleList +  3)
#define TL_HS_N    (titleList +  4)

// only a subset, see http://3dbrew.org/wiki/Title_list
// regions: JPN, USA, EUR, CHN, KOR, TWN
TitleListInfo titleList[] = {
    { "System Settings"       , 0x00040010, { 0x00020000, 0x00021000, 0x00022000, 0x00026000, 0x00027000, 0x00028000 } },
    { "Download Play"         , 0x00040010, { 0x00020100, 0x00021100, 0x00022100, 0x00026100, 0x00027100, 0x00028100 } },
    { "Activity Log"          , 0x00040010, { 0x00020200, 0x00021200, 0x00022200, 0x00026200, 0x00027200, 0x00028200 } },
    { "Health&Safety"         , 0x00040010, { 0x00020300, 0x00021300, 0x00022300, 0x00026300, 0x00027300, 0x00028300 } },
    { "Health&Safety (N3DS)"  , 0x00040010, { 0x20020300, 0x20021300, 0x20022300, 0x00000000, 0x20027300, 0x00000000 } },
    { "3DS Camera"            , 0x00040010, { 0x00020400, 0x00021400, 0x00022400, 0x00026400, 0x00027400, 0x00028400 } },
    { "3DS Sound"             , 0x00040010, { 0x00020500, 0x00021500, 0x00022500, 0x00026500, 0x00027500, 0x00028500 } },
    { "Mii Maker"             , 0x00040010, { 0x00020700, 0x00021700, 0x00022700, 0x00026700, 0x00027700, 0x00028700 } },
    { "Streetpass Mii Plaza"  , 0x00040010, { 0x00020800, 0x00021800, 0x00022800, 0x00026800, 0x00027800, 0x00028800 } },
    { "3DS eShop"             , 0x00040010, { 0x00020900, 0x00021900, 0x00022900, 0x00000000, 0x00027900, 0x00028900 } },
    { "Nintendo Zone"         , 0x00040010, { 0x00020B00, 0x00021B00, 0x00022B00, 0x00000000, 0x00000000, 0x00000000 } }
};

// contains all available NCCH firms, see http://3dbrew.org/wiki/Title_list
// N3DS firms first, O3DS FIRM starting at index 4
TitleListInfo firms[] = {
    { "NATIVE_FIRM_N3DS"      , 0x00040138, { 0x20000002, 0x20000002, 0x20000002, 0x20000002, 0x20000002, 0x20000002 } },
    { "SAFE_MODE_FIRM_N3DS"   , 0x00040138, { 0x20000003, 0x20000003, 0x20000003, 0x20000003, 0x20000003, 0x20000003 } },
    { "TWL_FIRM_N3DS"         , 0x00040138, { 0x20000102, 0x20000102, 0x20000102, 0x20000102, 0x20000102, 0x20000102 } },
    { "AGB_FIRM_N3DS"         , 0x00040138, { 0x20000202, 0x20000202, 0x20000202, 0x20000202, 0x20000202, 0x20000202 } },
    { "NATIVE_FIRM"           , 0x00040138, { 0x00000002, 0x00000002, 0x00000002, 0x00000002, 0x00000002, 0x00000002 } },
    { "SAFE_MODE_FIRM"        , 0x00040138, { 0x00000003, 0x00000003, 0x00000003, 0x00000003, 0x00000003, 0x00000003 } },
    { "TWL_FIRM"              , 0x00040138, { 0x00000102, 0x00000102, 0x00000102, 0x00000102, 0x00000102, 0x00000102 } },
    { "AGB_FIRM"              , 0x00040138, { 0x00000202, 0x00000202, 0x00000202, 0x00000202, 0x00000202, 0x00000202 } }
};

NandFileInfo fileList[] = { // first six entries are .dbs, placement corresponds to id
    { "ticket.db",             "ticket.db",             "DBS        TICKET  DB ",                P_CTRNAND },
    { "certs.db",              "certs.db",              "DBS        CERTS   DB ",                P_CTRNAND },
    { "title.db",              "title.db",              "DBS        TITLE   DB ",                P_CTRNAND },
    { "import.db",             "import.db",             "DBS        IMPORT  DB ",                P_CTRNAND },
    { "tmp_t.db",              "tmp_t.db",              "DBS        TMP_T   DB ",                P_CTRNAND },
    { "tmp_i.db",              "tmp_i.db",              "DBS        TMP_I   DB ",                P_CTRNAND },
    { "SecureInfo_A",          "SecureInfo",            "RW         SYS        SECURE~?   ",     P_CTRNAND },
    { "LocalFriendCodeSeed_B", "LocalFriendCodeSeed",   "RW         SYS        LOCALF~?   ",     P_CTRNAND },
    { "rand_seed",             "rand_seed",             "RW         SYS        RAND_S~?   ",     P_CTRNAND },
    { "movable.sed",           "movable.sed",           "PRIVATE    MOVABLE SED",                P_CTRNAND },
    { "seedsave.bin", "seedsave.bin", "DATA       ???????????SYSDATA    0001000F   00000000   ", P_CTRNAND },
    { "nagsave.bin",  "nagsave.bin",  "DATA       ???????????SYSDATA    0001002C   00000000   ", P_CTRNAND },
    { "nnidsave.bin", "nnidsave.bin", "DATA       ???????????SYSDATA    00010038   00000000   ", P_CTRNAND },
    { "friendsave.bin", "friendsave.bin", "DATA       ???????????SYSDATA    00010032   00000000   ", P_CTRNAND },
    { "configsave.bin", "configsave.bin", "DATA       ???????????SYSDATA    00010017   00000000   ", P_CTRNAND }
};


NandFileInfo* GetNandFileInfo(u32 file_id)
{
    u32 file_num = 0;
    for(; !(file_id & (1<<file_num)) && (file_num < 30); file_num++);
    return (file_num >= 30) ? NULL : &(fileList[file_num]);
}

u32 SeekFileInNand(u32* offset, u32* size, const char* path, PartitionInfo* partition)
{
    // poor mans NAND FAT file seeker:
    // - path must be in FAT 8+3 format, without dots or slashes
    //   example: DIR1_______DIR2_______FILENAMEEXT
    // - can't handle long filenames
    // - dirs must not exceed 1024 entries
    // - fragmentation not supported
    
    u8* buffer = BUFFER_ADDRESS;
    u32 p_size = partition->size;
    u32 p_offset = partition->offset;
    u32 fat_pos = 0;
    bool found = false;
    
    if (strnlen(path, 256) % (8+3) != 0)
        return 1;
    
    if (DecryptNandToMem(buffer, p_offset, NAND_SECTOR_SIZE, partition) != 0)
        return 1;
    
    // good FAT header description found here: http://www.compuphase.com/mbr_fat.htm
    u32 fat_start = NAND_SECTOR_SIZE * getle16(buffer + 0x0E);
    u32 fat_count = buffer[0x10];
    u32 fat_size = NAND_SECTOR_SIZE * getle16(buffer + 0x16) * fat_count;
    u32 root_size = getle16(buffer + 0x11) * 0x20;
    u32 cluster_start = fat_start + fat_size + root_size;
    u32 cluster_size = buffer[0x0D] * NAND_SECTOR_SIZE;
    
    for (*offset = p_offset + fat_start + fat_size; strnlen(path, 256) >= 8+3; path += 8+3) {
        if (*offset - p_offset > p_size)
            return 1;
        found = false;
        if (DecryptNandToMem(buffer, *offset, cluster_size, partition) != 0)
            return 1;
        for (u32 i = 0x00; i < cluster_size; i += 0x20) {
            static const char zeroes[8+3] = { 0x00 };
            // skip invisible, deleted and lfn entries
            if ((buffer[i] == '.') || (buffer[i] == 0xE5) || (buffer[i+0x0B] == 0x0F))
                continue;
            else if (memcmp(buffer + i, zeroes, 8+3) == 0)
                return 1;
            u32 p; // search for path in fat folder structure, accept '?' wildcards
            for (p = 0; (p < 8+3) && (path[p] == '?' || buffer[i+p] == path[p]); p++);
            if (p != 8+3) continue;
            // entry found, store offset and move on
            fat_pos = getle16(buffer + i + 0x1A);
            *offset = p_offset + cluster_start + (fat_pos - 2) * cluster_size;
            *size = getle32(buffer + i + 0x1C);
            found = true;
            break;
        }
        if (!found) break;
    }
    
    // check for fragmentation
    if (found && (*size > cluster_size)) {  
        if (fat_size / fat_count > 0x100000) // prevent buffer overflow
            return 1; // fishy FAT table size - should never happen
        if (DecryptNandToMem(buffer, p_offset + fat_start, fat_size / fat_count, partition) != 0)
            return 1;
        for (u32 i = 0; i < (*size - 1) / cluster_size; i++) {
            if (*(((u16*) buffer) + fat_pos + i) != fat_pos + i + 1)
                return 1;
        } // no need to check the files last FAT table entry
    }
    
    return (found) ? 0 : 1;
}

u32 DebugSeekFileInNand(u32* offset, u32* size, const char* filename, const char* path, PartitionInfo* partition)
{
    Debug("Searching for %s...", filename);
    if (SeekFileInNand(offset, size, path, partition) != 0) {
        Debug("Failed!");
        return 1;
    }
    if (*size < 1024)
        Debug("Found at %08X, size %ub", *offset, *size);
    else if (*size < 1024 * 1024)
        Debug("Found at %08X, size %ukB", *offset, *size / 1024);
    else
        Debug("Found at %08X, size %uMB", *offset, *size / (1024*1024));
    
    return 0;
}

u32 SeekTitleInNandDb(u32 tid_high, u32 tid_low, u32* tmd_id)
{
    PartitionInfo* ctrnand_info = GetPartitionInfo(P_CTRNAND);
    u8* titledb = (u8*) 0x20316000;
    
    u32 offset_db;
    u32 size_db;
    if (SeekFileInNand(&offset_db, &size_db, "DBS        TITLE   DB ", ctrnand_info) != 0)
        return 1; // database not found
    if (size_db != 0x64C00)
        return 1; // bad database size
    if (DecryptNandToMem(titledb, offset_db, size_db, ctrnand_info) != 0)
        return 1;
    
    u8* entry_table = titledb + 0x39A80;
    u8* info_data = titledb + 0x44B80;
    if ((getle32(entry_table + 0) != 2) || (getle32(entry_table + 4) != 3))
        return 1; // magic number not found
    *tmd_id = (u32) -1;
    for (u32 i = 0; i < 1000; i++) {
        u8* entry = entry_table + 0xA8 + (0x2C * i);
        u8* info = info_data + (0x80 * i);
        if ((getle32(entry + 0xC) != tid_high) || (getle32(entry + 0x8) != tid_low)) continue; // not a title id match
        if (getle32(entry + 0x4) != 1) continue; // not an active entry
        if ((getle32(entry + 0x18) - i != 0x162) || (getle32(entry + 0x1C) != 0x80) || (getle32(info + 0x08) != 0x40)) continue; // fishy title info / offset
        *tmd_id = getle32(info + 0x14);
        break; 
    }
    
    return (*tmd_id != (u32) -1) ? 0 : 1;
}

u32 DebugSeekTitleInNand(u32* offset_tmd, u32* size_tmd, u32* offset_app, u32* size_app, TitleListInfo* title_info, u32 max_cnt)
{
    PartitionInfo* ctrnand_info = GetPartitionInfo(P_CTRNAND);
    u8* buffer = (u8*) 0x20316000;
    u32 cnt_count = 0;
    u32 tid_high = title_info->tid_high;
    u32 tid_low = 0;
    u32 tmd_id = (u32) -1;
    
    // get correct title id
    u32 region = GetRegion();
    if (region > 6)
        return 1;
    tid_low = title_info->tid_low[(region >= 3) ? region - 1 : region];
    
    // try the correct one first, others after
    Debug("Searching title \"%s\"...", title_info->name);
    for (int r = -1; r < 6; r++) {
        if (r >= 0)
            tid_low = title_info->tid_low[r];
        if ((tid_low == 0) || ((u32) r == ((region >= 3) ? region - 1 : region)))
            continue;
        Debug("Trying title ID %08lX%08lX (region %u)", tid_high, tid_low, (r < 0) ? region : (u32) ((r < 3) ? r : r + 1));
        Debug("Method 1: Search in title.db...");
        if (SeekTitleInNandDb(tid_high, tid_low, &tmd_id) == 0) {
            char path[64];
            sprintf(path, "TITLE      %08lX   %08lX   CONTENT    %08lXTMD", tid_high, tid_low, tmd_id);
            if (SeekFileInNand(offset_tmd, size_tmd, path, ctrnand_info) != 0)
                tmd_id = (u32) -1;
        }
        if (tmd_id == (u32) -1) {
            Debug("Method 2: Search in file system...");
            char path[64];
            sprintf(path, "TITLE      %08lX   %08lX   CONTENT    ????????TMD", tid_high, tid_low);
            if (SeekFileInNand(offset_tmd, size_tmd, path, ctrnand_info) != 0) {
                tid_low = 0;
                continue;
            }
        }
        break;
    }
    
    if (!tid_low) {
        Debug("Failed!");
        return 1;
    }
    Debug("Found title ID %08X%08X", tid_high, tid_low);
    
    Debug("TMD0 found at %08X, size %ub", *offset_tmd, *size_tmd);
    if ((*size_tmd < 0xC4 + (0x40 * 0x24)) || (*size_tmd > 0x4000)) {
        Debug("TMD has bad size!");
        return 1;
    }
    if (DecryptNandToMem(buffer, *offset_tmd, *size_tmd, ctrnand_info) != 0)
        return 1;
    u32 size_sig = (buffer[3] == 3) ? 0x240 : (buffer[3] == 4) ? 0x140 : (buffer[3] == 5) ? 0x80 : 0;         
    if ((size_sig == 0) || (memcmp(buffer, "\x00\x01\x00", 3) != 0)) {
        Debug("Unknown signature type: %08X", getbe32(buffer));
        return 1;
    }
    cnt_count = getbe16(buffer + size_sig + 0x9E);
    u32 size_tmd_expected = size_sig + 0xC4 + (0x40 * 0x24) + (cnt_count * 0x30);
    if (*size_tmd < size_tmd_expected) {
        Debug("TMD bad size (expected %ub)!", size_tmd_expected );
        return 1;
    }
    buffer += size_sig + 0xC4 + (0x40 * 0x24);
    
    for (u32 i = 0; i < cnt_count && i < max_cnt; i++) {
        char path[64];
        u32 cnt_id = getbe32(buffer + (0x30 * i));
        if (i >= max_cnt) {
            Debug("APP%i was skipped", i);
            continue;
        }
        sprintf(path, "TITLE      %08lX   %08lX   CONTENT    %08lXAPP", tid_high, tid_low, cnt_id);
        if (SeekFileInNand(offset_app + i, size_app + i, path, ctrnand_info) != 0) {
            Debug("APP%i not found or fragmented!", i);
            return 1;
        }
        Debug("APP%i found at %08X, size %ukB", i, offset_app[i], size_app[i] / 1024);
    }
    
    return 0;
}

u32 FixNandDataId0(void)
{
    static const char zeroes[8+3] = { 0x00 };
    const u32 lfn_pos[13] = { 1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30 };
    u8* buffer = BUFFER_ADDRESS;
    PartitionInfo* ctrnand_info = GetPartitionInfo(P_CTRNAND);
    char id0_key[32 + 1];
    char id0_dir[32 + 1];
    char id0_fat[8 + 3 + 1];
    u32 offset;
    u32 size;
    
    // determine system id0, create filenames
    unsigned int id0_int[4];
    if (GetSystemId0((u8*) id0_int) != 0)
        return 1; // this should never happen
    snprintf(id0_key, 32 + 1, "%08x%08x%08x%08x", id0_int[0], id0_int[1], id0_int[2], id0_int[3]);
    snprintf(id0_fat, 8 + 3 + 1, "%06X~1   ", id0_int[0] >> 8);
    
    // grab the FAT directory object
    u8* dirblock = buffer;
    u32 dirblock_size = 16 * 1024; // 16kB just to be careful
    if ((SeekFileInNand(&offset, &size, "DATA       ", ctrnand_info) != 0) ||
        (DecryptNandToMem(dirblock, offset, dirblock_size, ctrnand_info) != 0))
        return 1;
    // search for first valid directory entry
    u32 base = 0;
    for (base = 0x20; base < dirblock_size; base += 0x20) {
        // skip invisible, deleted and lfn entries
        if ((dirblock[base] == '.') || (dirblock[base] == 0xE5) || (dirblock[base+0x0B] == 0x0F))
            continue;
        else if (memcmp(dirblock + base, zeroes, 8+3) == 0)
            return 1;
        break;
    }
    if (base >= dirblock_size)
        return 1;
    // got a valid entry, make sure it is the only one
    for (u32 pos = base; pos < dirblock_size; pos += 0x20) {
        if ((dirblock[base] == '.') || (dirblock[base] == 0xE5) || (dirblock[base+0x0B] == 0x0F))
            continue;
        else if (memcmp(dirblock + base, zeroes, 8+3) == 0)
            return 1;
    }
    
    // calculate checksum
    u8 checksum = 0;
    for (u32 i = 0; i < 8 + 3; i++)
        checksum = ((checksum >> 1) | (checksum << 7)) + dirblock[base+i];
    
    // now work backwards to put together the LFN
    memset(id0_dir, 0x00, 32 + 1);
    char* id0_ch = id0_dir;
    u32 cb = 1;
    for (u32 pos = base - 0x20; pos > 0; pos -= 0x20) {
        // check entry data (first byte, attributes, checksum)
        if (((dirblock[pos] & 0x3F) != cb++) || (dirblock[pos] & 0x80) ||
            (getbe16(dirblock + pos + 0x0B) != 0x0F00) || (getbe16(dirblock + pos + 0x1A) != 0x0000) ||
            (dirblock[pos+0x0D] != checksum))
            return 1;
        u32 idx = 0;
        while (idx < 13) {
            u32 cp = pos + lfn_pos[idx++];
            if (dirblock[cp+1] != 0)
                return 1;
            else if (dirblock[cp] == 0)
                break;
            *(id0_ch++) = dirblock[cp];
            if (id0_ch - id0_dir > 32)
                return 1;
        }
        while (idx < 13) {
            u32 cp = pos + lfn_pos[idx++];
            if ((dirblock[cp] != 0xFF) || (dirblock[cp+1] != 0xFF))
                return 1;
        }
        if (dirblock[pos] & 0x40)
            break;
    }
    
    if (memcmp(id0_key, id0_dir, 32 + 1) == 0) {
        Debug("/DATA/<ID0>: matches, no rename needed");
        return 0;
    }
    
    // calculate new checksum
    checksum = 0;
    for (u32 i = 0; i < 8 + 3; i++)
        checksum = ((checksum >> 1) | (checksum << 7)) + id0_fat[i];
    
    // rename the folder (SFN and LFN)
    memcpy(dirblock + base, id0_fat, 8 + 3);
    id0_ch = id0_key; cb = 1; 
    for (u32 pos = base - 0x20; pos > 0; pos -= 0x20) {
        u32 idx = 0;
        dirblock[pos+0x0D] = checksum;
        while (idx < 13) {
            u32 cp = pos + lfn_pos[idx++];
            dirblock[cp] = *(id0_ch++);
            if (id0_ch - id0_key == 32)
                break;
        }
    }
    
    // inject the directory block back
    if (EncryptMemToNand(dirblock, offset, dirblock_size, ctrnand_info) != 0)
        return 1;
    Debug("/DATA/<ID0>: renamed to match");
    
    return 0;
}

u32 GetRegion(void)
{
    PartitionInfo* p_info = GetPartitionInfo(P_CTRNAND);
    u8 secureinfo[0x200];
    u32 offset;
    u32 size;
    
    if ((SeekFileInNand(&offset, &size, "RW         SYS        SECURE~?   ", p_info) != 0) ||
        (DecryptNandToMem(secureinfo, offset, size, p_info) != 0))
        return 0xF;
    
    return (u32) secureinfo[0x100];
}

u32 GetSerial(char* serial)
{
    static char serial_store[16] = { 0 };
    if (!(*serial_store)) {
        PartitionInfo* p_info = GetPartitionInfo(P_CTRNAND);
        u8 secureinfo[0x200];
        u32 offset;
        u32 size;
        
        if ((SeekFileInNand(&offset, &size, "RW         SYS        SECURE~?   ", p_info) == 0) &&
            (DecryptNandToMem(secureinfo, offset, size, p_info) == 0)) {
            snprintf(serial_store, 16, "%.15s", (char*) (secureinfo + 0x102));
        } else {
            snprintf(serial_store, 16, "UNKNOWN");
        }            
    }
    memcpy(serial, serial_store, 16);
    return 0;
}

u32 GetSystemId0(u8* id0)
{
    PartitionInfo* p_info = GetPartitionInfo(P_CTRNAND);
    u32 shasum[8];
    u8 movable[0x200];
    u8* movableKeyY = movable + 0x110;
    u32 offset;
    u32 size;
    
    if ((SeekFileInNand(&offset, &size, "PRIVATE    MOVABLE SED", p_info) != 0) || (size > 0x200) ||
        (DecryptNandToMem(movable, offset, size, p_info) != 0)) {
        return 1; // this should never happen
    }
    sha_quick(shasum, movableKeyY, 16, SHA256_MODE);
    memcpy(id0, shasum, 16);
    
    return 0;
}

u32 FixCmac(u8* cmac, u8* data, u32 size, u32 keyslot)
{
    u8 lcmac[16] __attribute__((aligned(32)));
    u8 shasum[32];
    
    // calculate cmac (local)
    sha_quick(shasum, data, size, SHA256_MODE);
    use_aeskey(keyslot);
    aes_cmac(shasum, lcmac, 2);
    if (memcmp(lcmac, cmac, 16) != 0) {
        memcpy(cmac, lcmac, 16);
        Debug("CMAC mismatch -> fixed CMAC");
        return 1;
    } else {
        Debug("Validated CMAC okay");
        return 0;
    }
}

u32 FixNandCmac(u32 param) {
    NandFileInfo* f_info = GetNandFileInfo(param);
    PartitionInfo* p_info = GetPartitionInfo(f_info->partition_id);
    u8 data[0x200];
    u8 temp[0x200];
    u32 offset;
    u32 size;
    u64 id = 0;
    
    if (DebugSeekFileInNand(&offset, &size, f_info->name_l, f_info->path, p_info) != 0)
        return 1;
    if (DecryptNandToMem(data, offset, 0x200, p_info) != 0)
        return 1;
    
    if (f_info - fileList < 6) { // .db files
        id = f_info - fileList;
        Debug("CMAC id: %llu", id); 
        memcpy(temp + 0x0, "CTR-9DB0", 8);
        memcpy(temp + 0x8, &id, 4);
        memcpy(temp + 0xC, data + 0x100, 0x100);
        if ((FixCmac(data, temp, 0x10C, 0x0B) != 0) && (EncryptMemToNand(data, offset, 0x200, p_info) != 0))
            return 1;
    } else if (sscanf(f_info->path, "DATA       ???????????SYSDATA    %08llX   00000000   ", &id) == 1) { // system save
        Debug("CMAC id: %08llX", id); 
        if (SetupMovableKeyY(true, 0x30, NULL) != 0)
            return 1;
        memcpy(temp + 0x00, "CTR-SYS0", 8);
        memcpy(temp + 0x08, &id, 8);
        memcpy(temp + 0x10, data + 0x100, 0x100);
        if ((FixCmac(data, temp, 0x110, 0x30) != 0) && (EncryptMemToNand(data, offset, 0x200, p_info) != 0))
            return 1;
    } else if ((param & F_MOVABLE) && (size == 0x140)) { // movable.sed
        if ((FixCmac(data + 0x130, data, 0x130, 0x0B) != 0) && (EncryptMemToNand(data, offset, 0x200, p_info) != 0))
            return 1;
    } else {
        Debug("File has no fixable CMAC");
    }
    
    return 0;
}

u32 ValidateSeed(u8* seed, u64 titleId, u8* hash) {
    u8 valdata[16 + 8];
    u8 sha256sum[32];
    // validate seed
    memcpy(valdata, seed, 16);
    memcpy(valdata + 16, &titleId, 8);
    sha_quick(sha256sum, valdata, 16 + 8, SHA256_MODE);
    return (memcmp(hash, sha256sum, 4) == 0) ? 0 : 1;
}

u32 CheckNandFile(u32 param) {
    NandFileInfo* f_info = GetNandFileInfo(param);
    PartitionInfo* p_info = GetPartitionInfo(f_info->partition_id);
    u32 offset;
    u32 size;
    
    return DebugSeekFileInNand(&offset, &size, f_info->name_l, f_info->path, p_info);
}

u32 DumpNandFile(u32 param)
{
    NandFileInfo* f_info = GetNandFileInfo(param);
    PartitionInfo* p_info = GetPartitionInfo(f_info->partition_id);
    char filename[64];
    u32 offset;
    u32 size;
    
    if (DebugSeekFileInNand(&offset, &size, f_info->name_l, f_info->path, p_info) != 0)
        return 1;
    if (!(param & FF_AUTONAME)) {
        if (OutputFileNameSelector(filename, f_info->name_l, NULL) != 0)
            return 1;
    } else {
        unsigned int fileid[4];
        GetNandCtr((u8*) fileid, 0);
        snprintf(filename, 64, "%08X_%s", *fileid, f_info->name_l);
    }
    if (DecryptNandToFile(filename, offset, size, p_info, NULL) != 0)
        return 1;
    
    return 0;
}

u32 InjectNandFile(u32 param)
{
    NandFileInfo* f_info = GetNandFileInfo(param);
    PartitionInfo* p_info = GetPartitionInfo(f_info->partition_id);
    char filename[64];
    u32 offset;
    u32 size;
    
    if (!(param & N_NANDWRITE)) // developer screwup protection
        return 1;
    
    if (DebugSeekFileInNand(&offset, &size, f_info->name_l, f_info->path, p_info) != 0)
        return 1;
    if (!(param & FF_AUTONAME)) {
        if (InputFileNameSelector(filename, f_info->name_s, NULL, NULL, 0, size, false) != 0)
            return 1;
    } else {
        unsigned int fileid[4];
        GetNandCtr((u8*) fileid, 0);
        snprintf(filename, 64, "%08X_%s", *fileid, f_info->name_l);
    }
    if (EncryptFileToNand(filename, offset, size, p_info) != 0)
        return 1;
    
    // fix CMAC for file
    Debug("Fixing file CMAC for console...");
    FixNandCmac(param);
    
    return 0;
}

u32 DumpHealthAndSafety(u32 param)
{
    (void) (param); // param is unused here
    PartitionInfo* ctrnand_info = GetPartitionInfo(P_CTRNAND);
    TitleListInfo* health = (GetUnitPlatform() == PLATFORM_3DS) ? TL_HS : TL_HS_N;
    TitleListInfo* health_alt = (GetUnitPlatform() == PLATFORM_N3DS) ? TL_HS : NULL;
    char filename[64];
    u32 offset_app[4];
    u32 size_app[4];
    u32 offset_tmd;
    u32 size_tmd;
    
    
    if ((DebugSeekTitleInNand(&offset_tmd, &size_tmd, offset_app, size_app, health, 4) != 0) && (!health_alt || 
        (DebugSeekTitleInNand(&offset_tmd, &size_tmd, offset_app, size_app, health_alt, 4) != 0)))
        return 1;
    if (OutputFileNameSelector(filename, "hs.app", NULL) != 0)
        return 1;
        
    Debug("Dumping & decrypting APP0...");
    if (DecryptNandToFile(filename, offset_app[0], size_app[0], ctrnand_info, NULL) != 0)
        return 1;
    if (CryptNcch(filename, 0, 0, 0, NULL) != 0)
        return 1;
    
    
    return 0;
}

u32 InjectHealthAndSafety(u32 param)
{
    u8* buffer = BUFFER_ADDRESS;
    PartitionInfo* ctrnand_info = GetPartitionInfo(P_CTRNAND);
    TitleListInfo* health = (GetUnitPlatform() == PLATFORM_3DS) ? TL_HS : TL_HS_N;
    TitleListInfo* health_alt = (GetUnitPlatform() == PLATFORM_N3DS) ? TL_HS : NULL;
    NcchHeader* ncch = (NcchHeader*) 0x20316000;
    char filename[64];
    u32 offset_app[4];
    u32 size_app[4];
    u32 offset_tmd;
    u32 size_tmd;
    u32 size_hs;
    
    
    if (!(param & N_NANDWRITE)) // developer screwup protection
        return 1;
    
    if ((DebugSeekTitleInNand(&offset_tmd, &size_tmd, offset_app, size_app, health, 4) != 0) && (!health_alt || 
        (DebugSeekTitleInNand(&offset_tmd, &size_tmd, offset_app, size_app, health_alt, 4) != 0)))
        return 1;
    if (size_app[0] > 0x400000) {
        Debug("H&S system app is too big!");
        return 1;
    }
    if (DecryptNandToMem((void*) ncch, offset_app[0], 0x200, ctrnand_info) != 0)
        return 1;
    if (InputFileNameSelector(filename, NULL, "app", ncch->signature, 0x100, 0, false) != 0)
        return 1;
    
    if (!DebugFileOpen(filename))
        return 1;
    size_hs = FileGetSize();
    memset(buffer, 0, size_app[0]);
    if (size_hs > size_app[0]) {
        Debug("H&S inject app is too big!");
        FileClose();
        return 1;
    }
    if (FileCopyTo("hs.enc", buffer, size_hs) != size_hs) {
        Debug("Error copying to hs.enc");
        FileClose();
        return 1;
    }
    FileClose();
    
    if (CryptNcch("hs.enc", 0, 0, 0, ncch->flags) != 0)
        return 1;
    
    Debug("Injecting H&S app...");
    if (EncryptFileToNand("hs.enc", offset_app[0], size_hs, ctrnand_info) != 0)
        return 1;
    
    Debug("Fixing TMD...");
    TitleMetaData* tmd = (TitleMetaData*) 0x20316000;
    TmdContentChunk* content_list = (TmdContentChunk*) (tmd + 1);
    const u8 sig_type[4] = { 0x00, 0x01, 0x00, 0x04 };
    if (DecryptNandToMem((u8*) tmd, offset_tmd, size_tmd, ctrnand_info) != 0)
        return 1;
    u32 cnt_count = getbe16(tmd->content_count);
    if (memcmp(tmd->sig_type, sig_type, 4) != 0) {
        Debug("Bad TMD signature type");
        return 1; // this should never happen
    }
    if (GetHashFromFile("hs.enc", 0, size_app[0], content_list->hash) != 0) {
        Debug("Failed!");
        return 1;
    }
    for (u32 i = 0, kc = 0; i < 64 && kc < cnt_count; i++) {
        TmdContentInfo* cntinfo = tmd->contentinfo + i;
        u32 k = getbe16(cntinfo->cmd_count);
        sha_quick(cntinfo->hash, content_list + kc, k * sizeof(TmdContentChunk), SHA256_MODE);
        kc += k;
    }
    sha_quick(tmd->contentinfo_hash, (u8*)tmd->contentinfo, 64 * sizeof(TmdContentInfo), SHA256_MODE);
    if (EncryptMemToNand((u8*) tmd, offset_tmd, size_tmd, ctrnand_info) != 0)
        return 1;
    
    
    return 0;
}

u32 DumpNcchFirm(u32 firm_idx, bool version, bool a9l_decrypt)
{
    u8* buffer = BUFFER_ADDRESS;
    PartitionInfo* ctrnand_info = GetPartitionInfo(P_CTRNAND);
    TitleListInfo* firm = firms + firm_idx;
    char filename[64];
    u32 offset_app[4];
    u32 size_app[4];
    u32 offset_tmd;
    u32 size_tmd;
    u16 firm_ver;
    
    // search for firm title in NAND
    if (DebugSeekTitleInNand(&offset_tmd, &size_tmd, offset_app, size_app, firm, 4) != 0)
        return 1;
    
    // get version from TMD
    u8* tmd_data = buffer;
    if (DecryptNandToMem(tmd_data, offset_tmd, size_tmd, ctrnand_info) != 0)
        return 1;
    tmd_data += (tmd_data[3] == 3) ? 0x240 : (tmd_data[3] == 4) ? 0x140 : 0x80;
    firm_ver = getbe16(tmd_data + 0x9C);
    
    // Dump & decrypt FIRM app
    snprintf(filename, 64, (version) ? "%s_v%u.app" : "%s.app", firm->name, firm_ver);
    Debug("Dumping & decrypting %s...", filename);
    if (DecryptNandToFile(filename, offset_app[0], size_app[0], ctrnand_info, NULL) != 0)
        return 1;
    if (CryptNcch(filename, 0, 0, 0, NULL) != 0)
        return 1;
    
    // Extract FIRM bin
    NcchHeader* ncch = (NcchHeader*) buffer;
    u8* exefs;
    u8* firm_bin;
    u32 firm_size;
    u32 firm_offset;
    Debug("Extracting binary FIRM..."); // show kB
    if (size_app[0] > 0x400000) {
        Debug("FIRM app is too big (%lu Byte)!", size_app[0]);
        return 1;
    }
    if (FileGetData(filename, buffer, size_app[0], 0) != size_app[0]) {
        Debug("Error reading %s", filename);
        return 1;
    }
    if ((ncch->offset_exefs + ncch->size_exefs) * 0x200 > size_app[0])
        return 1; // almost impossible to happen at this point
    exefs = buffer + (ncch->offset_exefs * 0x200);
    if (strncmp((char*) exefs, ".firm", 8) != 0) {
        Debug(".firm not recognized");
        return 1;
    }
    firm_offset = (ncch->offset_exefs * 0x200) + 0x200 + getle32(exefs + 8);
    firm_size = getle32(exefs + 12);
    if (firm_offset + firm_size > size_app[0]) {
        Debug("Corrupt FIRM size / offset");
        return 1;
    }
    firm_bin = buffer + firm_offset;
    snprintf(filename, 64, (version) ? "%s_v%u.bin" : "%s.bin", firm->name, firm_ver);
    if (FileDumpData(filename, firm_bin, firm_size) != firm_size) {
        Debug("Error writing file");
        return 1;
    }
    
    // Verify FIRM bin
    Debug("Verifying %s...", filename);
    if (CheckFirmSize(firm_bin, firm_size) == 0) {
        Debug("Verification failed!");
        return 1;
    } else {
        Debug("Verified okay!");
    }
    
    if (a9l_decrypt && (firm_idx < 4)) { // only for N3DS FIRMs
        Debug("Decrypting ARM9 binary...");
        if (DecryptFirmArm9Mem(firm_bin, firm_size) != 0)
            return 1;
        snprintf(filename, 64, (version) ? "%s_v%u.dec" : "%s.dec", firm->name, firm_ver);
        if (FileDumpData(filename, firm_bin, firm_size) != firm_size) {
            Debug("Error writing file");
            return 1;
        }
        Debug("Done!");
    }
    
    return 0;
}

u32 DumpNcchFirms(u32 param)
{
    (void) (param); // param is unused here
    u32 success = 0;
    
    Debug("Dumping FIRMs from NCCHs...");
    for (u32 i = (GetUnitPlatform() == PLATFORM_N3DS) ? 0 : 4; i < 8; i++) {
        Debug("");
        if (DumpNcchFirm(i, true, true) == 0)
            success |= (1<<i);
    }
    
    Debug("");
    Debug("Succesfully processed FIRMs:");
    for (u32 i = 0; i < 8; i++) {
        if (success & (1<<i))
            Debug(firms[i].name);
    }
    if (!success)
        Debug("(none)");
    
    return success ? 0 : 1;
}

u32 AutoFixCtrnand(u32 param)
{
    if (!(param & N_NANDWRITE)) // developer screwup protection
        return 1;
    
    Debug("Checking and fixing <id0> folder");
    if (FixNandDataId0() != 0)
        return 1;
    
    Debug("Fixing essential system file CMACs");
    if ((FixNandCmac(F_TICKET)  != 0) ||
        (FixNandCmac(F_CERTS)   != 0) ||
        (FixNandCmac(F_TITLE)   != 0) ||
        (FixNandCmac(F_IMPORT)  != 0) ||
        (FixNandCmac(F_MOVABLE) != 0))
        return 1;
        
    Debug("Fixing other system file CMACs");
    FixNandCmac(F_TMPTDB);
    FixNandCmac(F_TMPIDB);
    FixNandCmac(F_SEEDSAVE);
    FixNandCmac(F_NAGSAVE);
    FixNandCmac(F_NNIDSAVE);
    FixNandCmac(F_FRIENDSAVE);
    FixNandCmac(F_CONFIGSAVE);
    
    return 0;
}

u32 DumpCitraConfig(u32 param)
{
    (void) (param); // param is unused here
    
    static const u32 config_offset[2] = { 0x6000, 0x25000 };
    static const u32 config_size = 0x8000;
    static const u8 magic[] = { 0x41, 0x00, 0xE4, 0x41, 0x00, 0x00, 0x00, 0x00, 0x39, 0x00 };
    
    NandFileInfo* f_info = GetNandFileInfo(F_CONFIGSAVE);
    PartitionInfo* p_info = GetPartitionInfo(f_info->partition_id);
    u8* buffer = BUFFER_ADDRESS;
    
    u32 p_active = 0;
    u32 offset;
    u32 size;
    
    // search for config save
    if (DebugSeekFileInNand(&offset, &size, f_info->name_l, f_info->path, p_info) != 0)
        return 1;
    
    // get active partition from DISA
    if (DecryptNandToMem(buffer, offset, 0x200, p_info) != 0)
        return 1;
    p_active = (getle32(buffer + 0x168)) ? 1 : 0;
    
    Debug("");
    for (u32 i = 0; i < 2; i++) {
        char filename[64];
        u32 p = (i + p_active) % 2; // offset / partition to try;
        Debug("Trying offset 0x%06X, partition %u...", config_offset[p], p);
        if (DecryptNandToMem(buffer, offset + config_offset[p], 0x200, p_info) != 0)
            return 1;
        if (memcmp(buffer, magic, sizeof(magic)) != 0) {
            Debug("Magic not found!");
            continue;
        }
        if (OutputFileNameSelector(filename, "config", NULL) != 0)
            return 1;
        if (DecryptNandToFile(filename, offset + config_offset[p], config_size, p_info, NULL) != 0)
            return 1;
        return 0;
    }
    
    return 1; // failed if arriving here
}

u32 FindSeedInSeedSave(u8* seed, u64 titleId, u8* hash)
{
    // there are two offsets where seeds can be found - 0x07000 & 0x5C000
    static const u32 seed_offset[2] = {0x7000, 0x5C000};
    
    NandFileInfo* f_info = GetNandFileInfo(F_SEEDSAVE);
    PartitionInfo* p_info = GetPartitionInfo(f_info->partition_id);
    u8* buffer = BUFFER_ADDRESS;
    
    u32 p_active = 0;
    u32 offset;
    u32 size;
    
    // load full seedsave to memory
    if (SeekFileInNand(&offset, &size, f_info->path, p_info) != 0)
        return 1;
    if (size != 0xAC000) {
        Debug("Expected %ukB, failed!", 0xAC000 / 1024);
        return 1;
    }
    if (DecryptNandToMem(buffer, offset, size, p_info) != 0)
        return 1;
    p_active = (getle32(buffer + 0x168)) ? 1 : 0;
    
    // search and extract seeds
    for ( int n = 0; n < 2; n++ ) {
        u8* seed_data = buffer + seed_offset[(n + p_active) % 2];
        for ( size_t i = 0; i < 2000; i++ ) {
            // 2000 seed entries max, splitted into title id and seed area
            u8* ltitleId = seed_data + (i*8);
            u8* lseed = seed_data + (2000*8) + (i*16);
            if (titleId != getle64(ltitleId))
                continue;
            if (hash && (ValidateSeed(lseed, titleId, hash) != 0))
                continue;
            memcpy(seed, lseed, 16);
            return 0;
        }
    }
    
    // not found if arriving here
    return 1;
}

u32 UpdateSeedDb(u32 param)
{
    (void) (param); // param is unused here
    // there are two offsets where seeds can be found - 0x07000 & 0x5C000
    static const u32 seed_offset[2] = {0x7000, 0x5C000};
    
    NandFileInfo* f_info = GetNandFileInfo(F_SEEDSAVE);
    PartitionInfo* p_info = GetPartitionInfo(f_info->partition_id);
    u8* buffer = BUFFER_ADDRESS;
    SeedInfo *seedinfo = (SeedInfo*) 0x20400000;
    
    u32 nNewSeeds = 0;
    u32 p_active = 0;
    u32 offset;
    u32 size;
    
    // load full seedsave to memory
    if (DebugSeekFileInNand(&offset, &size, f_info->name_l, f_info->path, p_info) != 0)
        return 1;
    if (size != 0xAC000) {
        Debug("Expected %ukB, failed!", 0xAC000 / 1024);
        return 1;
    }
    if (DecryptNandToMem(buffer, offset, size, p_info) != 0)
        return 1;
    p_active = (getle32(buffer + 0x168)) ? 1 : 0;
    
    // load / create seeddb.bin
    u32 size_seeddb;
    if ((size_seeddb = FileGetData("seeddb.bin", seedinfo, sizeof(SeedInfo), 0))) {
        if ((seedinfo->n_entries > MAX_ENTRIES) || (size_seeddb != 16 + seedinfo->n_entries * sizeof(SeedInfoEntry))) {
            Debug("seeddb.bin found, but seems corrupt");
            return 1;
        } else {
            Debug("Using existing seeddb.bin");
        }
    } else {
        Debug("Creating new seeddb.bin");
        memset(seedinfo, 0x00, 16);
    }
    
    // search and extract seeds
    for ( int n = 0; n < 2; n++ ) {
        u8* seed_data = buffer + seed_offset[(n + p_active) % 2];
        for ( size_t i = 0; i < 2000; i++ ) {
            static const u8 zeroes[16] = { 0x00 };
            // magic number is the reversed first 4 byte of a title id
            static const u8 magic[4] = { 0x00, 0x00, 0x04, 0x00 };
            // 2000 seed entries max, splitted into title id and seed area
            u8* titleId = seed_data + (i*8);
            u8* seed = seed_data + (2000*8) + (i*16);
            if (memcmp(titleId + 4, magic, 4) != 0)
                continue;
            // Bravely Second demo seed workaround
            if (memcmp(seed, zeroes, 16) == 0)
                seed = buffer + seed_offset[(n+1)%2] + (2000 * 8) + (i*16);
            if (memcmp(seed, zeroes, 16) == 0)
                continue;
            // seed found, check if it already exists
            u32 entryPos = 0;
            for (entryPos = 0; entryPos < seedinfo->n_entries; entryPos++)
                if (memcmp(titleId, &(seedinfo->entries[entryPos].titleId), 8) == 0)
                    break;
            if (entryPos < seedinfo->n_entries) {
                Debug("Found %08X%08X seed (duplicate)", getle32(titleId + 4), getle32(titleId));
                continue;
            }
            // seed is new, create a new entry
            Debug("Found %08X%08X seed (new)", getle32(titleId + 4), getle32(titleId));
            memset(&(seedinfo->entries[entryPos]), 0x00, sizeof(SeedInfoEntry));
            memcpy(&(seedinfo->entries[entryPos].titleId), titleId, 8);
            memcpy(&(seedinfo->entries[entryPos].external_seed), seed, 16);
            seedinfo->n_entries++;
            nNewSeeds++;
        }
    }
    
    if (nNewSeeds == 0) {
        Debug("Found no new seeds, %i total", seedinfo->n_entries);
        return 0;
    }
    
    Debug("Found %i new seeds, %i total", nNewSeeds, seedinfo->n_entries);
    if (!FileDumpData("seeddb.bin", seedinfo, 16 + seedinfo->n_entries * sizeof(SeedInfoEntry))) {
        Debug("Failed writing file");
        return 1;
    }
    
    return 0;
}

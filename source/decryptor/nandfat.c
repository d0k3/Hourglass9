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
    { "Health&Safety (N3DS)"  , 0x00040010, { 0x20020300, 0x20021300, 0x20022300, 0x00000000, 0x00000000, 0x00000000 } },
    { "3DS Camera"            , 0x00040010, { 0x00020400, 0x00021400, 0x00022400, 0x00026400, 0x00027400, 0x00028400 } },
    { "3DS Sound"             , 0x00040010, { 0x00020500, 0x00021500, 0x00022500, 0x00026500, 0x00027500, 0x00028500 } },
    { "Mii Maker"             , 0x00040010, { 0x00020700, 0x00021700, 0x00022700, 0x00026700, 0x00027700, 0x00028700 } },
    { "Streetpass Mii Plaza"  , 0x00040010, { 0x00020800, 0x00021800, 0x00022800, 0x00026800, 0x00027800, 0x00028800 } },
    { "3DS eShop"             , 0x00040010, { 0x00020900, 0x00021900, 0x00022900, 0x00000000, 0x00027900, 0x00028900 } },
    { "Nintendo Zone"         , 0x00040010, { 0x00020B00, 0x00021B00, 0x00022B00, 0x00000000, 0x00000000, 0x00000000 } }
};

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
    if (tid_low == 0) {
        Debug("%s not available for region", title_info->name);
        return 1;
    }
    
    Debug("Searching title \"%s\"...", title_info->name);
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
            Debug("Failed!");
            return 1;
        }
    }
    Debug("Found title %08X%08X", title_info->tid_high, tid_low);
    
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
        sprintf(path, "TITLE      %08X   %08X   CONTENT    %08XAPP", (unsigned int) title_info->tid_high, (unsigned int) tid_low, (unsigned int) cnt_id);
        if (SeekFileInNand(offset_app + i, size_app + i, path, ctrnand_info) != 0) {
            Debug("APP%i not found or fragmented!", i);
            return 1;
        }
        Debug("APP%i found at %08X, size %ukB", i, offset_app[i], size_app[i] / 1024);
    }
    
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
    if (DecryptNandToFile(filename, offset_app[0], size_app[0], ctrnand_info) != 0)
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

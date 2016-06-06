#include "fs.h"
#include "draw.h"
#include "platform.h"
#include "decryptor/aes.h"
#include "decryptor/sha.h"
#include "decryptor/keys.h"
#include "decryptor/hashfile.h"
#include "decryptor/nand.h"
#include "decryptor/injector.h"

// only a subset, see http://3dbrew.org/wiki/Title_list
// regions: JPN, USA, EUR, CHN, KOR, TWN
TitleListInfo titleList[] = {
    { "Health&Safety"         , 0x00040010, { 0x00020300, 0x00021300, 0x00022300, 0x00026300, 0x00027300, 0x00028300 } },
    { "Health&Safety (N3DS)"  , 0x00040010, { 0x20020300, 0x20021300, 0x20022300, 0x00000000, 0x00000000, 0x00000000 } }
};

u32 GetNcchCtr(u8* ctr, NcchHeader* ncch, u8 sub_id) {
    memset(ctr, 0x00, 16);
    if (ncch->version == 1) {
        memcpy(ctr, &(ncch->partitionId), 8);
        if (sub_id == 1) { // exHeader ctr
            add_ctr(ctr, 0x200); 
        } else if (sub_id == 2) { // exeFS ctr
            add_ctr(ctr, ncch->offset_exefs * 0x200);
        } else if (sub_id == 3) { // romFS ctr
            add_ctr(ctr, ncch->offset_romfs * 0x200);
        }
    } else {
        for (u32 i = 0; i < 8; i++)
            ctr[i] = ((u8*) &(ncch->partitionId))[7-i];
        ctr[8] = sub_id;
    }
    
    return 0;
}

u32 CryptSdToSd(const char* filename, u32 offset, u32 size, CryptBufferInfo* info, bool handle_offset16)
{
    u8* buffer = BUFFER_ADDRESS;
    u32 offset_16 = (handle_offset16) ? offset % 16 : 0;
    u32 result = 0;

    // no DebugFileOpen() - at this point the file has already been checked enough
    if (!FileOpen(filename)) 
        return 1;

    info->buffer = buffer;
    if (offset_16) { // handle offset alignment / this assumes the data is >= 16 byte
        if(!DebugFileRead(buffer + offset_16, 16 - offset_16, offset)) {
            result = 1;
        }
        info->size = 16;
        CryptBuffer(info);
        if(!DebugFileWrite(buffer + offset_16, 16 - offset_16, offset)) {
            result = 1;
        }
    }
    for (u32 i = (offset_16) ? (16 - offset_16) : 0; i < size; i += BUFFER_MAX_SIZE) {
        u32 read_bytes = min(BUFFER_MAX_SIZE, (size - i));
        ShowProgress(i, size);
        if(!DebugFileRead(buffer, read_bytes, offset + i)) {
            result = 1;
            break;
        }
        info->size = read_bytes;
        CryptBuffer(info);
        if(!DebugFileWrite(buffer, read_bytes, offset + i)) {
            result = 1;
            break;
        }
    }

    ShowProgress(0, 0);
    FileClose();

    return result;
}

u32 CryptNcch(const char* filename, u32 offset, u32 size, u64 seedId, u8* encrypt_flags)
{
    NcchHeader* ncch = (NcchHeader*) 0x20316200;
    u8* buffer = (u8*) 0x20316400;
    CryptBufferInfo info0 = {.setKeyY = 1, .keyslot = 0x2C, .mode = AES_CNT_CTRNAND_MODE};
    CryptBufferInfo info1 = {.setKeyY = 1, .mode = AES_CNT_CTRNAND_MODE};
    u8 seedKeyY[16] = { 0x00 };
    u32 result = 0;
    
    if (FileGetData(filename, (void*) ncch, 0x200, offset) != 0x200)
        return 1; // it's impossible to fail here anyways
 
    // check (again) for magic number
    if (memcmp(ncch->magic, "NCCH", 4) != 0) {
        Debug("Not a NCCH container");
        return 2; // not an actual error
    }
    
    // size plausibility check
    u32 size_sum = 0x200 + ((ncch->size_exthdr) ? 0x800 : 0x0) + 0x200 *
        (ncch->size_plain + ncch->size_logo + ncch->size_exefs + ncch->size_romfs);
    if (ncch->size * 0x200 < size_sum) {
        Debug("Probably not a NCCH container");
        return 2; // not an actual error
    }        
    
    // check if encrypted
    if (!encrypt_flags && (ncch->flags[7] & 0x04)) {
        Debug("NCCH is not encrypted");
        return 2; // not an actual error
    } else if (encrypt_flags && !(ncch->flags[7] & 0x04)) {
        Debug("NCCH is already encrypted");
        return 2; // not an actual error
    } else if (encrypt_flags && (encrypt_flags[7] & 0x04)) {
        Debug("Nothing to do!");
        return 2; // not an actual error
    }
    
    // check size
    if ((size > 0) && (ncch->size * 0x200 > size)) {
        Debug("NCCH size is out of bounds");
        return 1;
    }
    
    // select correct title ID for seed crypto
    if (seedId == 0) seedId = ncch->programId;
    
    // copy over encryption parameters (if applicable)
    if (encrypt_flags) {
        ncch->flags[3] = encrypt_flags[3];
        ncch->flags[7] &= (0x01|0x20|0x04)^0xFF;
        ncch->flags[7] |= (0x01|0x20)&encrypt_flags[7];
    }
    
    // check crypto type
    bool uses7xCrypto = ncch->flags[3];
    bool usesSeedCrypto = ncch->flags[7] & 0x20;
    bool usesSec3Crypto = (ncch->flags[3] == 0x0A);
    bool usesSec4Crypto = (ncch->flags[3] == 0x0B);
    bool usesFixedKey = ncch->flags[7] & 0x01;
    
    Debug("Code / Crypto: %.16s / %s%s%s%s", ncch->productCode, (usesFixedKey) ? "FixedKey " : "", (usesSec4Crypto) ? "Secure4 " : (usesSec3Crypto) ? "Secure3 " : (uses7xCrypto) ? "7x " : "", (usesSeedCrypto) ? "Seed " : "", (!uses7xCrypto && !usesSeedCrypto && !usesFixedKey) ? "Standard" : "");
    
    // setup zero key crypto
    if (usesFixedKey) {
        // from https://github.com/profi200/Project_CTR/blob/master/makerom/pki/dev.h
        u8 zeroKey[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        u8 sysKey[16]  = {0x52, 0x7C, 0xE6, 0x30, 0xA9, 0xCA, 0x30, 0x5F, 0x36, 0x96, 0xF3, 0xCD, 0xE9, 0x54, 0x19, 0x4B};
        if (uses7xCrypto || usesSeedCrypto) {
            Debug("Crypto combination is not allowed!");
            return 1;
        }
        info1.setKeyY = info0.setKeyY = 0;
        info1.keyslot = info0.keyslot = 0x11;
        setup_aeskey(0x11, (ncch->programId & ((u64) 0x10 << 32)) ? sysKey : zeroKey);
    }
    
    // check 7x crypto
    if (uses7xCrypto && (CheckKeySlot(0x25, 'X') != 0)) {
        Debug("slot0x25KeyX not set up");
        Debug("This won't work on O3DS < 7.x or A9LH");
        return 1;
    }
    
    // check Secure3 crypto on O3DS
    if (usesSec3Crypto && (CheckKeySlot(0x18, 'X') != 0)) {
        Debug("slot0x18KeyX not set up");
        Debug("Secure3 crypto is not available");
        return 1;
    }
    
    // check Secure4 crypto
    if (usesSec4Crypto && (CheckKeySlot(0x1B, 'X') != 0)) {
        Debug("slot0x1BKeyX not set up");
        Debug("Secure4 crypto is not available");
        return 1;
    }
    
    // check / setup seed crypto
    if (usesSeedCrypto) {
        if (FileOpen("seeddb.bin")) {
            SeedInfoEntry* entry = (SeedInfoEntry*) buffer;
            u32 found = 0;
            for (u32 i = 0x10;; i += 0x20) {
                if (FileRead(entry, 0x20, i) != 0x20)
                    break;
                if (entry->titleId == seedId) {
                    u8 keydata[32];
                    memcpy(keydata, ncch->signature, 16);
                    memcpy(keydata + 16, entry->external_seed, 16);
                    u8 sha256sum[32];
                    sha_quick(sha256sum, keydata, 32, SHA256_MODE);
                    memcpy(seedKeyY, sha256sum, 16);
                    found = 1;
                }
            }
            FileClose();
            if (!found) {
                Debug("Seed not found in seeddb.bin!");
                return 1;
            }
        } else {
            Debug("Need seeddb.bin for seed crypto!");
            return 1;
        }
        Debug("Loading seed from seeddb.bin: ok");
    }
    
    // basic setup of CryptBufferInfo structs
    memcpy(info0.keyY, ncch->signature, 16);
    memcpy(info1.keyY, (usesSeedCrypto) ? seedKeyY : ncch->signature, 16);
    info1.keyslot = (usesSec4Crypto) ? 0x1B : ((usesSec3Crypto) ? 0x18 : ((uses7xCrypto) ? 0x25 : info0.keyslot));
    
    Debug("%s ExHdr/ExeFS/RomFS (%ukB/%ukB/%uMB)",
        (encrypt_flags) ? "Encrypt" : "Decrypt",
        (ncch->size_exthdr > 0) ? 0x800 / 1024 : 0,
        (ncch->size_exefs * 0x200) / 1024,
        (ncch->size_romfs * 0x200) / (1024*1024));
        
    // process ExHeader
    if (ncch->size_exthdr > 0) {
        GetNcchCtr(info0.ctr, ncch, 1);
        result |= CryptSdToSd(filename, offset + 0x200, 0x800, &info0, true);
    }
    
    // process ExeFS
    if (ncch->size_exefs > 0) {
        u32 offset_byte = ncch->offset_exefs * 0x200;
        u32 size_byte = ncch->size_exefs * 0x200;
        if (uses7xCrypto || usesSeedCrypto) {
            GetNcchCtr(info0.ctr, ncch, 2);
            if (!encrypt_flags) // decrypt this first (when decrypting)
                result |= CryptSdToSd(filename, offset + offset_byte, 0x200, &info0, true);
            if (FileGetData(filename, buffer, 0x200, offset + offset_byte) != 0x200) // get exeFS header
                return 1;
            if (encrypt_flags) // encrypt this last (when encrypting)
                result |= CryptSdToSd(filename, offset + offset_byte, 0x200, &info0, true);
            // special ExeFS decryption routine ("banner" and "icon" use standard crypto)
            for (u32 i = 0; i < 10; i++) {
                char* name_exefs_file = (char*) buffer + (i*0x10);
                u32 offset_exefs_file = getle32(buffer + (i*0x10) + 0x8) + 0x200;
                u32 size_exefs_file = getle32(buffer + (i*0x10) + 0xC);
                CryptBufferInfo* infoExeFs = ((strncmp(name_exefs_file, "banner", 8) == 0) ||
                    (strncmp(name_exefs_file, "icon", 8) == 0)) ? &info0 : &info1;
                if (size_exefs_file == 0)
                    continue;
                if (offset_exefs_file % 16) {
                    Debug("ExeFS file offset not aligned!");
                    result |= 1;
                    break; // this should not happen
                }
                GetNcchCtr(infoExeFs->ctr, ncch, 2);
                add_ctr(infoExeFs->ctr, offset_exefs_file / 0x10);
                infoExeFs->setKeyY = 1;
                result |= CryptSdToSd(filename, offset + offset_byte + offset_exefs_file,
                    align(size_exefs_file, 16), infoExeFs, true);
            }
        } else {
            GetNcchCtr(info0.ctr, ncch, 2);
            result |= CryptSdToSd(filename, offset + offset_byte, size_byte, &info0, true);
        }
    }
    
    // process RomFS
    if (ncch->size_romfs > 0) {
        GetNcchCtr(info1.ctr, ncch, 3);
        if (!usesFixedKey)
            info1.setKeyY = 1;
        result |= CryptSdToSd(filename, offset + (ncch->offset_romfs * 0x200), ncch->size_romfs * 0x200, &info1, true);
    }
    
    // set NCCH header flags
    if (!encrypt_flags) {
        ncch->flags[3] = 0x00;
        ncch->flags[7] &= (0x01|0x20)^0xFF;
        ncch->flags[7] |= 0x04;
    }
    
    // write header back
    if (!FileOpen(filename))
        return 1;
    if (!DebugFileWrite((void*) ncch, 0x200, offset)) {
        FileClose();
        return 1;
    }
    FileClose();
    
    // verify decryption
    if ((result == 0) && !encrypt_flags) {
        char* status_str[3] = { "OK", "Fail", "-" }; 
        u32 ver_exthdr = 2;
        u32 ver_exefs = 2;
        u32 ver_romfs = 2;
        
        if (ncch->size_exthdr > 0)
            ver_exthdr = CheckHashFromFile(filename, offset + 0x200, 0x400, ncch->hash_exthdr);
        if (ncch->size_exefs_hash > 0)
            ver_exefs = CheckHashFromFile(filename, offset + (ncch->offset_exefs * 0x200), ncch->size_exefs_hash * 0x200, ncch->hash_exefs);
        if (ncch->size_romfs_hash > 0)
            ver_romfs = CheckHashFromFile(filename, offset + (ncch->offset_romfs * 0x200), ncch->size_romfs_hash * 0x200, ncch->hash_romfs);
        
        if (ncch->size_exefs > 0) { // thorough exefs verification
            u32 offset_byte = ncch->offset_exefs * 0x200;
            if (FileGetData(filename, buffer, 0x200, offset + offset_byte) != 0x200)
                ver_exefs = 1;
            for (u32 i = 0; (i < 10) && (ver_exefs != 1); i++) {
                u32 offset_exefs_file = offset_byte + getle32(buffer + (i*0x10) + 0x8) + 0x200;
                u32 size_exefs_file = getle32(buffer + (i*0x10) + 0xC);
                u8* hash_exefs_file = buffer + 0x200 - ((i+1)*0x20);
                if (size_exefs_file == 0)
                    break;
                ver_exefs = CheckHashFromFile(filename, offset + offset_exefs_file, size_exefs_file, hash_exefs_file);
            }
        }
        
        Debug("Verify ExHdr/ExeFS/RomFS: %s/%s/%s", status_str[ver_exthdr], status_str[ver_exefs], status_str[ver_romfs]);
        result = (((ver_exthdr | ver_exefs | ver_romfs) & 1) == 0) ? 0 : 1;
    }
    
    
    return result;
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

u32 SeekTitleInNandDb(u32* tid_low, u32* tmd_id, TitleListInfo* title_info)
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
    *tid_low = 0;
    for (u32 i = 0; i < 1000; i++) {
        u8* entry = entry_table + 0xA8 + (0x2C * i);
        u8* info = info_data + (0x80 * i);
        u32 r;
        if (getle32(entry + 0xC) != title_info->tid_high) continue; // not a title id match
        if (getle32(entry + 0x4) != 1) continue; // not an active entry
        if ((getle32(entry + 0x18) - i != 0x162) || (getle32(entry + 0x1C) != 0x80) || (getle32(info + 0x08) != 0x40)) continue; // fishy title info / offset
        for (r = 0; r < 6; r++) {
            if ((title_info->tid_low[r] != 0) && (getle32(entry + 0x8) == title_info->tid_low[r])) break;
        }
        if (r >= 6) continue;
        *tmd_id = getle32(info + 0x14);
        *tid_low = title_info->tid_low[r];
        break; 
    }
    
    return (*tid_low) ? 0 : 1;
}

u32 DebugSeekTitleInNand(u32* offset_tmd, u32* size_tmd, u32* offset_app, u32* size_app, TitleListInfo* title_info, u32 max_cnt)
{
    PartitionInfo* ctrnand_info = GetPartitionInfo(P_CTRNAND);
    u8* buffer = (u8*) 0x20316000;
    u32 cnt_count = 0;
    u32 tid_low = 0;
    u32 tmd_id = 0;
    
    Debug("Searching title \"%s\"...", title_info->name);
    Debug("Method 1: Search in title.db...");
    if (SeekTitleInNandDb(&tid_low, &tmd_id, title_info) == 0) {
        char path[64];
        sprintf(path, "TITLE      %08X   %08X   CONTENT    %08XTMD", (unsigned int) title_info->tid_high, (unsigned int) tid_low, (unsigned int) tmd_id);
        if (SeekFileInNand(offset_tmd, size_tmd, path, ctrnand_info) != 0)
            tid_low = 0;
    }
    if (!tid_low) {
        Debug("Method 2: Search in file system...");
        for (u32 i = 0; i < 6; i++) {
            char path[64];
            if (title_info->tid_low[i] == 0)
                continue;
            sprintf(path, "TITLE      %08X   %08X   CONTENT    ????????TMD", (unsigned int) title_info->tid_high, (unsigned int) title_info->tid_low[i]);
            if (SeekFileInNand(offset_tmd, size_tmd, path, ctrnand_info) == 0) {
                tid_low = title_info->tid_low[i];
                break;
            }
        }
    }
    if (!tid_low) {
        Debug("Failed!");
        return 1;
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

u32 DumpHealthAndSafety(u32 param)
{
    (void) (param); // param is unused here
    PartitionInfo* ctrnand_info = GetPartitionInfo(P_CTRNAND);
    TitleListInfo* health = titleList + ((GetUnitPlatform() == PLATFORM_3DS) ? 0 : 1);
    TitleListInfo* health_alt = (GetUnitPlatform() == PLATFORM_N3DS) ? titleList + 0 : NULL;
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
    TitleListInfo* health = titleList + ((GetUnitPlatform() == PLATFORM_3DS) ? 0 : 1);
    TitleListInfo* health_alt = (GetUnitPlatform() == PLATFORM_N3DS) ? titleList + 0 : NULL;
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
        return 1;
    }
    if (!DebugFileRead(buffer, size_hs, 0)) {
        FileClose();
        return 1;
    }
    FileClose();
    if (!DebugFileCreate("hs.enc", true))
        return 1;
    if (!DebugFileWrite(buffer, size_app[0], 0)) {
        FileClose();
        return 1;
    }
    FileClose();
    if (CryptNcch("hs.enc", 0, 0, 0, ncch->flags) != 0)
        return 1;
    
    Debug("Injecting H&S app...");
    if (EncryptFileToNand("hs.enc", offset_app[0], size_app[0], ctrnand_info) != 0)
        return 1;
    
    Debug("Fixing TMD...");
    u8* tmd_data = (u8*) 0x20316000;
    if (DecryptNandToMem(tmd_data, offset_tmd, size_tmd, ctrnand_info) != 0)
        return 1; 
    tmd_data += (tmd_data[3] == 3) ? 0x240 : (tmd_data[3] == 4) ? 0x140 : 0x80;
    u8* content_list = tmd_data + 0xC4 + (64 * 0x24);
    u32 cnt_count = getbe16(tmd_data + 0x9E);
    if (GetHashFromFile("hs.enc", 0, size_app[0], content_list + 0x10) != 0) {
        Debug("Failed!");
        return 1;
    }
    for (u32 i = 0, kc = 0; i < 64 && kc < cnt_count; i++) {
        u32 k = getbe16(tmd_data + 0xC4 + (i * 0x24) + 0x02);
        u8* chunk_hash = tmd_data + 0xC4 + (i * 0x24) + 0x04;
        sha_quick(chunk_hash, content_list + kc * 0x30, k * 0x30, SHA256_MODE);
        kc += k;
    }
    u8* tmd_hash = tmd_data + 0xA4;
    sha_quick(tmd_hash, tmd_data + 0xC4, 64 * 0x24, SHA256_MODE);
    tmd_data = (u8*) 0x20316000;
    if (EncryptMemToNand(tmd_data, offset_tmd, size_tmd, ctrnand_info) != 0)
        return 1; 
    
    
    return 0;
}

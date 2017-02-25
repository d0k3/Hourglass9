#include "fs.h"
#include "draw.h"
#include "hid.h"
#include "platform.h"
#include "decryptor/aes.h"
#include "decryptor/sha.h"
#include "decryptor/decryptor.h"
#include "decryptor/hashfile.h"
#include "decryptor/keys.h"
#include "decryptor/nand.h"
#include "decryptor/nandfat.h" // for serial in NAND backup name
#include "fatfs/sdmmc.h"

// return values for NAND header check
#define NAND_HDR_UNK  0 // should be zero
#define NAND_HDR_O3DS 1 
#define NAND_HDR_N3DS 2

// minimum sizes for O3DS / N3DS NAND
// see: http://3dbrew.org/wiki/Flash_Filesystem
#define NAND_MIN_SIZE ((GetUnitPlatform() == PLATFORM_3DS) ? 0x3AF00000 : 0x4D800000)

// see below
#define IS_NAND_HEADER(hdr) ((memcmp(buffer + 0x100, nand_magic_n3ds, 0x60) == 0) ||\
                             (memcmp(buffer + 0x100, nand_magic_o3ds, 0x60) == 0))

// from an actual N3DS NCSD NAND header (@0x100), same for all
static u8 nand_magic_n3ds[0x60] = {
    0x4E, 0x43, 0x53, 0x44, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x04, 0x03, 0x03, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x05, 0x00, 0x00, 0x88, 0x05, 0x00, 0x80, 0x01, 0x00, 0x00,
    0x80, 0x89, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00, 0x80, 0xA9, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00,
    0x80, 0xC9, 0x05, 0x00, 0x80, 0xF6, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// from an actual O3DS NCSD NAND header (@0x100), same for all
static u8 nand_magic_o3ds[0x60] = {
    0x4E, 0x43, 0x53, 0x44, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x04, 0x03, 0x03, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x05, 0x00, 0x00, 0x88, 0x05, 0x00, 0x80, 0x01, 0x00, 0x00,
    0x80, 0x89, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00, 0x80, 0xA9, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00,
    0x80, 0xC9, 0x05, 0x00, 0x80, 0xAE, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// encrypted version inside the NCSD NAND header (@0x1BE), same for all
static u8 twl_mbr[0x42] = {
    0x00, 0x04, 0x18, 0x00, 0x06, 0x01, 0xA0, 0x3F, 0x97, 0x00, 0x00, 0x00, 0xA9, 0x7D, 0x04, 0x00,
    0x00, 0x04, 0x8E, 0x40, 0x06, 0x01, 0xA0, 0xC3, 0x8D, 0x80, 0x04, 0x00, 0xB3, 0x05, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x55, 0xAA
};

// see: http://3dbrew.org/wiki/Flash_Filesystem
static PartitionInfo partitions[] = {
    { "TWLN",    {0xE9, 0x00, 0x00, 0x54, 0x57, 0x4C, 0x20, 0x20}, 0x00012E00, 0x08FB5200, 0x3, AES_CNT_TWLNAND_MODE },
    { "TWLP",    {0xE9, 0x00, 0x00, 0x54, 0x57, 0x4C, 0x20, 0x20}, 0x09011A00, 0x020B6600, 0x3, AES_CNT_TWLNAND_MODE },
    { "AGBSAVE", {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 0x0B100000, 0x00030000, 0x7, AES_CNT_CTRNAND_MODE },
    { "FIRM",    {0x46, 0x49, 0x52, 0x4D, 0x00, 0x00, 0x00, 0x00}, 0x0B130000, 0x00400000, 0x6, AES_CNT_CTRNAND_MODE },
    { "FIRM",    {0x46, 0x49, 0x52, 0x4D, 0x00, 0x00, 0x00, 0x00}, 0x0B530000, 0x00400000, 0x6, AES_CNT_CTRNAND_MODE },
    { "CTRNAND", {0xE9, 0x00, 0x00, 0x43, 0x54, 0x52, 0x20, 0x20}, 0x0B95CA00, 0x2F3E3600, 0x4, AES_CNT_CTRNAND_MODE }, // O3DS
    { "CTRNAND", {0xE9, 0x00, 0x00, 0x43, 0x54, 0x52, 0x20, 0x20}, 0x0B95AE00, 0x41D2D200, 0x5, AES_CNT_CTRNAND_MODE }, // N3DS
    { "CTRNAND", {0xE9, 0x00, 0x00, 0x43, 0x54, 0x52, 0x20, 0x20}, 0x0B95AE00, 0x41D2D200, 0x4, AES_CNT_CTRNAND_MODE }, // NO3DS
    { "CTRFULL", {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 0x0B930000, 0x2F5D0000, 0x4, AES_CNT_CTRNAND_MODE }, // O3DS
    { "CTRFULL", {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 0x0B930000, 0x41ED0000, 0x5, AES_CNT_CTRNAND_MODE }  // N3DS
};

static u32 emunand_header = 0;
static u32 emunand_offset = 0;


u32 GetEmuNandMultiSectors(void)
{
    u8* buffer = BUFFER_ADDRESS;
    u32 compact_sectors = align(1 + (NAND_MIN_SIZE / NAND_SECTOR_SIZE), 0x2000);
    u32 legacy_sectors = (getMMCDevice(0)->total_size > 0x200000) ? 0x400000 : 0x200000;
    sdmmc_sdcard_readsectors(compact_sectors + 1, 1, buffer);
    return (IS_NAND_HEADER(buffer)) ? compact_sectors : legacy_sectors;
}

u32 CheckEmuNand(void)
{
    u8* buffer = BUFFER_ADDRESS;
    u32 nand_size_sectors = getMMCDevice(0)->total_size;
    u32 nand_size_sectors_min = NAND_MIN_SIZE / NAND_SECTOR_SIZE;
    u32 multi_sectors = GetEmuNandMultiSectors();
    u32 ret = EMUNAND_NOT_READY;

    // check the MBR for presence of a hidden partition
    u32 hidden_sectors = NumHiddenSectors();
    if (hidden_sectors > 4 * multi_sectors)
        hidden_sectors = 4 * multi_sectors;
    
    for (u32 offset_sector = 0; offset_sector + nand_size_sectors_min <= hidden_sectors; offset_sector += multi_sectors) {
        // check for RedNAND type EmuNAND
        sdmmc_sdcard_readsectors(offset_sector + 1, 1, buffer);
        if (IS_NAND_HEADER(buffer)) {
            ret |= EMUNAND_REDNAND << (2 * (offset_sector / multi_sectors)); 
            continue;
        }
        // check for Gateway type EmuNAND
        sdmmc_sdcard_readsectors(offset_sector + nand_size_sectors, 1, buffer);
        if ((hidden_sectors > offset_sector + nand_size_sectors) && IS_NAND_HEADER(buffer)) {
            ret |= EMUNAND_GATEWAY << (2 * (offset_sector / multi_sectors)); 
            continue;
        }
        // EmuNAND ready but not set up
        ret |= EMUNAND_READY << (2 * (offset_sector / multi_sectors));
    }
    
    return ret;
}

u32 SetNand(bool set_emunand, bool force_emunand)
{
    if (set_emunand) {
        u32 emunand_state = CheckEmuNand();
        u32 emunand_count = 0;
        u32 offset_sector = 0;
        
        for (emunand_count = 0; (emunand_state >> (2 * emunand_count)) & 0x3; emunand_count++);
        if (emunand_count > 1) { // multiple EmuNANDs -> use selector
            u32 multi_sectors = GetEmuNandMultiSectors();
            u32 emunand_no = 0;
            DebugColor(COLOR_ASK, "Use arrow keys and <A> to choose EmuNAND");
            while (true) {
                u32 emunandn_state = (emunand_state >> (2 * emunand_no)) & 0x3;
                offset_sector = emunand_no * multi_sectors;
                DebugColor(COLOR_SELECT, "\rEmuNAND #%u: %s", emunand_no, (emunandn_state == EMUNAND_READY) ? "EmuNAND ready" : (emunandn_state == EMUNAND_GATEWAY) ? "GW EmuNAND" : "RedNAND");
                // user input routine
                u32 pad_state = InputWait();
                if (pad_state & BUTTON_DOWN) {
                    emunand_no = (emunand_no + 1) % emunand_count;
                } else if (pad_state & BUTTON_UP) {
                    emunand_no = (emunand_no) ?  emunand_no - 1 : emunand_count - 1;
                } else if (pad_state & BUTTON_A) {
                    DebugColor(COLOR_ASK, "EmuNAND #%u", emunand_no);
                    emunand_state = emunandn_state;
                    break;
                } else if (pad_state & BUTTON_B) {
                    DebugColor(COLOR_ASK, "(cancelled by user)");
                    return 2;
                }
            }
        }
        
        if ((emunand_state == EMUNAND_READY) && force_emunand)
            emunand_state = EMUNAND_REDNAND;
        switch (emunand_state) {
            case EMUNAND_NOT_READY:
                Debug("SD is not formatted for EmuNAND");
                return 1;
            case EMUNAND_GATEWAY:
                emunand_header = offset_sector + getMMCDevice(0)->total_size;
                emunand_offset = offset_sector;
                Debug("Using EmuNAND @ %06X/%06X", emunand_header, emunand_offset);
                return 0;
            case EMUNAND_REDNAND:
                emunand_header = offset_sector + 1;
                emunand_offset = offset_sector + 1;
                Debug("Using RedNAND @ %06X/%06X", emunand_header, emunand_offset);
                return 0;
            default:
                Debug("EmuNAND is not available");
                return 1;
        }
    } else {
        emunand_header = 0;
        emunand_offset = 0;
        return 0;
    }
}

static inline int ReadNandSectors(u32 sector_no, u32 numsectors, u8 *out)
{
    if (emunand_header) {
        if (sector_no == 0) {
            int errorcode = sdmmc_sdcard_readsectors(emunand_header, 1, out);
            if (errorcode) return errorcode;
            sector_no = 1;
            numsectors--;
            out += 0x200;
        }
        return (numsectors) ? sdmmc_sdcard_readsectors(sector_no + emunand_offset, numsectors, out) : 0;
    } else return sdmmc_nand_readsectors(sector_no, numsectors, out);
}

static inline int WriteNandSectors(u32 sector_no, u32 numsectors, u8 *in)
{
    if (emunand_header) {
        if (sector_no == 0) {
            int errorcode = sdmmc_sdcard_writesectors(emunand_header, 1, in);
            if (errorcode) return errorcode;
            sector_no = 1;
            numsectors--;
            in += 0x200;
        }
        return (numsectors) ? sdmmc_sdcard_writesectors(sector_no + emunand_offset, numsectors, in) : 0;
    } else return sdmmc_nand_writesectors(sector_no, numsectors, in);
}

static u32 CheckNandHeaderType(u8* header) {
    u8 lheader[0x200];
    
    if (header != NULL)
        memcpy(lheader, header, 0x200);
    else if (ReadNandSectors(0, 1, lheader) != 0)
        return NAND_HDR_UNK;
    
    if (memcmp(lheader + 0x100, nand_magic_n3ds, 0x60) == 0) {
        return NAND_HDR_N3DS;
    } else if (memcmp(lheader + 0x100, nand_magic_o3ds, 0x60) == 0) {
        return NAND_HDR_O3DS;
    } 
    
    return NAND_HDR_UNK;
}

static u32 CheckNandHeaderIntegrity(u8* header) {
    
    if (!header)
        return 1;
    
    // check header type
    if (CheckNandHeaderType(header) == NAND_HDR_UNK) {
        Debug("NAND header not recognized");
        return 1;
    }
    
    // check if header belongs to console via TWL MBR decryption
    u8 dec_mbr_block[0xA0];
    PartitionInfo* twln = GetPartitionInfo(P_TWLN);
    CryptBufferInfo info = {.keyslot = twln->keyslot, .setKeyY = 0, .size = 0xA0, .buffer = dec_mbr_block, .mode = twln->mode};
    GetNandCtr(info.ctr, 0x160);
    memcpy(dec_mbr_block, header + 0x160, 0xA0);
    CryptBuffer(&info);
    if (memcmp(dec_mbr_block + 0x5E, twl_mbr, 0x42) != 0) {
        Debug("NAND header is corrupt or from another 3DS");
        return 1;
    }
    
    // compare with current header
    if (!emunand_header) { // only for SysNAND
        u8 curr_header[0x200];
        if (ReadNandSectors(0, 1, curr_header) != 0)
            return 1;
        // first make sure current header has same mbr crypto
        if ((memcmp(curr_header + 0x1BE, header + 0x1BE, 42) == 0) &&
            (memcmp(curr_header, header, 0x200) != 0)) {
            Debug("NAND header is corrupt");
            return 1;
        }
    }
    
    return 0;
}

u32 CheckFirmSize(const u8* firm, u32 f_size) {
    // returns firm size if okay, 0 otherwise
    u32 f_actualsize = 0;
    if (f_size < 0x100)
        return 0;
    for (u32 section = 0; section < 4; section++) {
        u32 offset = getle32(firm + 0x40 + 0x00 + (0x30*section));
        u32 size = getle32(firm + 0x40 + 0x08 + (0x30*section));
        if (!size)
            continue;
        if (offset < f_actualsize) {
            Debug("FIRM sections are overlapping", section);
            return 0;
        }
        f_actualsize = offset + size;
        if (f_actualsize > 0x400000) {
            Debug("FIRM size exceeds partition", section);
            return 0;
        }
        // if size <= 0x200, only check size
        if (f_size > 0x200) { // includes SHA-256 check
            if (f_actualsize > f_size) {
                Debug("FIRM section%u out of bounds", section);
                return 0;
            }
            u8 l_sha256[32];
            const u8* sha256 = firm + 0x40 + 0x10 + (0x30*section);
            sha_quick(l_sha256, firm + offset, size, SHA256_MODE);
            if (memcmp(l_sha256, sha256, 32) != 0) {
                Debug("FIRM section%u hash mismatch", section);
                return 0;
            }
        }
    }
    
    return f_actualsize;
}

static u32 CheckNandDumpIntegrity(const char* path, bool check_firm) {
    u8 header[0x200];
    u32 nand_hdr_type = NAND_HDR_UNK;
    
    Debug("Verifying dump via .SHA...");
    u32 hash_res = HashVerifyFile(path);
    if (hash_res == HASH_FAILED) {
        Debug("Failed, file is corrupt!");
        return 1;
    }
    Debug((hash_res == HASH_VERIFIED) ? "Verification passed" : ".SHA not found, skipped");
    
    if (!DebugFileOpen(path))
        return 1;
    
    // size check
    if (FileGetSize() < NAND_MIN_SIZE) {
        FileClose();
        Debug("NAND dump is too small");
        return 1;
    }
    
    // header check
    if(!DebugFileRead(header, 0x200, 0)) {
        FileClose();
        return 1;
    }
    // header type check
    nand_hdr_type = CheckNandHeaderType(header);
    if ((nand_hdr_type == NAND_HDR_UNK) || ((GetUnitPlatform() == PLATFORM_3DS) && (nand_hdr_type != NAND_HDR_O3DS))) {
        FileClose();
        Debug("NAND header not recognized");
        return 1;
    }
    // header integrity check - skip for O3DS headers on N3DS
    if (!((GetUnitPlatform() == PLATFORM_N3DS) && (nand_hdr_type == NAND_HDR_O3DS))) {
        if (CheckNandHeaderIntegrity(header) != 0) {
            FileClose();
            Debug("NAND header integrity check failed!");
            return 1;
        }
    }
    
    // magic number / crypto check
    for (u32 p_num = 0; p_num < 6; p_num++) { 
        PartitionInfo* partition = partitions + p_num; // workaround for files, not possible with GetPartitionInfo()
        if ((p_num == 5) && (GetUnitPlatform() == PLATFORM_N3DS)) // special N3DS partition types
            partition = (nand_hdr_type == NAND_HDR_N3DS) ? partitions + 6 : partitions + 7;
        CryptBufferInfo info = {.keyslot = partition->keyslot, .setKeyY = 0, .size = 16, .buffer = header, .mode = partition->mode};
        if (GetNandCtr(info.ctr, partition->offset) != 0) {
            FileClose();
            return 1;
        }
        if (!DebugFileRead(header, 16, partition->offset)) {
            FileClose();
            return 1;
        }
        CryptBuffer(&info);
        if ((partition->magic[0] != 0xFF) && (memcmp(partition->magic, header, 8) != 0)) {
            FileClose();
            Debug("Not a proper NAND backup for this 3DS");
            if (partition->keyslot == 0x05)
                Debug("(or slot0x05keyY not set up)");
            return 1;
        }
    }
    
    // firm hash check
    if (check_firm) {
        for (u32 f_num = 0; f_num < 2; f_num++) {
            u8* firm = BUFFER_ADDRESS;
            PartitionInfo* partition = partitions + 3 + f_num;
            CryptBufferInfo info = {.keyslot = partition->keyslot, .setKeyY = 0, .size = 0x200, .buffer = firm, .mode = partition->mode};
            if ((GetNandCtr(info.ctr, partition->offset) != 0) || (!DebugFileRead(firm, 0x200, partition->offset))) {
                FileClose();
                return 1;
            }
            CryptBuffer(&info);
            u32 firm_size = CheckFirmSize(firm, 0x200); // check the first 0x200 byte to get actual size
            if (firm_size != 0) { // check the remaining bytes
                info.buffer = firm + 0x200;
                info.size = firm_size - 0x200;
                if ((!DebugFileRead(firm + 0x200, firm_size - 0x200, partition->offset + 0x200))) {
                    FileClose();
                    return 1;
                }
                CryptBuffer(&info);
                firm_size = CheckFirmSize(firm, firm_size);
            }
            
            if (firm_size == 0) {
                if ((f_num == 0) && ((*(vu32*) 0x101401C0) == 0)) {
                    Debug("FIRM0 is corrupt (non critical)");
                    Debug("(this is expected with a9lh)");
                } else {
                    Debug("FIRM%i is corrupt", f_num);
                    FileClose();
                    return 1;
                }
            }
        }
    }
    
    FileClose();
    
    
    return 0;
}

u32 OutputFileNameSelector(char* filename, const char* basename, char* extension) {
    char bases[4][64] = { 0 };
    char serial[16] = { 0 };
    char* dotpos = NULL;
    
    // build first base name and extension
    strncpy(bases[0], basename, 63);
    dotpos = strrchr(bases[0], '.');
    
    if (dotpos) {
        *dotpos = '\0';
        if (!extension)
            extension = dotpos + 1;
    }
    
    // build other two base names
    snprintf(bases[1], 63, "%s_%s", (GetSerial(serial) == 0) ? serial : "UNK", bases[0]);
    snprintf(bases[2], 63, "%s_%s", bases[0], (emunand_header) ? "emu" : "sys");
    snprintf(bases[3], 63, "%s%s" , (emunand_header) ? "emu" : "sys", bases[0]);
    
    u32 fn_id = (emunand_header) ? 1 : 0;
    u32 fn_num = 0;
    bool exists = false;
    char extstr[16] = { 0 };
    if (extension)
        snprintf(extstr, 15, ".%s", extension);
    DebugColor(COLOR_ASK, "Use arrow keys and <A> to choose a name");
    while (true) {
        char numstr[2] = { 0 };
        // build and output file name (plus "(!)" if existing)
        numstr[0] = (fn_num > 0) ? '0' + fn_num : '\0';
        snprintf(filename, 63, "%s%s%s", bases[fn_id], numstr, extstr);
        if ((exists = FileOpen(filename)))
            FileClose();
        DebugColor(COLOR_SELECT, "\r%s%s", filename, (exists) ? " (!)" : "");
        // user input routine
        u32 pad_state = InputWait();
        if (pad_state & BUTTON_DOWN) { // increment filename id
            fn_id = (fn_id + 1) % 4;
        } else if (pad_state & BUTTON_UP) { // decrement filename id
            fn_id = (fn_id > 0) ? fn_id - 1 : 3;
        } else if ((pad_state & BUTTON_RIGHT) && (fn_num < 9)) { // increment number
            fn_num++;
        } else if ((pad_state & BUTTON_LEFT) && (fn_num > 0)) { // decrement number
            fn_num--;
        } else if (pad_state & BUTTON_A) {
           DebugColor(COLOR_ASK, "%s%s", filename, (exists) ? " (!)" : "");
            break;
        } else if (pad_state & BUTTON_B) {
            DebugColor(COLOR_ASK, "(cancelled by user)");
            return 2;
        }
    }
    
    // overwrite confirmation
    if (exists) {
        DebugColor(COLOR_ASK, "Press <A> to overwrite existing file");
        while (true) {
            u32 pad_state = InputWait();
            if (pad_state & BUTTON_A) {
                break;
            } else if (pad_state & BUTTON_B) {
                DebugColor(COLOR_ASK, "(cancelled by user)");
                return 2;
            }
        }
    }
    
    return 0;
}

u32 InputFileNameSelector(char* filename, const char* basename, char* extension, u8* magic, u32 msize, u32 fsize, bool accept_bigger) {
    char** fnptr = (char**) 0x20400000; // allow using 0x8000 byte
    char* fnlist = (char*) 0x20408000; // allow using 0x80000 byte
    u32 n_names = 0;
    
    // get base name, extension
    char base[64] = { 0 };
    if (basename != NULL) {
        // build base name and extension
        strncpy(base, basename, 63);
        char* dotpos = strrchr(base, '.');
        if (dotpos) {
            *dotpos = '\0';
            if (!extension)
                extension = dotpos + 1;
        }
    }
    
    // limit magic number size
    if (msize > 0x200)
        msize = 0x200;
    
    // pass #1 -> work dir
    // pass #2 -> root dir
    for (u32 i = 0; i < 2; i++) {
        // get the file list - try work directory first
        if (!GetFileList((i) ? "/" : GetWorkDir(), fnlist, 0x80000, false, true, false))
            continue;
        
        // parse the file names list for usable entries
        for (char* fn = strtok(fnlist, "\n"); fn != NULL; fn = strtok(NULL, "\n")) {
            u8 data[0x200];
            char* dotpos = strrchr(fn, '.');
            if (strrchr(fn, '/'))
                fn = strrchr(fn, '/') + 1;
            if (strnlen(fn, 128) > 63)
                continue; // file name too long
            if ((basename != NULL) && !strcasestr(fn, base))
                continue; // basename check failed
            if ((extension != NULL) && (dotpos != NULL) && (strncasecmp(dotpos + 1, extension, strnlen(extension, 16))))
                continue; // extension check failed
            else if ((extension == NULL) != (dotpos == NULL))
                continue; // extension check failed
            if (!FileOpen(fn))
                continue; // file can't be opened
            if (fsize && (FileGetSize() < fsize)) {
                FileClose();
                continue; // file minimum size check failed
            } else if (fsize && !accept_bigger && (FileGetSize() != fsize)) {
                FileClose();
                continue; // file exact size check failed
            }
            if (msize) {
                if (FileRead(data, msize, 0) != msize) {
                    FileClose();
                    continue; // can't be read
                }
                if (memcmp(data, magic, msize) != 0) {
                    FileClose();
                    continue; // magic number does not match
                }
            }
            FileClose();
            // this is a match - keep it
            fnptr[n_names++] = fn;
            if (n_names * sizeof(char**) >= 0x8000)
                return 1;
        }
        if (n_names)
            break;
    }
    if (n_names == 0) {
        Debug("No usable file found");
        return 1;
    }
    
    u32 index = 0;
    DebugColor(COLOR_ASK, "Use arrow keys and <A> to choose a file");
    while (true) {
        snprintf(filename, 63, "%s", fnptr[index]);
        DebugColor(COLOR_SELECT, "\r%s", filename);
        u32 pad_state = InputWait();
        if (pad_state & BUTTON_DOWN) { // next filename
            index = (index + 1) % n_names;
        } else if (pad_state & BUTTON_UP) { // previous filename
            index = (index > 0) ? index - 1 : n_names - 1;
        } else if (pad_state & BUTTON_A) {
            DebugColor(COLOR_ASK, "%s", filename);
            break;
        } else if (pad_state & BUTTON_B) {
            DebugColor(COLOR_ASK, "(cancelled by user)");
            return 2;
        }
    }
    
    return 0;
}

PartitionInfo* GetPartitionInfo(u32 partition_id)
{
    u32 partition_num = 0;
    
    if (partition_id & P_CTRNAND) {
        partition_num = (CheckNandHeaderType(NULL) == NAND_HDR_O3DS) ? 5 : 6;
    } else if (partition_id & P_CTRFULL) {
        partition_num = (CheckNandHeaderType(NULL) == NAND_HDR_O3DS) ? 8 : 9;
    } else {
        for(; !(partition_id & (1<<partition_num)) && (partition_num < 32); partition_num++);
    }
    
    return (partition_num >= 32) ? NULL : &(partitions[partition_num]);
}

u32 GetNandCtr(u8* ctr, u32 offset)
{
    static bool initial_setup_done = false;
    static u8 CtrNandCtr[16];
    static u8 TwlNandCtr[16];
    
    if (!initial_setup_done) {
        // calculate CTRNAND/TWL ctr from NAND CID
        u8 NandCid[16];
        u8 shasum[32];
        
        sdmmc_get_cid(1, (uint32_t*) NandCid);
        sha_quick(shasum, NandCid, 16, SHA256_MODE);
        memcpy(CtrNandCtr, shasum, 16);
        
        sha_quick(shasum, NandCid, 16, SHA1_MODE);
        for(u32 i = 0; i < 16; i++) // little endian and reversed order
            TwlNandCtr[i] = shasum[15-i];
        
        initial_setup_done = true;
    }
    
    // get the correct CTR and increment counter
    memcpy(ctr, (offset >= 0x0B100000) ? CtrNandCtr : TwlNandCtr, 16);
    add_ctr(ctr, offset / 0x10);

    return 0;
}

u32 DecryptNandToMem(u8* buffer, u32 offset, u32 size, PartitionInfo* partition)
{
    CryptBufferInfo info = {.keyslot = partition->keyslot, .setKeyY = 0, .size = size, .buffer = buffer, .mode = partition->mode};
    if(GetNandCtr(info.ctr, offset) != 0)
        return 1;
    
    if (offset % NAND_SECTOR_SIZE) {
        Debug("Bad NAND offset alignment");
        return 1;
    }

    u32 n_sectors = (size + NAND_SECTOR_SIZE - 1) / NAND_SECTOR_SIZE;
    u32 start_sector = offset / NAND_SECTOR_SIZE;
    if (ReadNandSectors(start_sector, n_sectors, buffer) != 0) {
        Debug("%sNAND read error", (emunand_header) ? "Emu" : "Sys");
        return 1;
    }
    CryptBuffer(&info);

    return 0;
}

u32 DecryptNandToFile(const char* filename, u32 offset, u32 size, PartitionInfo* partition, u8* sha256)
{
    u8* buffer = BUFFER_ADDRESS;
    u32 result = 0;

    if (!DebugCheckFreeSpace(size))
        return 1;
    
    if (!DebugFileCreate(filename, true))
        return 1;

    if (sha256)
        sha_init(SHA256_MODE);
    for (u32 i = 0; i < size; i += NAND_SECTOR_SIZE * SECTORS_PER_READ) {
        u32 read_bytes = min(NAND_SECTOR_SIZE * SECTORS_PER_READ, (size - i));
        ShowProgress(i, size);
        if ((DecryptNandToMem(buffer, offset + i, read_bytes, partition) != 0) ||
            !DebugFileWrite(buffer, read_bytes, i)) {
            result = 1;
            break;
        }
        if (sha256)
            sha_update(buffer, read_bytes);
    }
    if (sha256)
        sha_get(sha256);

    ShowProgress(0, 0);
    FileClose();

    return result;
}

u32 DumpNand(u32 param)
{
    char filename[64];
    u8* buffer = BUFFER_ADDRESS;
    u32 nand_size = (param & NB_MINSIZE) ? NAND_MIN_SIZE : getMMCDevice(0)->total_size * NAND_SECTOR_SIZE;
    u32 result = 0;
    
    
    // check actual EmuNAND size
    if (emunand_header && (emunand_offset + getMMCDevice(0)->total_size > NumHiddenSectors()))
        nand_size = NAND_MIN_SIZE;
    
    Debug("Dumping %sNAND. Size (MB): %u", (param & N_EMUNAND) ? "Emu" : "Sys", nand_size / (1024 * 1024));
    
    if (OutputFileNameSelector(filename, (param & NB_MINSIZE) ? "NANDmin.bin" : "NAND.bin", NULL) != 0)
        return 2;
    if (!DebugFileCreate(filename, true))
        return 1;
    
    if (!DebugCheckFreeSpace(nand_size))
        return 1;

    sha_init(SHA256_MODE);
    u32 n_sectors = nand_size / NAND_SECTOR_SIZE;
    for (u32 i = 0; i < n_sectors; i += SECTORS_PER_READ) {
        u32 read_sectors = min(SECTORS_PER_READ, (n_sectors - i));
        ShowProgress(i, n_sectors);
        if (ReadNandSectors(i, read_sectors, buffer) != 0)  {
            Debug("%sNAND read error", (emunand_header) ? "Emu" : "Sys");
            result = 1;
            break;
        }
        if (!DebugFileWrite(buffer, NAND_SECTOR_SIZE * read_sectors, i * NAND_SECTOR_SIZE)) {
            result = 1;
            break;
        }
        sha_update(buffer, NAND_SECTOR_SIZE * read_sectors);
    }
    if (FileGetSize() < NAND_MIN_SIZE) result = 1; // very improbable
    ShowProgress(0, 0);
    FileClose();
    
    if (result == 0) {
        char hashname[64];
        u8 shasum[32];
        sha_get(shasum);
        Debug("NAND dump SHA256: %08X...", getbe32(shasum));
        snprintf(hashname, 64, "%s.sha", filename);
        Debug("Store to %s: %s", hashname, (FileDumpData(hashname, shasum, 32) == 32) ? "ok" : "failed");
    }

    return result;
}

u32 GetNandHeader(u8* header)
{
    if (ReadNandSectors(0, 1, header) != 0)  {
        Debug("%sNAND read error", (emunand_header) ? "Emu" : "Sys");
        return 1;
    }
    
    return 0;
}

u32 DumpNandHeader(u32 param)
{
    char filename[64];
    u8* header = BUFFER_ADDRESS;
    
    Debug("Dumping %sNAND header. Size (Byte): 512", (param & N_EMUNAND) ? "Emu" : "Sys");
    
    if (!DebugCheckFreeSpace(512))
        return 1;
    
    if (OutputFileNameSelector(filename, "NAND_hdr.bin", NULL) != 0)
        return 1;

    if (GetNandHeader(header) != 0)
        return 1;
    if (FileDumpData(filename, header, 0x200) != 0x200) {
        Debug("Error writing file");
        return 1;
    }

    return 0;
}

u32 DecryptNandPartition(u32 param)
{
    PartitionInfo* p_info = NULL;
    char filename[64];
    u8 magic[NAND_SECTOR_SIZE];
    
    p_info = GetPartitionInfo(param);
    if (p_info == NULL)
        return 1;
    
    Debug("Dumping & Decrypting %s, size (MB): %u", p_info->name, p_info->size / (1024 * 1024));
    if (DecryptNandToMem(magic, p_info->offset, 16, p_info) != 0)
        return 1;
    if ((p_info->magic[0] != 0xFF) && (memcmp(p_info->magic, magic, 8) != 0)) {
        Debug("Corrupt partition or decryption error");
        if (p_info->keyslot == 0x05)
            Debug("(or slot0x05keyY not set up)");
        return 1;
    }
    if (OutputFileNameSelector(filename, p_info->name, "bin") != 0)
        return 1;
    
    return DecryptNandToFile(filename, p_info->offset, p_info->size, p_info, NULL);
}

u32 DecryptSector0x96(u32 param)
{
    (void) (param); // param is unused here
    u8* sector0x96 = BUFFER_ADDRESS;
    CryptBufferInfo info = {.keyslot = 0x11, .setKeyY = 0, .size = 0x200, .buffer = sector0x96, .mode = AES_CNT_ECB_DECRYPT_MODE};
    char filename[64];
    
    // setup key 0x11
    if (SetupSector0x96Key0x11() != 0)
        return 1;
    
    // read & decrypt encrypted sector0x96
    if (ReadNandSectors(0x96, 1, sector0x96) != 0) {
        Debug("%sNAND read error", (emunand_header) ? "Emu" : "Sys");
        return 1;
    }
    CryptBuffer(&info);
    
    // write to file
    if (OutputFileNameSelector(filename, "sector0x96.bin", NULL) != 0)
        return 1;
    if (FileDumpData(filename, sector0x96, 0x200) != 0x200) {
        Debug("Error writing file");
        return 1;
    }
    
    return 0;
}

u32 EncryptMemToNand(u8* buffer, u32 offset, u32 size, PartitionInfo* partition)
{
    CryptBufferInfo info = {.keyslot = partition->keyslot, .setKeyY = 0, .size = size, .buffer = buffer, .mode = partition->mode};
    if(GetNandCtr(info.ctr, offset) != 0)
        return 1;
    
    if (offset % NAND_SECTOR_SIZE) {
        Debug("Bad NAND offset alignment");
        return 1;
    }

    u32 n_sectors = (size + NAND_SECTOR_SIZE - 1) / NAND_SECTOR_SIZE;
    u32 start_sector = offset / NAND_SECTOR_SIZE;
    CryptBuffer(&info);
    if (WriteNandSectors(start_sector, n_sectors, buffer) != 0) {
        Debug("%sNAND write error", (emunand_header) ? "Emu" : "Sys");
        return 1;
    }

    return 0;
}

u32 EncryptFileToNand(const char* filename, u32 offset, u32 size, PartitionInfo* partition)
{
    u8* buffer = BUFFER_ADDRESS;
    u32 result = 0;

    if (!DebugFileOpen(filename))
        return 1;
    
    u32 fsize = FileGetSize();
    if (fsize != size) {
        if (align(fsize, NAND_SECTOR_SIZE) == align(size, NAND_SECTOR_SIZE)) {
            Debug("Warning: %s minor size mismatch", filename);
            Debug("(handled automatically)");
            size = fsize;
        } else {
            Debug("%s has wrong size", filename);
            FileClose();
            return 1;
        }
    }

    for (u32 i = 0; i < size; i += NAND_SECTOR_SIZE * SECTORS_PER_READ) {
        u32 read_bytes = min(NAND_SECTOR_SIZE * SECTORS_PER_READ, (size - i));
        ShowProgress(i, size);
        if (!DebugFileRead(buffer, read_bytes, i) ||
            (EncryptMemToNand(buffer, offset + i, read_bytes, partition) != 0)) {
            result = 1;
            break;
        }
    }

    ShowProgress(0, 0);
    FileClose();

    return result;
}

u32 RestoreNand(u32 param)
{
    char filename[64];
    u8* buffer = BUFFER_ADDRESS;
    u32 nand_size = getMMCDevice(0)->total_size * NAND_SECTOR_SIZE;
    u32 result = 0;

    // developer screwup protection
    if (!(param & N_NANDWRITE))
        return 1;
    if (!(param & N_EMUNAND) && !(param & NR_KEEPA9LH) && !(param & N_A9LHWRITE))
        return 1;
        
    // user file select
    if (InputFileNameSelector(filename, "NAND.bin", NULL, NULL, 0, NAND_MIN_SIZE, true) != 0)
        return 1;
    
    // check if actually on A9LH for the special option
    if (!emunand_header && (param & NR_KEEPA9LH) && (*(u32*) 0x101401C0) != 0) {
        Debug("A9LH not detected, use regular restore");
        return 1;
    }
    
    // safety checks
    if (!(param & NR_NOCHECKS)) {
        Debug("Validating NAND dump %s...", filename);
        if (CheckNandDumpIntegrity(filename, !(param & NR_KEEPA9LH)) != 0)
            return 1;
    }
    
    // check EmuNAND partition size
    if (emunand_header) {
        if (((NumHiddenSectors() - emunand_offset) < (NAND_MIN_SIZE / NAND_SECTOR_SIZE)) || (NumHiddenSectors() < emunand_header)) {
            Debug("Error: Not enough space in EmuNAND partition");
            return 1; // this really should not happen
        } else if (emunand_offset + getMMCDevice(0)->total_size > NumHiddenSectors()) {
            Debug("Small EmuNAND, using minimum size...");
            nand_size = NAND_MIN_SIZE;
        }
    }
    
    // open file, adjust size if required
    // NAND dump has at least min size (checked 2x at this point)
    if (!FileOpen(filename))
        return 1;
    if (FileGetSize() < nand_size) {
        Debug("Small NAND backup, using minimum size...");
        nand_size = NAND_MIN_SIZE;
    }
    
    Debug("Restoring %sNAND. Size (MB): %u", (param & N_EMUNAND) ? "Emu" : "Sys", nand_size / (1024 * 1024));

    u32 n_sectors = nand_size / NAND_SECTOR_SIZE;
    if (!(param & NR_KEEPA9LH)) { // standard, full restore
        for (u32 i = 0; i < n_sectors; i += SECTORS_PER_READ) {
            u32 read_sectors = min(SECTORS_PER_READ, (n_sectors - i));
            ShowProgress(i, n_sectors);
            if (!DebugFileRead(buffer, NAND_SECTOR_SIZE * read_sectors, i * NAND_SECTOR_SIZE)) {
                result = 1;
                break;
            }
            if (WriteNandSectors(i, read_sectors, buffer) != 0) {
                Debug("%sNAND write error", (emunand_header) ? "Emu" : "Sys");
                result = 1;
                break;
            }
        }
    } else { // ARM9loaderhax preserving restore
        for (u32 section = 0; section < 3; section++) {
            u32 start_sector, end_sector;
            if (section == 0) { // NAND header & sectors until 0x96
                start_sector = 0x00;
                end_sector = 0x96;
            } else if (section == 1) { // TWLN, TWLP & AGBSAVE
                start_sector = partitions[0].offset / NAND_SECTOR_SIZE;
                end_sector = ((partitions[2].offset + partitions[2].size) - partitions[0].offset) / NAND_SECTOR_SIZE;
            } else { // CTRNAND (full size) (FIRM skipped)
                start_sector = 0x0B930000 / NAND_SECTOR_SIZE;
                end_sector = n_sectors;
            }
            for (u32 i = start_sector; i < end_sector; i += SECTORS_PER_READ) {
                u32 read_sectors = min(SECTORS_PER_READ, (end_sector - i));
                ShowProgress(i, n_sectors);
                if (!DebugFileRead(buffer, NAND_SECTOR_SIZE * read_sectors, i * NAND_SECTOR_SIZE)) {
                    result = 1;
                    break;
                }
                if (WriteNandSectors(i, read_sectors, buffer) != 0) {
                    Debug("%sNAND write error", (emunand_header) ? "Emu" : "Sys");
                    result = 1;
                    break;
                }
            }
        }
    }

    ShowProgress(0, 0);
    FileClose();

    return result;
}

u32 PutNandHeader(u8* header)
{
    u8 header_old[0x200];
    
    if (header != NULL) { // if header for injection is provided
        // make a backup of the genuine header @0x400 (if genuine) first
        if ((ReadNandSectors(0, 1, header_old) == 0) && (CheckNandHeaderIntegrity(header_old) == 0))
            WriteNandSectors(2, 1, header_old); // only basic checks here - this is for last resort
    } else { // header == NULL -> restore genuine header
        // grab the genuine header backup @0x400
        if ((ReadNandSectors(2, 1, header_old) == 0) &&
            ((CheckNandHeaderType(header_old) == NAND_HDR_UNK) || (CheckNandHeaderIntegrity(header_old) != 0))) {
            Debug("Genuine header backup not found");
            return 1;
        }
        // provide old header for write
        header = header_old;
    }
    
    // write provided header
    if (WriteNandSectors(0, 1, header) != 0) {
        Debug("%sNAND write error", (emunand_header) ? "Emu" : "Sys");
        return 1;
    }
    
    return 0;
}

u32 RestoreNandHeader(u32 param)
{
    char filename[64];
    u8* header = BUFFER_ADDRESS;

    // developer screwup protection
    if (!(param & N_NANDWRITE))
        return 1;
    if (!(param & N_EMUNAND) && !(param & N_A9LHWRITE))
        return 1;  
        
    // user file select
    if (InputFileNameSelector(filename, "NAND_hdr.bin", NULL, NULL, 0, 512, false) != 0)
        return 1;
    // read file to mem, check header
    if (FileGetData(filename, header, 512, 0) != 512) {
        Debug("File has bad size");
        return 1; // this should not happen
    }
    // header integrity check - skip for O3DS headers on N3DS
    if (!((GetUnitPlatform() == PLATFORM_N3DS) && (CheckNandHeaderType(header) == NAND_HDR_O3DS))) {
        if (CheckNandHeaderIntegrity(header) != 0) {
            FileClose();
            Debug("NAND header integrity check failed!");
            return 1;
        }
    }
    
    Debug("Restoring %sNAND header. Size (Byte): 512", (param & N_EMUNAND) ? "Emu" : "Sys");
    if (PutNandHeader(header) != 0)
        return 1;

    return 0;
}

u32 InjectNandPartition(u32 param)
{
    PartitionInfo* p_info = NULL;
    u8 header[NAND_SECTOR_SIZE];
    char filename[64];
    bool is_firm = param & (P_FIRM0|P_FIRM1);
    
    // developer screwup protection
    if (!(param & N_NANDWRITE))
        return 1;
    if (is_firm && !(param & N_EMUNAND) && !(param & N_A9LHWRITE))
        return 1;
    
    p_info = GetPartitionInfo(param);
    if (p_info == NULL)
        return 1;
    
    Debug("Encrypting & Injecting %s, size (MB): %u", p_info->name, p_info->size / (1024 * 1024));
    // User file select
    if (InputFileNameSelector(filename, p_info->name, "bin",
        p_info->magic, (p_info->magic[0] != 0xFF) ? 8 : 0,
        is_firm ? 0x200 : p_info->size, is_firm ? true : false) != 0)
        return 1;
    
    // Encryption check
    if (DecryptNandToMem(header, p_info->offset, 16, p_info) != 0)
        return 1;
    if ((p_info->magic[0] != 0xFF) && (memcmp(p_info->magic, header, 8) != 0)) {
        Debug("Corrupt partition or decryption error");
        if (p_info->keyslot == 0x05)
            Debug("(or slot0x05keyY not set up)");
        return 1;
    }
    
    // FIRM check
    if (is_firm) {
        if (!FileOpen(filename))
            return 1; // this should open without problem
        if (!DebugFileRead(header, 0x200, 0))
            return 1; // size was already checked
        u32 file_size = FileGetSize();
        u32 firm_size = CheckFirmSize(header, 0x200);
        FileClose();
        if (!firm_size || (firm_size > file_size)) {
            Debug("FIRM is corrupt, won't inject");
            return 1;
        } else if (file_size > p_info->size) {
            Debug("File has bad size, won't inject");
            return 1;
        } else if (file_size < p_info->size) {
            return EncryptFileToNand(filename, p_info->offset, file_size, p_info);
        }
    }
    
    return EncryptFileToNand(filename, p_info->offset, p_info->size, p_info);
}

u32 InjectSector0x96(u32 param)
{
    // from: https://github.com/AuroraWright/SafeA9LHInstaller/blob/master/source/installer.c#L9-L17
    static const u8 sectorHash[0x20] = {
        0x82, 0xF2, 0x73, 0x0D, 0x2C, 0x2D, 0xA3, 0xF3, 0x01, 0x65, 0xF9, 0x87, 0xFD, 0xCC, 0xAC, 0x5C,
        0xBA, 0xB2, 0x4B, 0x4E, 0x5F, 0x65, 0xC9, 0x81, 0xCD, 0x7B, 0xE6, 0xF4, 0x38, 0xE6, 0xD9, 0xD3
    };
    static const u8 sectorA9lhv1Hash[0x20] = {
        0x89, 0x72, 0xAD, 0x96, 0x42, 0x6F, 0x8A, 0x9B, 0x3E, 0xEB, 0x4C, 0xC9, 0xCC, 0xEF, 0x0E, 0xF4,
        0x5B, 0x91, 0x91, 0xFB, 0xEE, 0xFC, 0x7E, 0x30, 0xB4, 0x8E, 0xE3, 0x1A, 0x3E, 0xD0, 0x42, 0x3A
    };
    static const u8 sectorA9lhv2Hash[0x20] = {
        0x72, 0x76, 0xA3, 0x57, 0xEE, 0xE8, 0xF7, 0x8D, 0x13, 0x4F, 0xE7, 0xDC, 0x1A, 0x8C, 0x2D, 0xBC,
        0x27, 0xBA, 0x7F, 0x3C, 0x7C, 0x16, 0xF5, 0x7D, 0xD6, 0x2F, 0x24, 0xB5, 0x06, 0x1D, 0x3D, 0x63
    };

    u8* sector0x96 = BUFFER_ADDRESS;
    CryptBufferInfo info = {.keyslot = 0x11, .setKeyY = 0, .size = 0x200, .buffer = sector0x96, .mode = AES_CNT_ECB_ENCRYPT_MODE};
    char filename[64];
    u8 sha256sum[32];
    
    // developer screwup protection
    if (!(param & N_NANDWRITE))
        return 1;
    if (!(param & N_EMUNAND) && !(param & N_A9LHWRITE))
        return 1;
    
    // read from file
    if (InputFileNameSelector(filename, "sector0x96.bin", NULL, NULL, 0, 0x200, false) != 0)
        return 1;
    if (FileGetData(filename, sector0x96, 0x200, 0) != 0x200)
        return 1;
    
    // check loaded sector
    sha_quick(sha256sum, sector0x96, 0x200, SHA256_MODE);
    if (memcmp(sha256sum, sectorHash, 32) == 0) {
        Debug("Detected: standard sector0x96");
    } else if (memcmp(sha256sum, sectorA9lhv1Hash, 32) == 0) {
        Debug("Detected: a9lh v1 sector0x96");
    } else if (memcmp(sha256sum, sectorA9lhv2Hash, 32) == 0) {
        Debug("Detected: a9lh v2 sector0x96");
    } else {
        DebugColor(COLOR_ASK, "Unknown content, press <A> to inject");
        while (true) {
            u32 pad_state = InputWait();
            if (pad_state & BUTTON_A) {
                break;
            } else if (pad_state & BUTTON_B) {
                DebugColor(COLOR_ASK, "(cancelled by user)");
                return 1;
            }
        }
    }
        
    // setup key 0x11
    if (SetupSector0x96Key0x11() != 0)
        return 1;
    
    // encrypt & write encrypted sector0x96
    CryptBuffer(&info);
    if (WriteNandSectors(0x96, 1, sector0x96) != 0) {
        Debug("%sNAND write error", (emunand_header) ? "Emu" : "Sys");
        return 1;
    }
    
    return 0;
}

u32 DumpGbaVcSave(u32 param)
{
    (void) (param); // param is unused here
    const u8 magic[8] = { 0x2E, 0x53, 0x41, 0x56, 0xFF, 0xFF, 0xFF, 0xFF };
    PartitionInfo* p_info = GetPartitionInfo(P_AGBSAVE);
    u8* agbsave = BUFFER_ADDRESS;
    u32 save_size = 0;
    char filename[64];
    
    if (CheckKeySlot(0x24, 'Y')) {
        Debug("slot0x24KeyY not set up");
        return 1;
    }
    
    Debug("Dumping & Decrypting GBA VC Save...");
    if (DecryptNandToMem(agbsave, p_info->offset, p_info->size, p_info) != 0)
        return 1;
    
    // check AGBSAVE header
    if (memcmp(agbsave, magic, 8) != 0) {
        Debug("AGBSAVE is corrupted or empty");
        return 1;
    }
    
    // get save size
    save_size = getle32(agbsave + 0x54);
    if (save_size + 0x200 > p_info->size) {
        Debug("Bad save size");
        return 1;
    }
    
    // check CMAC
    u8 cmac[16] __attribute__((aligned(32)));
    u8 shasum[32];
    sha_quick(shasum, agbsave + 0x30, (0x200 - 0x30) + save_size, SHA256_MODE);
    use_aeskey(0x24);
    aes_cmac(shasum, cmac, 2);
    if (memcmp(agbsave + 0x10, cmac, 16) != 0)
        Debug("Warning: current CMAC does not match");
    
    // dump the file
    if (OutputFileNameSelector(filename, "gbavc.sav", NULL) != 0)
        return 1;
    if (FileDumpData(filename, agbsave + 0x200, save_size) != save_size) {
        Debug("Error writing file");
        return 1;
    }
    
    return 0;
}

u32 InjectGbaVcSave(u32 param)
{
    (void) (param); // param is unused here
    const u8 magic[8] = { 0x2E, 0x53, 0x41, 0x56, 0xFF, 0xFF, 0xFF, 0xFF };
    PartitionInfo* p_info = GetPartitionInfo(P_AGBSAVE);
    u8* agbsave = BUFFER_ADDRESS;
    u32 save_size = 0;
    char filename[64];
    
    if (!(param & N_NANDWRITE)) // developer screwup protection
        return 1;
    
    if (CheckKeySlot(0x24, 'Y')) {
        Debug("slot0x24KeyY not set up");
        return 1;
    }
    
    if (DecryptNandToMem(agbsave, p_info->offset, 0x200, p_info) != 0)
        return 1;
    
    // check AGBSAVE header
    if (memcmp(agbsave, magic, 8) != 0) {
        Debug("AGBSAVE is corrupted or empty");
        return 1;
    }
    
    // get save size
    save_size = getle32(agbsave + 0x54);
    if (save_size + 0x200 > p_info->size) {
        Debug("Bad save size");
        return 1;
    }
    
    // get the save from file
    Debug("Encrypting & Injecting GBA VC Save...");
    if (InputFileNameSelector(filename, "gbavc.sav", NULL, NULL, 0, save_size, true) != 0)
        return 1;
    if (FileGetData(filename, agbsave + 0x200, save_size, 0) != save_size)
        return 1;
    
    // fix CMAC
    u8* cmac = agbsave + 0x10;
    u8 shasum[32];
    sha_quick(shasum, agbsave + 0x30, (0x200 - 0x30) + save_size, SHA256_MODE);
    use_aeskey(0x24);
    aes_cmac(shasum, cmac, 2);
    
    // set CFG_BOOTENV = 0x7 so the save is taken over
    // https://www.3dbrew.org/wiki/CONFIG_Registers#CFG_BOOTENV
    *(u32*) 0x10010000 = 0x7;
    
    // inject to AGBSAVE partition
    return EncryptMemToNand(agbsave, p_info->offset, p_info->size, p_info);
}

u32 DecryptFirmArm9Mem(u8* firm, u32 f_size)
{
    static const u8 keyX0x15hash[32] = {
        0x42, 0xC3, 0xB3, 0x7A, 0xD6, 0x0F, 0x49, 0x43, 0xA4, 0x01, 0x38, 0x77, 0x81, 0xD4, 0xC0, 0x53,
        0x4E, 0x4A, 0xE4, 0x5B, 0x64, 0x39, 0xEC, 0x69, 0x6C, 0xB0, 0xBD, 0x55, 0x11, 0x34, 0x29, 0xF1
    };
    
    if (!CheckFirmSize(firm, f_size)) {
        Debug("FIRM is corrupt");
        return 1;
    }
    
    // search for encrypted arm9 binary
    CryptBufferInfo info = {.keyslot = 0x11, .setKeyY = 0, .size = 16, .mode = AES_CNT_ECB_DECRYPT_MODE};
    if (SetupSecretKey0x11(0) != 0)
        return 1;
    u8* arm9bin;
    u32 bin_size;
    u8* keyX0x15;
    u32 section;
    for (section = 0; section < 4; section++) {
        u8 key[16];
        arm9bin = firm + getle32(firm + 0x40 + 0x00 + (0x30*section));
        bin_size = getle32(firm + 0x40 + 0x08 + (0x30*section));
        if (!bin_size)
            continue;
        memcpy(key, arm9bin, 16);
        info.buffer = key;
        CryptBuffer(&info);
        // check keyX0x15 hash (same for all)
        u8* shasum[32];
        sha_quick(shasum, key, 16, SHA256_MODE);
        if (memcmp(shasum, keyX0x15hash, 32) == 0) {
            memcpy(arm9bin, key, 16);
            keyX0x15 = arm9bin;
            break;
        }
    }
    
    Debug("FIRM size: %u Byte", f_size);
    
    if (section > 4) {
        Debug("Encrypted ARM9 binary: not found!");
        return 1;
    }
    
    Debug("Encrypted ARM9 binary: section %u", section);
    Debug("Section %u: %u Byte @ 0x%06X", section, bin_size, arm9bin - firm);
    
    u32 crypto_type = (arm9bin[0x53] == 0xFF) ? 0 : (arm9bin[0x53] == '1') ? 1 : 2;
    Debug("Crypto Type: %s", (crypto_type == 0) ? "< 9.5" : (crypto_type == 1) ? "9.5" : ">= 9.6");
    
    // get keyY0x15, setup key0x15
    u8* keyY0x15 = arm9bin + 0x10;
    setup_aeskeyX(0x15, keyX0x15);
    setup_aeskeyY(0x15, keyY0x15);
    use_aeskey(0x15);
    Debug("0x15 KeyX & KeyY: decrypted, set up");
    
    // key0x16 setup
    if (crypto_type) { // for FWs >= 9.5
        u8* keyX0x16 = arm9bin + 0x60;
        u8* keyY0x16 = keyY0x15;
        info.buffer = keyX0x16;
        if ((crypto_type == 2) && (SetupSecretKey0x11(1) != 0))
            return 1;
        CryptBuffer(&info);
        setup_aeskeyX(0x16, keyX0x16);
        setup_aeskeyY(0x16, keyY0x16);
        use_aeskey(0x16);
        Debug("0x16 KeyX & KeyY: decrypted, set up");
    }
    
    // get arm9 binary size
    u32 arm9bin_size = 0;
    for (u32 i = 0; (i < 8) && *(arm9bin + 0x30 + i); i++)
        arm9bin_size = (arm9bin_size * 10) + (*(arm9bin + 0x30 + i) - '0');
    if (arm9bin_size + 0x800 > bin_size) {
        Debug("Bad arm9 binary size (%u Byte)", arm9bin_size);
        return 1;
    }
    
    // decrypt arm9 binary
    Debug("Decrypting arm9 binary (%u Byte)...", arm9bin_size);
    info.buffer = arm9bin + 0x800;
    info.size = arm9bin_size;
    info.mode = AES_CNT_CTRNAND_MODE;
    info.keyslot = (crypto_type) ? 0x16 : 0x15;
    memcpy(info.ctr, arm9bin + 0x20, 16);
    CryptBuffer(&info);
    
    // recalculate section hash
    sha_quick(firm + 0x40 + 0x10 + (0x30*section), arm9bin, bin_size, SHA256_MODE);
    
    // mark FIRM as decrypted
    memcpy(firm, (u8*) "FIRMDEC", 7);
    
    return 0;
}

u32 DecryptFirmArm9File(u32 param)
{
    (void) (param); // param is unused here
    static u8 magic[8] = {0x46, 0x49, 0x52, 0x4D, 0x00, 0x00, 0x00, 0x00};
    u8* firm = BUFFER_ADDRESS;
    u32 f_size = 0;
    char filename[64];
    
    // user file select
    if (InputFileNameSelector(filename, NULL, "bin", magic, 8, 0x200, true) != 0)
        return 1;
    
    // open file, check size
    f_size = FileGetData(filename, firm, 0x400000, 0);
    if (f_size >= 0x400000) {
        Debug("File is >= 4MB"); // 4MB is the maximum
        return 1;
    }
    
    // decrypt ARM9 binary (if encrypted)
    if (DecryptFirmArm9Mem(firm, f_size) != 0)
        return 1;
    
    // inject back
    Debug("Done, injecting back..");
    if (FileDumpData(filename, firm, f_size) != f_size) {
        Debug("Error writing file");
        return 1;
    }
    
    return 0;
}

u32 ValidateNandDump(u32 param)
{
    (void) (param); // param is unused here
    char filename[64];
        
    // user file select
    if (InputFileNameSelector(filename, "NAND.bin", NULL, NULL, 0, NAND_MIN_SIZE, true) != 0)
        return 1;
    Debug("Validating NAND dump %s...", filename);
    if (CheckNandDumpIntegrity(filename, true) != 0)
        return 1;
    
    return 0;
}

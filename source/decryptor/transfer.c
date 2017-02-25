#include "fs.h"
#include "draw.h"
#include "hid.h"
#include "platform.h"
#include "decryptor/hashfile.h"
#include "decryptor/nand.h"
#include "decryptor/nandfat.h"
#include "decryptor/keys.h"
#include "decryptor/transfer.h"
#include "fatfs/sdmmc.h"
#include "NCSD_header_o3ds_hdr.h"
#include "NCSD_header_n3ds_hdr.h"
#include "NCSD_header_o3ds_dev_hdr.h"

#define O3DS_TRANSFER_SIZE  0x2F5D0000
#define N3DS_TRANSFER_SIZE  0x41ED0000


u32 NandTransfer(u32 param) {
    PartitionInfo* p_info = GetPartitionInfo(P_CTRFULL);
    PartitionInfo* p_firm0 = GetPartitionInfo(P_FIRM0);
    PartitionInfo* p_firm1 = GetPartitionInfo(P_FIRM1);
    u8* firm = BUFFER_ADDRESS;
    char filename[64] = { 0 };
    char hashname[64] = { 0 };
    bool a9lh = !(param & N_EMUNAND) && ((*(u32*) 0x101401C0) == 0);
    bool secnfo_transfer = true;
    u32 region = GetRegion();
    u32 imgsize = 0;
    
    
    // developer screwup protection
    if (!(param & N_NANDWRITE))
        return 1;
    
    // deeper check for a9lh
    if (!(param & N_EMUNAND) && !a9lh) {
        Debug("A9LH not detected, checking FIRM0...");
        if (DecryptNandToMem(firm, p_firm0->offset, p_firm0->size, p_firm0) != 0)
            return 1;
        if (CheckFirmSize(firm, p_firm0->size) == 0) {
            Debug("Not running from A9LH, but FIRM0 corrupted");
            Debug("Fix your FIRM0 or run from A9LH");
            return 1;
        }
    }
    
    // select CTRNAND image for transfer
    Debug("Select CTRNAND transfer image");
    if (InputFileNameSelector(filename, "ctrtransfer", "bin", NULL, 0, O3DS_TRANSFER_SIZE, true) != 0)
        return 1; // use O3DS size as minimum
    // check size of image
    if (!FileOpen(filename) || !(imgsize = FileGetSize()))
        return 1;
    FileClose();
    if (((GetUnitPlatform() == PLATFORM_3DS) && (imgsize != O3DS_TRANSFER_SIZE)) || // only O3DS size allowed on O3DS
        ((GetUnitPlatform() == PLATFORM_N3DS) && (imgsize != O3DS_TRANSFER_SIZE) && (imgsize != N3DS_TRANSFER_SIZE))) {
        Debug("Image has wrong size");
        return 1;
    }
    Debug("Image size is: %lu byte", imgsize);
    
    // SHA / region check
    if (param & TF_FORCED) {
        Debug("Forced transfer, not checking region");
    } else {
        u8 sha256[0x21]; // this needs a 0x20 + 0x01 byte .SHA file
        snprintf(hashname, 64, "%s.sha", filename);
        if (FileGetData(hashname, sha256, 0x21, 0) != 0x21) {
            Debug(".SHA file not found or too small");
            return 1;
        }
        // region check
        if (region != sha256[0x20]) {
            Debug("Region does not match");
            if (!a9lh) {
                Debug("Using SecureInfo_A from image");
                secnfo_transfer = false;
            }
        }
    }
    
    Debug("");
    Debug("Step #0: Optional NAND backup");
    Debug("Press <B> to skip and continue without backup");
    if (DumpNand(param | NB_MINSIZE) == 1) {
        DebugColor(COLOR_ASK, "Failed, <A> to continue, <B> to stop");
        if (!(InputWait() & BUTTON_A))
            return 1;
    }
    
    // check free space
    if (!DebugCheckFreeSpace(128 * 1024 * 1024)) {
        Debug("You need 128MB free to continue this operation");
        return 1;
    }
    
    Debug("");
    Debug("Step #1: .SHA verification of CTRNAND image...");
    if (param & TF_FORCED) {
        Debug("Forced transfer, skipping this step");
        Debug("Step #1 skipped");
    } else {
        Debug("Checking hash from .SHA file...");
        if (HashVerifyFile(filename) != 0) {
            Debug("Failed, image corrupt or modified!");
            return 1;
        }
        Debug("Step #1 success!");
    }
    
    Debug("");
    Debug("Step #2: Dumping transfer files");
    if ((DumpNandFile(FF_AUTONAME | F_SECUREINFO) != 0) ||
        (DumpNandFile(FF_AUTONAME | F_MOVABLE) != 0) ||
        (DumpNandFile(FF_AUTONAME | F_LOCALFRIEND) != 0) ||
        (DumpNandFile(FF_AUTONAME | F_CONFIGSAVE) != 0)) {
        if (!(param & TF_FORCED))
            return 1;
        Debug("Forced transfer, ignoring errors");
    }
    Debug("Step #2 success!");
        
    // check NAND header, restore if required (!!!)
    
    Debug("");
    Debug("Step #3: Injecting CTRNAND transfer image");
    if (p_info->size != imgsize) {
        u32 keys_type = GetUnitKeysType();
        if (GetUnitPlatform() != PLATFORM_N3DS) // extra safety, not actually needed
            return 1;
        Debug("Switching out NAND header first...");
        if (keys_type == KEYS_RETAIL) { // for retail N3DS
            if ((imgsize == O3DS_TRANSFER_SIZE) && // use hardcoded o3ds header
                ((NCSD_header_o3ds_hdr_size != 0x200) || (PutNandHeader((u8*) NCSD_header_o3ds_hdr) != 0))) {
                return 1;
            } else if ((imgsize == N3DS_TRANSFER_SIZE) && (PutNandHeader(NULL) != 0)) { // use N3DS header backup
                if ((param & TF_FORCED) && // use hardcoded N3DS header (from a different console)
                    (NCSD_header_n3ds_hdr_size == 0x200) && (PutNandHeader((u8*) NCSD_header_n3ds_hdr) == 0)) {
                    Debug("Forced transfer, using illegit N3DS header");
                } else {
                    return 1;
                }
            }
        } else if (keys_type == KEYS_DEVKIT) { // for devkit N3DS
            if ((imgsize == O3DS_TRANSFER_SIZE) && // use hardcoded o3ds header
                ((NCSD_header_o3ds_dev_hdr_size != 0x200) || (PutNandHeader((u8*) NCSD_header_o3ds_dev_hdr) != 0))) {
                return 1;
            } else if ((imgsize == N3DS_TRANSFER_SIZE) && (PutNandHeader(NULL) != 0)) { // use N3DS header backup
                return 1;
            }
        } else {
            Debug("Console type (retail/devkit) not detected!");
            return 1;
        }
        p_info = GetPartitionInfo(P_CTRFULL);
        if (p_info->size != imgsize)
            return 1;
    }
    Debug("Injecting %s (%lu MB)...", filename, p_info->size / (1024 * 1024));
    if (EncryptFileToNand(filename, p_info->offset, p_info->size, p_info) != 0)
        return 1;
    Debug("Step #3 success!");
    
    Debug("");
    Debug("Step #4: Injecting transfer files");
    if ((secnfo_transfer && (InjectNandFile(N_NANDWRITE | FF_AUTONAME | F_SECUREINFO) != 0)) ||
        (InjectNandFile(N_NANDWRITE | FF_AUTONAME | F_MOVABLE) != 0) ||
        (InjectNandFile(N_NANDWRITE | FF_AUTONAME | F_LOCALFRIEND) != 0) ||
        (InjectNandFile(N_NANDWRITE | FF_AUTONAME | F_CONFIGSAVE) != 0)) {
        if (!(param & TF_FORCED))
            return 1;
        Debug("Forced transfer, ignoring errors");
    }
    Debug("Step #4 success!");
    
    Debug("");
    Debug("Step #5: Fixing CMACs and paths");
    if (AutoFixCtrnand(N_NANDWRITE) != 0)
        return 1;
    Debug("Step #5 success!");
    
    if (a9lh) { // done at this step if running from a9lh
        Debug("");
        return 0;
    }
    
    Debug("");
    Debug("Step #6: Dumping and injecting NATIVE_FIRM");
    u32 firm_size = 0;
    if (DumpNcchFirm((p_info->keyslot == 0x4) ? 4 : 0, false, false) == 0) {
        Debug("NATIVE_FIRM found, injecting...");
        firm_size = FileGetData((p_info->keyslot == 0x4) ? "NATIVE_FIRM.bin" : "NATIVE_FIRM_N3DS.bin", firm, 0x400000, 0);
    } else {
        Debug("NATIVE_FIRM not found, failure!");
        return 1;
    }
    firm_size = CheckFirmSize(firm, firm_size);
    if (!firm_size)
        return 0;
    if ((EncryptMemToNand(firm, p_firm0->offset, firm_size, p_firm0) != 0) ||
        (EncryptMemToNand(firm, p_firm1->offset, firm_size, p_firm1) != 0))
        return 1;
    Debug("Step #6 success!");
    
    
    return 0;
}

u32 DumpTransferable(u32 param) {
    (void) param;
    PartitionInfo* p_info;
    char filename[64];
    char hashname[64];
    u8 magic[0x200];
    u8 sha256[0x21];
    
    p_info = GetPartitionInfo(P_CTRNAND);
    if ((DecryptNandToMem(magic, p_info->offset, 16, p_info) != 0) || (memcmp(p_info->magic, magic, 8) != 0)) {
        Debug("Corrupt partition or decryption error");
        if (p_info->keyslot == 0x05)
            Debug("(or slot0x05keyY not set up)");
        return 1;
    }
    
    if ((CheckNandFile(F_MOVABLE) != 0) ||
        (CheckNandFile(F_TICKET) != 0) ||
        (CheckNandFile(F_CONFIGSAVE) != 0) ||
        (CheckNandFile(F_LOCALFRIEND) != 0) ||
        (CheckNandFile(F_SECUREINFO) != 0)) {
        Debug("CTRNAND is fragmented or corrupt");
        return 1;
    }
    
    // check free space
    p_info = GetPartitionInfo(P_CTRFULL);
    if (!DebugCheckFreeSpace(p_info->size))
        return 1;
    
    Debug("");
    Debug("Creating transferable CTRNAND, size (MB): %u", p_info->size / (1024 * 1024));
    Debug("Select name for transfer file");
    if (OutputFileNameSelector(filename, "ctrtransfer", "bin") != 0)
        return 1;
    if (DecryptNandToFile(filename, p_info->offset, p_info->size, p_info, sha256) != 0)
        return 1;
    
    sha256[0x20] = (u8) GetRegion();
    snprintf(hashname, 64, "%s.sha", filename);
    if ((sha256[0x20] > 6) || (FileDumpData(hashname, sha256, 0x21) != 0x21)) {
        Debug("Failed creating hashfile");
        return 1;
    }
    
    return 0;
}
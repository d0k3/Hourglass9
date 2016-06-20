#include "fs.h"
#include "draw.h"
#include "decryptor/aes.h"
#include "decryptor/sha.h"
#include "decryptor/decryptor.h"
#include "decryptor/keys.h"
#include "decryptor/nand.h"

#define KEYDB_NAME "aeskeydb.bin"

typedef struct {
    u8   slot;           // keyslot, 0x00...0x39 
    char type;           // type 'X' / 'Y' / 'N' for normalKey
    char id[10];         // key ID for special keys, all zero for standard keys
} __attribute__((packed)) AesKeyDesc;

typedef struct {
    AesKeyDesc desc;     // slot, type, id
    u8   isDevkitKey;     // 1 if for DevKit unit, 0 otherwise
    u8   keySha256[32];  // SHA-256 of the key
} __attribute__((packed)) AesKeyHashInfo;

typedef struct {
    u8   slot;           // keyslot, 0x00...0x39
    u8   isDevkitKey;     // 1 if for DevKit unit, 0 otherwise
    u8   sample[16];     // sample data, encoded with src = keyY = ctr = { 0 }
} __attribute__((packed)) AesNcchSampleInfo;

static u64 keyState  = 0;
static u64 keyXState = 0;
static u64 keyYState = 0;

void CryptAesKeyInfo(AesKeyInfo* keyInfo) {
    CryptBufferInfo info = {.keyslot = 0x2C, .setKeyY = 1, .size = 16, .buffer = keyInfo->key, .mode = AES_CNT_CTRNAND_MODE};
    memset(info.keyY, 0x00, 16); // keyY -> all zeroes
    memset(info.ctr, 0x00, 16);
    memcpy(info.ctr, (void*) keyInfo, 12); // CTR -> slot + type + id + zeroes
    CryptBuffer(&info);
    keyInfo->isEncrypted = !keyInfo->isEncrypted;
}

u32 SetupTwlKey0x03(void) // setup the TWLNAND key 0x03
{
    // check if already loaded
    if (CheckKeySlot(0x03, 'N') == 0) {
        Debug("0x03 KeyX & KeyY: already set up");
        return 0;
    }
    
    // see: https://www.3dbrew.org/wiki/Memory_layout#ARM9_ITCM
    u32* TwlCustId = (u32*) (0x01FFB808);
    u8 TwlKeyX[16];
    u8 TwlKeyY[16];
    
    // thanks b1l1s & Normmatt
    // see source from https://gbatemp.net/threads/release-twltool-dsi-downgrading-save-injection-etc-multitool.393488/
    const char* nintendo = "NINTENDO";
    u32* TwlKeyXW = (u32*) TwlKeyX;
    TwlKeyXW[0] = (TwlCustId[0] ^ 0xB358A6AF) | 0x80000000;
    TwlKeyXW[3] = TwlCustId[1] ^ 0x08C267B7;
    memcpy(TwlKeyX + 4, nintendo, 8);
    
    // see: https://www.3dbrew.org/wiki/Memory_layout#ARM9_ITCM
    u32 TwlKeyYW3 = 0xE1A00005;
    memcpy(TwlKeyY, (u8*) 0x01FFD3C8, 12);
    memcpy(TwlKeyY + 12, &TwlKeyYW3, 4);
    
    setup_aeskeyX(0x03, TwlKeyX);
    setup_aeskeyY(0x03, TwlKeyY);
    use_aeskey(0x03);
    keyState  |= (u64) 1 << 0x03;
    keyXState |= (u64) 1 << 0x03;
    keyYState |= (u64) 1 << 0x03;
    Debug("0x03 KeyX & KeyY: automatically set up");
    
    return 0;
}

u32 SetupCtrNandKeyY0x05(void) // setup the CTRNAND keyY 0x05
{
    static const u8 keyY0x05Sha256[32] = {
        0x98, 0x24, 0x27, 0x14, 0x22, 0xB0, 0x6B, 0xF2, 0x10, 0x96, 0x9C, 0x36, 0x42, 0x53, 0x7C, 0x86,
        0x62, 0x22, 0x5C, 0xFD, 0x6F, 0xAE, 0x9B, 0x0A, 0x85, 0xA5, 0xCE, 0x21, 0xAA, 0xB6, 0xC8, 0x4D
    };
    static const u32 offset_keyy0x05[2] = { 0x0EB014, 0x0EB24C }; // FIRM90 & FIRM81 offsets
    static const u32 firm_sig_magic[2] = { 0x87B79D15, 0x79D0FB89 }; // FIRM90 & FIRM81 signature magic 
    
    // check if already loaded
    if (CheckKeySlot(0x05, 'Y') == 0) {
        Debug("0x05 KeyY: already set up");
        return 0;
    }
    
    // this uses fixed offsets and works ONLY for FIRM90 & FIRM81 (= on A9LH SysNAND, too)
    // see: https://github.com/AuroraWright/Luma3DS/blob/master/source/crypto.c#L347
    // thanks AuroraWright & Gelex
    u8 buffer[0x200];
    PartitionInfo* p_firm = GetPartitionInfo(P_FIRM0);
    
    DecryptNandToMem(buffer, p_firm->offset, 0x200, p_firm);
    u32 offset_section2 = getle32(buffer + 0xA0);
    u32 fver = 0;
    for (; (fver < 2) && (firm_sig_magic[fver] != getle32(buffer + 0x100)); fver++);
    if ((fver < 2) && (offset_section2 == 0x066A00)) {
        CryptBufferInfo info = {.keyslot = 0x15, .setKeyY = 1, .buffer = buffer, .size = 0x200,
            .mode = AES_CNT_CTRNAND_MODE};
        u32 offset_keyy0x05a = offset_keyy0x05[fver] - (offset_keyy0x05[fver] % 0x200);
        DecryptNandToMem(buffer, p_firm->offset + offset_section2, 0x200, p_firm);
        memcpy(info.keyY, buffer + 0x10, 0x10);
        memcpy(info.ctr, buffer + 0x20, 0x10);
        add_ctr(info.ctr, (offset_keyy0x05a - (offset_section2 + 0x800)) / 16);
        DecryptNandToMem(buffer, p_firm->offset + offset_keyy0x05a, 0x200, p_firm);
        CryptBuffer(&info);
        
        // set it, check it
        u8* CtrKeyY = buffer + (offset_keyy0x05[fver] % 0x200);
        u8 keySha256[32];
        sha_quick(keySha256, CtrKeyY, 16, SHA256_MODE);
        if (memcmp(keySha256, keyY0x05Sha256, 32) == 0) {
            setup_aeskeyY(0x05, CtrKeyY);
            use_aeskey(0x05);
            keyYState |= (u64) 1 << 0x05;
            Debug("0x05 KeyY: automatically set up");
            return 0;
        }
    }
    
    // if we arrive here, try loading from file
    // this will not happen with regular entrypoints
    return LoadKeyFromFile(0x05, 'Y', NULL);
}

u32 GetUnitKeysType(void)
{
    static u32 keys_type = KEYS_UNKNOWN;
    
    if (keys_type == KEYS_UNKNOWN) {
        static const u8 slot0x2CSampleRetail[16] = {
            0xBC, 0xC4, 0x16, 0x2C, 0x2A, 0x06, 0x91, 0xEE, 0x47, 0x18, 0x86, 0xB8, 0xEB, 0x2F, 0xB5, 0x48 };
        static const u8 slot0x2CSampleDevkit[16] = {
            0x29, 0xB5, 0x5D, 0x9F, 0x61, 0xAC, 0xD2, 0x28, 0x22, 0x23, 0xFB, 0x57, 0xDD, 0x50, 0x8A, 0xF5 };
        u8 sample[16] = { 0 };
        CryptBufferInfo info = {.keyslot = 0x2C, .setKeyY = 1, .buffer = sample, .size = 16, .mode = AES_CNT_CTRNAND_MODE};
        memset(info.ctr, 0x00, 16);
        memset(info.keyY, 0x00, 16);
        memset(info.buffer, 0x00, 16);
        CryptBuffer(&info);
        
        if (memcmp(sample, slot0x2CSampleRetail, 16) == 0) {
            keys_type = KEYS_RETAIL;
        } else if (memcmp(sample, slot0x2CSampleDevkit, 16) == 0) {
            keys_type = KEYS_DEVKIT;
        }
    }
        
    return keys_type;
}

u32 LoadKeyFromFile(u32 keyslot, char type, char* id)
{
    static const AesKeyHashInfo keyHashes[] = {
        { { 0x05, 'Y', "" }, 0, // Retail N3DS CTRNAND key SHA256
         { 0x98, 0x24, 0x27, 0x14, 0x22, 0xB0, 0x6B, 0xF2, 0x10, 0x96, 0x9C, 0x36, 0x42, 0x53, 0x7C, 0x86,
         0x62, 0x22, 0x5C, 0xFD, 0x6F, 0xAE, 0x9B, 0x0A, 0x85, 0xA5, 0xCE, 0x21, 0xAA, 0xB6, 0xC8, 0x4D }
        },
        { { 0x18, 'X', "" }, 0, // Retail NCCH Secure3 key SHA256
         { 0x76, 0xC7, 0x6B, 0x65, 0x5D, 0xB8, 0x52, 0x19, 0xC5, 0xD3, 0x5D, 0x51, 0x7F, 0xFA, 0xF7, 0xA4,
         0x3E, 0xBA, 0xD6, 0x6E, 0x31, 0xFB, 0xDD, 0x57, 0x43, 0x92, 0x59, 0x37, 0xA8, 0x93, 0xCC, 0xFC }
        },
        { { 0x1B, 'X', "" }, 0, // Retail NCCH Secure4 key SHA256
         { 0x9A, 0x20, 0x1E, 0x7C, 0x37, 0x37, 0xF3, 0x72, 0x2E, 0x5B, 0x57, 0x8D, 0x11, 0x83, 0x7F, 0x19,
         0x7C, 0xA6, 0x5B, 0xF5, 0x26, 0x25, 0xB2, 0x69, 0x06, 0x93, 0xE4, 0x16, 0x53, 0x52, 0xC6, 0xBB }
        },
        { { 0x25, 'X', "" }, 0, // Retail NCCH 7x key SHA256
         { 0x7E, 0x87, 0x8D, 0xDE, 0x92, 0x93, 0x8E, 0x4C, 0x71, 0x7D, 0xD5, 0x3D, 0x1E, 0xA3, 0x5A, 0x75,
         0x63, 0x3F, 0x51, 0x30, 0xD8, 0xCF, 0xD7, 0xC7, 0x6C, 0x8F, 0x4A, 0x8F, 0xB8, 0x70, 0x50, 0xCD }
        }
    };
    
    char keyname[16];
    u8 key[16] = {0};
    bool found = false;
    bool verified = false;

    // build keyname
    snprintf(keyname, 15, "Key%.10s", (id) ? id : (type == 'X') ? "X" : (type == 'Y') ? "Y" : "");
    
    // checking the obvious
    if (keyslot >= 0x40) {
        Debug("0x%02X %s: invalid keyslot", (unsigned int) keyslot, keyname);
        return 1;
    } else if ((type != 'X') && (type != 'Y') && (type != 'N')) {
        Debug("0x%02X %s: invalid keytype (%c)", (unsigned int) keyslot, keyname, type);
        return 1;
    }
    
    // check if already loaded
    if (!id && (CheckKeySlot(keyslot, type) == 0)) {
        Debug("0x%02X %s: already set up", (unsigned int) keyslot, keyname, type);
        return 0;
    }
    
    // try to get key from 'aeskeydb.bin' file
    if (FileOpen(KEYDB_NAME)) {
        AesKeyInfo info;
        for (u32 p = 0; FileRead(&info, sizeof(AesKeyInfo), p) == sizeof(AesKeyInfo); p += sizeof(AesKeyInfo)) {
            if ((info.slot == keyslot) && (info.type == type) && 
                ((!id && !(info.id[0])) || (id && (strncmp(id, info.id, 10) == 0)))) {
                found = true;
                break;
            }
        }
        if (found) { // decrypt key if required
            if (info.isEncrypted)
                CryptAesKeyInfo(&info);
            memcpy(key, info.key, 16);
        }
        FileClose();
    }
    
    // load legacy slot0x??Key?.bin file
    if (!found) {
        char filename[32];
        snprintf(filename, 31, "slot0x%02X%s.bin", (unsigned int) keyslot, keyname);
        if (FileGetData(filename, key, 16, 0) == 16)
            found = true;
    }
    
    if (!found) { // out of options here
        Debug("0x%02X %s: not found", (unsigned int) keyslot, keyname);
        return 1;
    }
    // found the key, now try to verify it
    u8 keySha256[32];
    sha_quick(keySha256, key, 16, SHA256_MODE);
    for (u32 p = 0; p < sizeof(keyHashes) / sizeof(AesKeyHashInfo); p++) {
        if ((keyHashes[p].desc.slot != keyslot) || (keyHashes[p].desc.type != type))
            continue;
        if ((!id && keyHashes[p].desc.id[0]) || (id && strncmp(id, keyHashes[p].desc.id, 10) != 0))
            continue;
        if ((bool) keyHashes[p].isDevkitKey != (GetUnitKeysType() == KEYS_DEVKIT))
            continue;
        if (memcmp(keySha256, keyHashes[p].keySha256, 32) == 0) {
            verified = true;
            break;
        } else {
            Debug("0x%02X %s: corrupt key", (unsigned int) keyslot, keyname);
            return 1;
        }
    }
    
    // now, setup the key
    if (type == 'X') {
        setup_aeskeyX(keyslot, key);
        keyXState |= (u64) 1 << keyslot;
    } else if (type == 'Y') {
        setup_aeskeyY(keyslot, key);
        keyYState |= (u64) 1 << keyslot;
    } else { // normalKey includes keyX & keyY
        setup_aeskey(keyslot, key);
        keyState  |= (u64) 1 << keyslot;
        keyXState |= (u64) 1 << keyslot;
        keyYState |= (u64) 1 << keyslot;
    }
    use_aeskey(keyslot);
    
    // Output key state
    Debug("0x%02X %s: loaded, %sset up", (unsigned int) keyslot, keyname, (verified) ? "verified, " : "");
    
    return 0;
}

u32 CheckKeySlot(u32 keyslot, char type)
{
    static const AesNcchSampleInfo keyNcchSamples[] = {
        { 0x18, 0, // Retail NCCH Secure3
         { 0x78, 0xBB, 0x84, 0xFA, 0xB3, 0xA2, 0x49, 0x83, 0x9E, 0x4F, 0x50, 0x7B, 0x17, 0xA0, 0xDA, 0x23 } },
        { 0x1B, 0, // Retail NCCH Secure4
         { 0xF3, 0x6F, 0x84, 0x7E, 0x59, 0x43, 0x6E, 0xD5, 0xA0, 0x40, 0x4C, 0x71, 0x19, 0xED, 0xF7, 0x0A } },
        { 0x25, 0, // Retail NCCH 7x
         { 0x34, 0x7D, 0x07, 0x48, 0xAE, 0x5D, 0xFB, 0xB0, 0xF5, 0x86, 0xD6, 0xB5, 0x14, 0x65, 0xF1, 0xFF } },
        { 0x25, 1, // DevKit NCCH 7x
         { 0xBC, 0x83, 0x7C, 0xC9, 0x99, 0xC8, 0x80, 0x9E, 0x8A, 0xDE, 0x4A, 0xFA, 0xAA, 0x72, 0x08, 0x28 } }
    };
    u64* state = (type == 'X') ? &keyXState : (type == 'Y') ? &keyYState : &keyState;
    
    // just to be safe...
    if (keyslot >= 0x40)
        return 1;
    
    // check if key is already loaded
    if ((*state >> keyslot) & 1)
        return 0;
    
    // if is not, we may still be able to verify the currently set one (for NCCH keys)
    for (u32 p = 0; (type == 'X') && (p < sizeof(keyNcchSamples) / sizeof(AesNcchSampleInfo)); p++) {
        if (keyNcchSamples[p].slot != keyslot) // only for keyslots in the keyNcchSamples table!
            continue;
        if ((bool) keyNcchSamples[p].isDevkitKey != (GetUnitKeysType() == KEYS_DEVKIT))
            continue;
        u8 sample[16] = { 0 };
        CryptBufferInfo info = {.keyslot = keyslot, .setKeyY = 1, .buffer = sample, .size = 16, .mode = AES_CNT_CTRNAND_MODE};
        memset(info.ctr, 0x00, 16);
        memset(info.keyY, 0x00, 16);
        memset(info.buffer, 0x00, 16);
        CryptBuffer(&info);
        if (memcmp(keyNcchSamples[p].sample, sample, 16) == 0) {
            keyXState |= (u64) 1 << keyslot;
            return 0;
        }
    }
    
    // we can also verify keyslots 0x03 to 0x06 via magic number checking
    if ((keyslot >= 0x03) && (keyslot <= 0x06)) {
        u8 magic[0x200];
        PartitionInfo* p_info = GetPartitionInfo((keyslot == 0x03) ? P_TWLN : (keyslot == 0x06) ? P_FIRM0 : P_CTRNAND);
        if (p_info && (p_info->keyslot == keyslot) && (DecryptNandToMem(magic, p_info->offset, 16, p_info) == 0)) {
            if (memcmp(p_info->magic, magic, 8) == 0) {
                keyState  |= (u64) 1 << keyslot;
                keyXState |= (u64) 1 << keyslot;
                keyYState |= (u64) 1 << keyslot;
                return 0;
            }
        }
    }
    
    // not set up if getting here
    return 1;
}

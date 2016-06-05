#include "fs.h"
#include "draw.h"
#include "decryptor/sha.h"
#include "decryptor/hashfile.h"


u32 GetHashFromFile(const char* filename, u32 offset, u32 size, u8* hash)
{
    // uses the standard buffer, so be careful
    u8* buffer = BUFFER_ADDRESS;
    
    if (!FileOpen(filename))
        return 1;
    if (!size) {
        size = FileGetSize();
        if (offset >= size)
            return 1;
        size -= offset;
    }
    sha_init(SHA256_MODE);
    for (u32 i = 0; i < size; i += BUFFER_MAX_SIZE) {
        u32 read_bytes = min(BUFFER_MAX_SIZE, (size - i));
        if (size >= 0x100000) ShowProgress(i, size);
        if(!FileRead(buffer, read_bytes, offset + i)) {
            FileClose();
            return 1;
        }
        sha_update(buffer, read_bytes);
    }
    sha_get(hash);
    ShowProgress(0, 0);
    FileClose();
    
    return 0;
}

u32 CheckHashFromFile(const char* filename, u32 offset, u32 size, const u8* hash)
{
    u8 digest[32];
    
    if (GetHashFromFile(filename, offset, size, digest) != 0)
        return 1;
    
    return (memcmp(hash, digest, 32) == 0) ? HASH_VERIFIED : HASH_FAILED; 
}

u32 HashVerifyFile(const char* filename)
{
    char hashname[64];
    u8 hash[32];
    
    snprintf(hashname, 64, "%s.sha", filename);
    if (FileGetData(hashname, hash, 32, 0) != 32)
        return HASH_NOT_FOUND;
    
    return CheckHashFromFile(filename, 0, 0, hash);
}

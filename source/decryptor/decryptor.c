#include "fs.h"
#include "draw.h"
#include "decryptor/decryptor.h"
#include "decryptor/aes.h"


u32 CryptBuffer(CryptBufferInfo *info)
{
    u8 ctr[16] __attribute__((aligned(32)));
    memcpy(ctr, info->ctr, 16);

    u8* buffer = info->buffer;
    u32 size = info->size;
    u32 mode = info->mode;

    if (info->setKeyY) {
        u8 keyY[16] __attribute__((aligned(32)));
        memcpy(keyY, info->keyY, 16);
        setup_aeskeyY(info->keyslot, keyY);
        info->setKeyY = 0;
    }
    use_aeskey(info->keyslot);

    if ((mode & (0x7 << 27)) == AES_CTR_MODE) {
        ctr_decrypt((void*) buffer, (void*) buffer, (size + 0xF) / 0x10, mode, ctr);
    } else for (u32 i = 0; i < size; i += 0x10, buffer += 0x10) {
        if (((mode & (0x7 << 27)) != AES_ECB_DECRYPT_MODE) && ((mode & (0x7 << 27)) != AES_ECB_ENCRYPT_MODE))
            set_ctr(ctr);
        if ((mode & (0x7 << 27)) == AES_CBC_DECRYPT_MODE)
            memcpy(ctr, buffer, 0x10);
        aes_decrypt((void*) buffer, (void*) buffer, 1, mode);
        if ((mode & (0x7 << 27)) == AES_CBC_ENCRYPT_MODE)
            memcpy(ctr, buffer, 0x10);
    }

    memcpy(info->ctr, ctr, 16);
    
    return 0;
}

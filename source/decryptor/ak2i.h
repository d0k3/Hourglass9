#pragma once

#include "common.h"
#include "decryptor/decryptor.h"
#include "decryptor/game.h"

struct ntrcardhax_info {
    int32_t version;
    u32 ntrcard_header_addr;
    u32 rtfs_cfg_addr;
    u32 rtfs_handle_addr;
};

u32 DumpAk2iCart(u32 param);
u32 InjectAk2iCart(u32 param);
u32 PatchAndInjectAk2iCart(u32 param);
u32 AutoAk2iCart(u32 param);
u32 RestoreAk2iCart(u32 param);

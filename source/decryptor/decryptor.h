#pragma once

#include "common.h"

typedef struct {
    u32  keyslot;
    u32  setKeyY;
    u8   ctr[16];
    u8   keyY[16];
    u32  size;
    u32  mode;
    u8*  buffer;
} __attribute__((packed)) CryptBufferInfo;

u32 CryptBuffer(CryptBufferInfo *info);

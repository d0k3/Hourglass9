#pragma once

#include "common.h"

#define HASH_VERIFIED   0
#define HASH_FAILED     1
#define HASH_NOT_FOUND  2

u32 GetHashFromFile(const char* filename, u32 offset, u32 size, u8* hash);
u32 CheckHashFromFile(const char* filename, u32 offset, u32 size, const u8* hash);
u32 HashVerifyFile(const char* filename);

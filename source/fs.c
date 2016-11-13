#include "fs.h"
#include "draw.h"

#include "fatfs/ff.h"
#include "hid.h"

static FATFS fs;
static FIL file;
static DIR dir;

bool InitFS()
{
    bool ret = (f_mount(&fs, "0:", 1) == FR_OK);
    if (ret)
        f_chdir(GetWorkDir());

    return ret;
}

void DeinitFS()
{
    LogWrite(NULL);
    f_mount(NULL, "0:", 1);
}

const char* GetWorkDir()
{
    const char* root = "/";
    const char* work_dirs[] = { WORK_DIRS };
    u32 n_dirs = sizeof(work_dirs) / sizeof(char*);
    
    u32 i;
    for (i = 0; i < n_dirs; i++) {
        FILINFO fno;
        if ((f_stat(work_dirs[i], &fno) == FR_OK) && (fno.fattrib & AM_DIR))
            break;
    }
    
    return ((i >= n_dirs) ? root : work_dirs[i]);
}

bool DebugCheckCancel(void)
{
    if (CheckButton(BUTTON_B)) {
        DebugColor(COLOR_ASK, "Press <A> to cancel operation");
        while (CheckButton(BUTTON_B)); // make sure <B> is no more pressed
        if (InputWait() & BUTTON_A) {
            DebugColor(COLOR_ASK, "(cancelled by user)");
            return true;
        } else {
            Debug("Continuing operation...");
        }
    }
    return false;
}

bool DebugCheckFreeSpace(size_t required)
{
    if (required > RemainingStorageSpace()) {
        Debug("Not enough space left on SD card");
        return false;
    }
    
    return true;
}

bool FileOpen(const char* path)
{
    unsigned flags = FA_READ | FA_WRITE | FA_OPEN_EXISTING;
    unsigned flags_ro = FA_READ | FA_OPEN_EXISTING;
    if (*path == '/')
        path++;
    bool ret = (f_open(&file, path, flags) == FR_OK) ||
        (f_open(&file, path, flags_ro) == FR_OK);
    f_chdir("/"); // allow root as alternative to work dir
    if (!ret) ret = (f_open(&file, path, flags) == FR_OK) ||
        (f_open(&file, path, flags_ro) == FR_OK);
    f_chdir(GetWorkDir());
    f_lseek(&file, 0);
    f_sync(&file);
    return ret;
}

bool DebugFileOpen(const char* path)
{
    Debug("Opening %s ...", path);
    if (!FileOpen(path)) {
        Debug("Could not open %s", path);
        return false;
    }
    
    return true;
}

bool FileCreate(const char* path, bool truncate)
{
    if (!truncate && FileOpen(path))
        return true;
    unsigned flags = FA_READ | FA_WRITE;
    flags |= truncate ? FA_CREATE_ALWAYS : FA_OPEN_ALWAYS;
    if (*path == '/')
        path++;
    bool ret = (f_open(&file, path, flags) == FR_OK);
    f_lseek(&file, 0);
    f_sync(&file);
    return ret;
}

bool DebugFileCreate(const char* path, bool truncate) {
    Debug("%s %s ...", truncate ? "Creating" : "Opening", path);
    if (!FileCreate(path, truncate)) {
        Debug("Could not create %s", path);
        return false;
    }

    return true;
}

size_t FileInjectTo(const char* dest, u32 offset_in, u32 offset_out, u32 size, bool overwrite, void* buf, size_t bufsize)
{
    unsigned flags = FA_WRITE | (overwrite ? FA_CREATE_ALWAYS : FA_OPEN_ALWAYS);
    size_t fsize = f_size(&file);
    size_t result = size;
    FIL dfile;
    // make sure the containing folder exists
    char tmp[256] = { 0 };
    strncpy(tmp, dest, sizeof(tmp) - 1);
    for (char* p = tmp + 1; *p; p++) {
        if (*p == '/') {
            char s = *p;
            *p = 0;
            f_mkdir(tmp);
            *p = s;
        }
    }
    // fix size var if zero
    if (size == 0)
        result = size = fsize - offset_in;
    // do the actual injecting
    if (f_open(&dfile, dest, flags) != FR_OK)
        return 0;
    f_lseek(&dfile, offset_out);
    f_sync(&dfile);
    f_lseek(&file, offset_in);
    f_sync(&file);
    for (size_t pos = 0; pos < size; pos += bufsize) {
        UINT bytes_read = 0;
        UINT bytes_written = 0;
        ShowProgress(pos, size);
        if (pos + bufsize > size)
            bufsize = size - pos;
        if ((f_read(&file, buf, bufsize, &bytes_read) != FR_OK) ||
            (f_write(&dfile, buf, bytes_read, &bytes_written) != FR_OK) ||
            (bytes_read != bytes_written)) {
            result = 0;
            break;
        }
        if (DebugCheckCancel())
            return 0;
    }
    ShowProgress(0, 0);
    f_close(&dfile);
    return result;
}

size_t FileCopyTo(const char* dest, void* buf, size_t bufsize)
{
    return FileInjectTo(dest, 0, 0, 0, true, buf, bufsize);
}

size_t FileRead(void* buf, size_t size, size_t foffset)
{if (size == 0)
        return 0;
    UINT bytes_read = 0;
    f_lseek(&file, foffset);
    if (f_read(&file, buf, size, &bytes_read) != FR_OK)
        return 0;
    return bytes_read;
}

bool DebugFileRead(void* buf, size_t size, size_t foffset) {
    size_t bytesRead = FileRead(buf, size, foffset);
    if(bytesRead != size) {
        Debug("File too small or SD failure");
        return false;
    }
    // NOT enabled -> dangerous on NAND writes
    /* if (DebugCheckCancel())
        return false; */
    
    return true;
}

size_t FileWrite(void* buf, size_t size, size_t foffset)
{
    if (size == 0)
        return 0;
    UINT bytes_written = 0;
    f_lseek(&file, foffset);
    if (f_write(&file, buf, size, &bytes_written) != FR_OK)
        return 0;
    f_sync(&file);
    return bytes_written;
}

bool DebugFileWrite(void* buf, size_t size, size_t foffset)
{
    size_t bytesWritten = FileWrite(buf, size, foffset);
    if(bytesWritten != size) {
        Debug("SD failure or SD full");
        return false;
    }
    if (DebugCheckCancel())
        return false;
    
    return true;
}

size_t FileGetSize()
{
    return f_size(&file);
}

void FileClose()
{
    f_close(&file);
}

bool DirOpen(const char* path)
{
    return (f_opendir(&dir, path) == FR_OK);
}

bool DebugDirOpen(const char* path)
{
    Debug("Opening %s ...", path);
    if (!DirOpen(path)) {
        Debug("Could not open %s!", path);
        return false;
    }
    
    return true;
}

bool DirRead(char* fname, int fsize)
{
    FILINFO fno;
    bool ret = false;
    while (f_readdir(&dir, &fno) == FR_OK) {
        if (fno.fname[0] == 0) break;
        if ((fno.fname[0] != '.') && !(fno.fattrib & AM_DIR)) {
            strncpy(fname, fno.fname, fsize - 1);
            ret = true;
            break;
        }
    }
    return ret;
}

void DirClose()
{
    f_closedir(&dir);
}

bool GetFileListWorker(char** list, int* lsize, char* fpath, int fsize, bool recursive, bool inc_files, bool inc_dirs)
{
    DIR pdir;
    FILINFO fno;
    char* fname = fpath + strnlen(fpath, fsize - 1);
    bool ret = false;
    
    if (f_opendir(&pdir, fpath) != FR_OK)
        return false;
    (fname++)[0] = '/';
    
    while (f_readdir(&pdir, &fno) == FR_OK) {
        if ((strncmp(fno.fname, ".", 2) == 0) || (strncmp(fno.fname, "..", 3) == 0))
            continue; // filter out virtual entries
        strncpy(fname, fno.fname, (fsize - 1) - (fname - fpath));
        if (fno.fname[0] == 0) {
            ret = true;
            break;
        } else if ((inc_files && !(fno.fattrib & AM_DIR)) || (inc_dirs && (fno.fattrib & AM_DIR))) {
            snprintf(*list, *lsize, "%s\n", fpath);
            for(;(*list)[0] != '\0' && (*lsize) > 1; (*list)++, (*lsize)--); 
            if ((*lsize) <= 1) break;
        }
        if (recursive && (fno.fattrib & AM_DIR)) {
            if (!GetFileListWorker(list, lsize, fpath, fsize, recursive, inc_files, inc_dirs))
                break;
        }
    }
    f_closedir(&pdir);
    
    return ret;
}

bool GetFileList(const char* path, char* list, int lsize, bool recursive, bool inc_files, bool inc_dirs)
{
    char fpath[256]; // 256 is the maximum length of a full path
    strncpy(fpath, path, 256);
    return GetFileListWorker(&list, &lsize, fpath, 256, recursive, inc_files, inc_dirs);
}

size_t FileGetData(const char* path, void* buf, size_t size, size_t foffset)
{
    unsigned flags = FA_READ | FA_OPEN_EXISTING;
    FIL tmp_file;
    if (*path == '/')
        path++;
    bool exists = (f_open(&tmp_file, path, flags) == FR_OK);
    if (!exists) { // this allows root as alternative to work dir
        f_chdir("/"); // temporarily change the current directory
        exists = (f_open(&tmp_file, path, flags) == FR_OK);
        f_chdir(GetWorkDir());
    }
    if (exists) {
        UINT bytes_read = 0;
        bool res = false;
        f_lseek(&tmp_file, foffset);
        f_sync(&tmp_file);
        res = (f_read(&tmp_file, buf, size, &bytes_read) == FR_OK);
        f_close(&tmp_file);
        return (res) ? bytes_read : 0;
    }
    
    return 0;
}

size_t FileDumpData(const char* path, void* buf, size_t size)
{
    unsigned flags = FA_WRITE | FA_CREATE_ALWAYS;
    FIL tmp_file;
    UINT bytes_written = 0;;
    bool res = false;
    if (*path == '/')
        path++;
    if (f_open(&tmp_file, path, flags) != FR_OK)
        return 0;
    f_lseek(&tmp_file, 0);
    f_sync(&tmp_file);
    res = (f_write(&tmp_file, buf, size, &bytes_written) == FR_OK);
    f_close(&tmp_file);
    
    return (res) ? bytes_written : 0;
}

size_t LogWrite(const char* text)
{
    #ifdef LOG_FILE
    static FIL lfile;
    static bool lready = false;
    static size_t lstart = 0;
    
    if ((text == NULL) && lready) {
        f_close(&lfile);
        lready = false;
        return lstart; // return the current log start
    } else if (text == NULL) {
        return 0;
    }
    
    if (!lready) {
        unsigned flags = FA_READ | FA_WRITE | FA_OPEN_ALWAYS;
        lready = (f_open(&lfile, LOG_FILE, flags) == FR_OK);
        if (!lready) return 0;
        lstart = f_size(&lfile);
        f_lseek(&lfile, lstart);
        f_sync(&lfile);
    }
    
    const char newline = '\n';
    UINT bytes_written;
    UINT tlen = strnlen(text, 128); 
    f_write(&lfile, text, tlen, &bytes_written);
    if (bytes_written != tlen) return 0;
    f_write(&lfile, &newline, 1, &bytes_written);
    if (bytes_written != 1) return 0;
    
    return f_size(&lfile); // return the current position
    #else
    return 0;
    #endif
}

static uint64_t ClustersToBytes(FATFS* fs, DWORD clusters)
{
    uint64_t sectors = clusters * fs->csize;
    #if _MAX_SS != _MIN_SS
    return sectors * fs->ssize;
    #else
    return sectors * _MAX_SS;
    #endif
}

uint64_t RemainingStorageSpace()
{
    DWORD free_clusters;
    FATFS *fs2;
    FRESULT res = f_getfree("0:", &free_clusters, &fs2);
    if (res)
        return -1;

    return ClustersToBytes(&fs, free_clusters);
}

uint64_t TotalStorageSpace()
{
    return ClustersToBytes(&fs, fs.n_fatent - 2);
}

uint32_t NumHiddenSectors()
{
    return (fs.volbase > 0) ? (uint32_t) fs.volbase - 1 : 0;
}

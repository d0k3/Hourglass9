#include "common.h"
#include "draw.h"
#include "fs.h"
#include "hid.h"
#include "menu.h"
#include "platform.h"
#include "i2c.h"
#include "decryptor/keys.h"
#include "decryptor/nand.h"
#include "decryptor/injector.h"
#include "bottomlogo_bgr.h"

#define SUBMENU_START 1

MenuInfo menu[] =
{
    {
        #ifndef VERSION_NAME
        "Hourglass9 Main Menu", 3,
        #else
        VERSION_NAME, 3,
        #endif
        {
            { "SysNAND Backup/Restore...",    NULL,                   SUBMENU_START + 0 },
            { "EmuNAND Backup/Restore...",    NULL,                   SUBMENU_START + 1 },
            { "Validate NAND Dump",           &ValidateNandDump,      0 }
        }
    },
    {
        "SysNAND Backup/Restore Options", 4, // ID 0
        {
            { "SysNAND Backup",               &DumpNand,              NB_MINSIZE },
            { "SysNAND Restore (keep a9lh)",  &RestoreNand,           N_NANDWRITE | NR_KEEPA9LH },
            { "Health&Safety Dump",           &DumpHealthAndSafety,   0 },
            { "Health&Safety Inject",         &InjectHealthAndSafety, N_NANDWRITE }
        }
    },
    {
        "EmuNAND Backup/Restore Options", 4, // ID 1
        {
            { "EmuNAND Backup",               &DumpNand,              N_EMUNAND | NB_MINSIZE },
            { "EmuNAND Restore",              &RestoreNand,           N_NANDWRITE | N_EMUNAND | N_FORCEEMU },
            { "Health&Safety Dump",           &DumpHealthAndSafety,   N_EMUNAND },
            { "Health&Safety Inject",         &InjectHealthAndSafety, N_NANDWRITE | N_EMUNAND }
        }
    },
    {
        NULL, 0, { { 0 } } // empty menu to signal end
    }
};


void Reboot()
{
    i2cWriteRegister(I2C_DEV_MCU, 0x20, 1 << 2);
    while(true);
}


void PowerOff()
{
    i2cWriteRegister(I2C_DEV_MCU, 0x20, 1 << 0);
    while (true);
}


u32 InitializeH9()
{
    u32 errorlevel = 0; // 0 -> none, 1 -> autopause, 2 -> critical
    
    ClearScreenFull(true, true);
    if (bottomlogo_bgr_size == 320 * 240 * 3) {
        memcpy(BOT_SCREEN0, bottomlogo_bgr, 320 * 240 * 3);
        memcpy(BOT_SCREEN1, bottomlogo_bgr, 320 * 240 * 3);
    }
    
    DebugClear();
    #ifndef BUILD_NAME
    Debug("-- Hourglass9 --");
    #else
    Debug("-- %s --", BUILD_NAME);
    #endif
    
    // a little bit of information about the current menu
    if (sizeof(menu)) {
        u32 n_submenus = 0;
        u32 n_features = 0;
        for (u32 m = 0; menu[m].n_entries; m++) {
            n_submenus = m;
            for (u32 e = 0; e < menu[m].n_entries; e++)
                n_features += (menu[m].entries[e].function) ? 1 : 0;
        }
        Debug("Counting %u submenus and %u features", n_submenus, n_features);
    }
    
    Debug("Initializing, hold L+R to pause");
    Debug("");    
    
    if ((*(vu32*) 0x101401C0) != 0)
        errorlevel = 2;
    Debug("Checking arm9loaderhax... %s", (*(vu32*) 0x101401C0) ? "failed" : "success");
    if (InitFS()) {
        Debug("Initializing SD card... success");
        FileGetData("h9logo.bin", BOT_SCREEN0, 320 * 240 * 3, 0);
        memcpy(BOT_SCREEN1, BOT_SCREEN0, 320 * 240 * 3);
        if (SetupTwlKey0x03() != 0) // TWL KeyX / KeyY
            errorlevel = 2;
        if ((GetUnitPlatform() == PLATFORM_N3DS) && (SetupCtrNandKeyY0x05() != 0))
            errorlevel = 2; // N3DS CTRNAND KeyY
        if (LoadKeyFromFile(0x25, 'X', NULL)) // NCCH 7x KeyX
            errorlevel = (errorlevel < 1) ? 1 : errorlevel;
        if (LoadKeyFromFile(0x18, 'X', NULL)) // NCCH Secure3 KeyX
            errorlevel = (errorlevel < 1) ? 1 : errorlevel;
        if (LoadKeyFromFile(0x1B, 'X', NULL)) // NCCH Secure4 KeyX
            errorlevel = (errorlevel < 1) ? 1 : errorlevel;
        Debug("Finalizing Initialization...");
        RemainingStorageSpace();
    } else {
        Debug("Initializing SD card... failed");
            errorlevel = 2;
    }
    Debug("");
    Debug("Initialization: %s", (errorlevel < 2) ? "success!" : "failed!");
    
    if (((~HID_STATE & BUTTON_L1) && (~HID_STATE & BUTTON_R1)) || (errorlevel > 1)) {
        Debug("(A to %s)", (errorlevel > 1) ? "exit" : "continue");
        while (!(InputWait() & BUTTON_A));
    }
    
    return errorlevel;
}


int main()
{
    u32 menu_exit = MENU_EXIT_REBOOT;
    
    if (InitializeH9() <= 1) {
        menu_exit = ProcessMenu(menu, SUBMENU_START);
    }
    DeinitFS();
    
    ClearScreenFull(true, true);
    (menu_exit == MENU_EXIT_REBOOT) ? Reboot() : PowerOff();
    return 0;
}

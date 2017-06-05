#include "common.h"
#include "descriptions.h"
#include "draw.h"
#include "fs.h"
#include "hid.h"
#include "menu.h"
#include "platform.h"
#include "i2c.h"
#include "decryptor/keys.h"
#include "decryptor/nand.h"
#include "decryptor/nandfat.h"
#include "decryptor/game.h"
#include "decryptor/xorpad.h"
#include "decryptor/selftest.h"
#include "bottomlogo_bgr.h"

#define SUBMENU_START 1


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


u32 InitializeH9(MenuInfo* menu)
{
    u32 errorlevel = 0; // 0 -> none, 1 -> autopause, 2 -> critical
    
    ClearScreenFull(true, true);
    if (bottomlogo_bgr_size == 320 * 240 * 3)
        memcpy(BOT_SCREEN, bottomlogo_bgr, 320 * 240 * 3);
    
    DebugClear();
    #ifndef BUILD_NAME
    DebugColor(COLOR_ACCENT, "-- Hourglass9 --");
    #else
    DebugColor(COLOR_ACCENT, "-- %s --", BUILD_NAME);
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
        FileGetData("h9logo.bin", BOT_SCREEN, 320 * 240 * 3, 0);
        Debug("Build: %s", BUILD_NAME);
        Debug("Work directory: %s", GetWorkDir());
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
        if (SetupAgbCmacKeyY0x24()) // AGBSAVE CMAC KeyY
            errorlevel = (errorlevel < 1) ? 1 : errorlevel;
        Debug("Finalizing Initialization...");
        RemainingStorageSpace();
    } else {
        Debug("Initializing SD card... failed");
            errorlevel = 2;
    }
    Debug("");
    Debug("Initialization: %s", (errorlevel < 2) ? "success!" : "failed!");
    
    if (CheckButton(BUTTON_L1|BUTTON_R1) || (errorlevel > 1)) {
        DebugColor(COLOR_ASK, "(A to %s)", (errorlevel > 1) ? "exit" : "continue");
        while (!(InputWait() & BUTTON_A));
    }
    
    return errorlevel;
}

u8 *top_screen, *bottom_screen;

int main(int argc, char** argv)
{
    MenuInfo menu[] =
    {
        {
            #ifndef VERSION_NAME
            "Hourglass9 Main Menu", 5,
            #else
            VERSION_NAME, 5,
            #endif
            {
                { "SysNAND Backup/Restore...",    NULL,                    NULL,                   SUBMENU_START + 0 },
                { "EmuNAND Backup/Restore...",    NULL,                    NULL,                   SUBMENU_START + 1 },
                { "Gamecart Dumper...",           NULL,                    NULL,                   SUBMENU_START + 2 },
                { "Miscellaneous...",             NULL,                    NULL,                   SUBMENU_START + 3 },
                { "Validate NAND Dump",           ValidateNandDumpDesc,    &ValidateNandDump,      0 }
            }
        },
        {
            "SysNAND Backup/Restore Options", 4, // ID 0
            {
                { "SysNAND Backup",               DumpNandMinDesc,         &DumpNand,              NB_MINSIZE },
                { "SysNAND Restore (keep hax)",   RestoreNandKeepHaxDesc,  &RestoreNand,           N_NANDWRITE | NR_KEEPA9LH },
                { "Health&Safety Dump",           HealthAndSafetyDesc,     &DumpHealthAndSafety,   0 },
                { "Health&Safety Inject",         HealthAndSafetyDesc,     &InjectHealthAndSafety, N_NANDWRITE }
            }
        },
        {
            "EmuNAND Backup/Restore Options", 4, // ID 1
            {
                { "EmuNAND Backup",               DumpNandMinDesc,         &DumpNand,              N_EMUNAND | NB_MINSIZE },
                { "EmuNAND Restore",              RestoreNandKeepHaxDesc,  &RestoreNand,           N_NANDWRITE | N_EMUNAND | N_FORCEEMU },
                { "Health&Safety Dump",           HealthAndSafetyDesc,     &DumpHealthAndSafety,   N_EMUNAND },
                { "Health&Safety Inject",         HealthAndSafetyDesc,     &InjectHealthAndSafety, N_NANDWRITE | N_EMUNAND }
            }
        },
        {
            "Gamecart Dumper Options", 6, // ID 2
            {
                { "Dump Cart (full)",             DumpGameCartFullDesc,    &DumpGameCart,          0 },
                { "Dump Cart (trim)",             DumpGameCartTrimDesc,    &DumpGameCart,          CD_TRIM },
                { "Dump & Decrypt Cart (full)",   DumpGameCartDecFullDesc, &DumpGameCart,          CD_DECRYPT },
                { "Dump & Decrypt Cart (trim)",   DumpGameCartDecTrimDesc, &DumpGameCart,          CD_DECRYPT | CD_TRIM },
                { "Dump Cart to CIA",             DumpGameCartCIADesc,     &DumpGameCart,          CD_DECRYPT | CD_MAKECIA },
                { "Dump Private Header",          DumpPrivateHeaderDesc,   &DumpPrivateHeader,     0 }
            }
        },
        {
            "Miscellaneous Options", 6, // ID 3
            {
                { "SysNAND title to CIA",         CiaBuilderDesc,          &ConvertSdToCia,        GC_CIA_DEEP },
                { "EmuNAND title to CIA",         CiaBuilderDesc,          &ConvertSdToCia,        GC_CIA_DEEP | N_EMUNAND },
                { "GBA VC Save Dump",             GbaVcSaveDesc,           &DumpGbaVcSave,         0 },
                { "GBA VC Save Inject",           GbaVcSaveDesc,           &InjectGbaVcSave,       N_NANDWRITE },
                { "NCCH Padgen",                  NcchPadgenDesc,          &NcchPadgen,            0 },
                { "System Info",                  SystemInfoDesc,          &SystemInfo,            0 }
            }
        },
        {
            NULL, 0, { { 0 } } // empty menu to signal end
        }
    };
   // Fetch the framebuffer addresses
    if(argc >= 2) {
        // newer entrypoints
        u8 **fb = (u8 **)(void *)argv[1];
        top_screen = fb[0];
        bottom_screen = fb[2];
    } else {
        // outdated entrypoints
        top_screen = (u8*)(*(u32*)0x23FFFE00);
        bottom_screen = (u8*)(*(u32*)0x23FFFE08);
    }

    u32 menu_exit = MENU_EXIT_REBOOT;
    
    if (InitializeH9(menu) <= 1) {
        menu_exit = ProcessMenu(menu, SUBMENU_START);
    }
    DeinitFS();
    
    ClearScreenFull(true, true);
    (menu_exit == MENU_EXIT_REBOOT) ? Reboot() : PowerOff();
    return 0;
}

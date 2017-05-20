# Hourglass9
_Noob friendly, safe, arm9loaderhax / sighax only NAND dumper & restorer for the 3DS console_

## What is this good for?

Hourglass9 is nothing new - all the functionality found within it is in Decrypt9, too, and possibly was in Decrypt9 for ages. What new it brings to the table is simplicity and (even more) safety. [Arm9loaderhax](https://github.com/Plailect/Guide/wiki) is a prequisite for this, and with it, __it is impossible to brick your console with Hourglass9__. So, the rather short list of features:
* __Dump your SysNAND / EmuNAND__ - to make backup copies you can later return to.
* __Restore your SysNAND / EmuNAND__ - to return to an earlier state. _This will never overwrite your existing arm9loaderhax installation_.
* __Validate existing NAND dumps__ - to make sure they are ready to restore.
* __Dump & Inject the Health and Safety app__ - to setup a CIA installer in your system. More info [here](https://gbatemp.net/threads/release-inject-any-app-into-health-safety-o3ds-n3ds-cfw-only.402236/).
* Dump retail game cartridges to .3DS / .CIA / .NDS.
* __A nice dragon logo on the bottom screen__ - you wouldn't have expected this, right?

While the stuff written above should be enough for the average user, advanced users will still need to use Decrypt9 for more specific modifications of their console OS. Also keep in mind that __you alone or responsible for keeping your backups safe and not losing them__.

## Hourglass9 controls

The most important controls are displayed on screen, here is a list of all:
* __DOWN__/__UP__ - Navigate menus, scroll output, select between options.
* __A__ - Enter submenu or confirm action.
* __B__ - Depending on location, leave submenu or cancel.
* __X__ - Make a screenshot. Works in menu and on console output, after a feature finishes.
* __X + LEFT/RIGHT__ - Batch screenshot all submenus / entries (only on menu)
* __SELECT__ - Unmount SD card (only on menu).
* __HOME__ - Reboot the console.
* __POWER__ - Poweroff the console.
* __START (+ LEFT)__ - Reboot (START only) / Poweroff (with LEFT).

Most features require the user to choose a file or a directory. In these cases, use the arrow keys to select and A / B to confirm and cancel. Also, most file write operations (NAND writes excluded) can be cancelled by holding B.

## License
You may use this under the terms of the GNU General Public License GPL v2 or under the terms of any later revisions of the GPL. Refer to the provided `LICENSE.txt` file for further information.

## Credits
* smealum, plutoo, derrek for giving the world the gift of arm9loaderhax
* delebile, dark_samus, Plailect, AuroraWright and countless others for making arm9loaderhax available to the public
* Archshift for starting Decrypt9
* Normmatt for `sdmmc.c` as well as project infrastructure (Makefile, linker setup, etc)
* Cha(N), Kane49, and all other FatFS contributors for FatFS
* b1l1s for his 'behind-the-scenes' work and for making arm9loaderhax support possible
* Relys, sbJFn5r for the decryptor
* mid-kid for hosting freenode #Cakey
* Al3x_10m for being an immense help with testing stuff that I can't test
* Everyone I forgot about - if you think you deserve to be mentioned, just contact me

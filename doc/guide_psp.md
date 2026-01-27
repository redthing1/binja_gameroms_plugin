
# guide: psp

extract iso:
```sh
7z x <game.iso>
```

locate main executable:
+ often it's `PSP_GAME/SYSDIR/EBOOT.BIN`
+ this is an encrypted ELF

decrypt executable using [pspdecrypt](https://github.com/redthing1/pspdecrypt):

```sh
./pspdecrypt /path/to/PSP_GAME/SYSDIR/EBOOT.BIN
```

or dump using PPSSPP:
+ load the game
+ `Settings > Tools > Developer tools > Dump files > Dump EBOOT...`
+ close and reopen the game

now you have a decrypted ELF

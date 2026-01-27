
# guide: switch

you need [nstool](https://github.com/jakcron/nstool/)

extract NSP:
```sh
./nstool -x extract_dir <file.nsp>
```

extract NCA containing game files:
```sh
./nstool -x extract_dir <file.nca>
```

look for executable: `main`

create NXEXE (`.nxexe`) for analysis:
```sh
python ./tools/exefs_to_nxexe.py -i /path/to/exefs
```

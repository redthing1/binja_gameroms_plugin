
# guide: 3ds

you need [ctrtool](https://github.com/3DSGuy/Project_CTR)

extract NCCH (CXI):
```sh
./ctrtool --contents=content_dir <rom>
```

create CXIEXE (`.cxiexe`) for analysis:
```sh
python3 ./tools/cxi_to_cxiexe.py -v -i <file.cxi>
```

(optional) extract `code.bin`:
```sh
./ctrtool --exefsdir=exefs_dir --decompresscode <content_file>
```

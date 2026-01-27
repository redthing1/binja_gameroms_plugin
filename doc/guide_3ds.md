
# guide: 3ds

you need [ctrtool](https://github.com/3DSGuy/Project_CTR)

extract NCCH:
```sh
./ctrtool --contents=content_dir <rom>
```

extract `code.bin`:
```sh
./ctrtool --exefsdir=exefs_dir --decompresscode <content_file>
```

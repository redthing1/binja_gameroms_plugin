
# guide: wii

extract disk image (`.iso`) using witL

```sh
./wit EXTRACT "<iso>" -D <dump_dir>
```

this should create a dir with `DATA/` and `UPDATE/`, each containing `sys/main.dol` (executable)

pack into a WIIEXE (`.wiiexe`) container:
```sh
python3 ./tools/wii_to_wiiexe.py -i <dump_dir>
```

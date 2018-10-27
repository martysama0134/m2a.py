# m2a.py
## Python Metin2 Archiver

### General
This is an old 2013 project (py22 backward-compatible), but it works perfectly fine. It can be run on Windows, FreeBSD and everywhere else.
Anything is written in python, and just the xtea/lzo algorithms are extended as PYD (cpython).
The execution (compress/decompress) is very fast.

This tool is for:
- eter packs (eix&epk MCOZ&EPKD structs)
- item_proto (152&156 structs + new ones)
- mob_proto (pre&post 2011=235&255 structs + new ones)
- locale_%s.addr (2011&2013 structs)

### Usage
How to easily pack/unpack root:
```python
>>> import m2a
>>> m2a.PM("root").Extract()
0.305999994278
### pack again, the second field is a postfix ("" overwrites the previous eix epk)
>>> m2a.PM("root", "").Compact()
0.150000095367
### to generate the .pma (index file) of a specific pack folder:
>>> m2a.PM("root", "").Generate_PMAONLY()
```
You can also use the relative drag&drop `.bat` files, and the `m2a_g.py`. Don't also forget to check the relative documentation by using `help(m2a)` and much more.

### Settings
Settings are in the `m2a/__init__.py`.

### Build deps on FreeBSD/elsewhere
Inside the `dep/_src/_c` folder you can find the relative `Makefile`. You just need to go there and do:
```sh
cd m2a.py/dep/_src/_c
make
```

#### Install lzo on Linux/Ubuntu
In case you get the _"lzomodule.c:35:10: fatal error: lzo/lzo1x.h: No such file or directory"_ error:
```sh
sudo apt install liblzo2-dev
```

### Suggested Updates
- `with open` refactoring
- new proto structs

### Credits
Copyright © 2018 martysama0134 All rights reserved.

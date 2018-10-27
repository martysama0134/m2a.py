# m2a.py
Metin2 Python Archiver

This is an old 2013 project (py22 backward-compatible), but it works perfectly fine. It can be run on Windows, FreeBSD and everywhere else.
Anything is written in python, and just the xtea/lzo algorithms are extended as PYD (cpython).
The execution (compress/decompress) is very fast.

This tool is for:
- eter packs (eix&epk MCOZ&EPKD structs)
- item_proto (152&156 structs + new ones)
- mob_proto (pre&post 2011=235&255 structs + new ones)
- locale_%s.addr (2011&2013 structs)

How to easily pack/unpack root:
```python
>>> import m2a
>>> m2a.PM("root").Extract()
0.305999994278
>>> m2a.PM("root", "").Compact()
0.150000095367
```
You can also use the relative drag&drop `.bat` files, and the `m2a_g.py`. Don't also forget to check the relative documentation by using `help(m2a)` and much more.

Copyright © 2018 martysama0134 All rights reserved.

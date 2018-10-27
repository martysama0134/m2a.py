#! /usr/bin/env python

# Copyright (c) 2013, martysama0134
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# Neither the name of martysama0134 nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""PYTHON METIN2 ARCHIVER (PMA)

Python Metin2 Archiver for:
-Packs (eix&epk MCOZ&EPKD structs)
-item_proto (152&156 structs)
-mob_proto (pre&post 2011=235&255 structs)
-locale_%s.addr (2011&2013 structs)

"""
__author__		= "martysama0134 <martysama0134@gmail.com>"
__copyright__	= "Copyright (c) 2013 martysama0134"
__date__		= "2018-10-27"
__license__		= "GNU GPL v3.0 License"
__version__		= "4.5.3"






EIX_EXTS = ".eix"
EPK_EXTS = ".epk"

MT2_MAGIC1 = 'MCOZ'		# xtea(lzo(file.eix)) or lzo(file.eix) if esize is 0
MT2_MAGIC2 = 'EPKD'		# file.eix
MT2_MAGIC3 = 'MIPX'		# xtea(lzo(item_proto))
MT2_MAGIC4 = 'MMPT'		# xtea(lzo(mob_proto))

MT2_XTEAKEY_INDEX = 'B99EB0026F69810563989B2879181A00'.decode('hex')		# eix xtea_key
MT2_XTEAKEY_DATA = '22B8B40464B26E1FAEEA1800A6F6FB1C'.decode('hex')			# epk xtea_key

MT2_XTEAKEY_IPX = 'A1A40200AA155404E78B5A18ABD6AA01'.decode('hex')			# item_proto xtea_key
MT2_XTEAKEY_MPX = '467449000B4A0000B76E08009D186800'.decode('hex')			# mob_proto xtea_key

MT2_XTEAKEY_ADDR = "821B34AE123BFB17D72C39AE4198F163".decode("hex")			# locale_%s.addr xtea_key

MCOZ_HEADER = {
	'magic':	'MCOZ',		# magic header
	'esize':	0L,			# xtea encrypted code size (if 0 skip)
	'csize':	0L,			# lzo compressed code size
	'dsize':	0L,			# lzo decompressed code size
}
EPKD_HEADER = {
	'magic':	'EPKD',		# magic header
}
EIX_HEADER = {
	'magic':	'MCOZ',		# magic header
	'version':	0L,			# eix version
	'count':	0L,			# number of files
}
MIPX_HEADER = {
	'magic':	'MIPX',		# magic header
	'version':	0L,			# version of the header
	'struct':	0L,			# length of the elements
	'count':	0L,			# count of the elements
	'esize':	0L,			# xtea encrypted code size
}
MMPT_HEADER = {
	'magic':	'MMPT',		# magic header
	'count':	0L,			# count of the elements
	'esize':	0L,			# xtea encrypted code size
}

EIX_COMPRESSION = 1 #0 or 1 (EPKD or MCOZ)
LZO_COMPRESSION_LEVEL = 9 #1 or 9

DEBUG_MODE = False #extract eix|epk struct list
EXT_DEBUG_MODE = False #extract pseudo lzo-xtea (de|)compressed/(de|en)crypted files from eix|epk

MPROTO_STRUCT_TYPE = 1 # 1 [2011], 2 [2013], 3 [2014 bleeding], 4 [2015 claw+pet], 5 [2016 br], 6 [2018] {only 1 re-pack successfully}


LFR2_AUTO_TYPE = True	#only for lfr2 def
LFR2_TYPE_EXTS = {
	#0:("_proto",".dds",".gr2",".jpg",".ifl",".mdatr",".mp3",".msenv",".png",".pra",".prb",".prd",".pre",".prt",".scc",".sub",".wav",".wtr",),
	#1:(".atr",".bmp",".mde",".mse",".msf",".pyc",".pyd",".raw",".sfk",".spt",".tga",".uvw",),
	0:("_proto",".mp3"),
	1:(".atr",".bmp",".mde",".mse",".msf",".pyc",".pyd",".raw",".sfk",".spt",".tga",".uvw",".dds",".gr2",".jpg",".ifl",".mdatr",".mp3",".msenv",".png",".pra",".prb",".prd",".pre",".prt",".scc",".sub",".wav",".wtr",),
	2:(".msa",".msk",".msm",".mss",".py",".txt",),
}
LFR2_SKIP_EXTS = ("Thumbs.db","server_attr",".bak",".exe",".psd",".xml","~")

listPackTypes = {
	0:("item_proto","mob_proto","mp3","pyd","dds","gr2","jpg","png"),
	1:("atr","bmp","mde","msf","pyc","raw","sfk","spt","tga","uvw","ifl","mdatr","msenv","pra","prb","prd","pre","prt","scc","sub","wav","wtr"),
	2:("msa","mse","msk","msm","mss","py","txt"),
}


from m2a_main import PackManager,IProtoManager,MProtoManager,AddrManager,GetPath,SetPath
PM,IM,MM,AM=PackManager,IProtoManager,MProtoManager,AddrManager



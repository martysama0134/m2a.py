# Copyright (c) 2013, martysama0134
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# Neither the name of martysama0134 nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#std
import struct
from time import strftime
#nstd
import lzo
import xtea3 as _xtea
#pkg
from m2a import MT2_MAGIC1, MT2_MAGIC3, MT2_XTEAKEY_IPX, LZO_COMPRESSION_LEVEL, EXT_DEBUG_MODE

### ITEM_PROTO
def iproto_load(iproto):
	pack, unpack = struct.pack, struct.unpack

	ip_f1 = open(iproto, "rb")
	iph = {}
	iph['magic'] = ip_f1.read(4)
	iph['version'] = unpack("I", ip_f1.read(4))[0]
	iph['struct'] = unpack("I", ip_f1.read(4))[0]
	iph['count'] = unpack("I", ip_f1.read(4))[0]
	iph['esize'] = unpack("I", ip_f1.read(4))[0]

	import cStringIO
	ip_data1 = cStringIO.StringIO(ip_f1.read(iph['esize']))
	ip_f1.close(); del ip_f1

	ipph = {}
	ipph['magic'] = unpack("I", ip_data1.read(4))[0]
	ipph['esize'] = unpack("I", ip_data1.read(4))[0]
	ipph['csize'] = unpack("I", ip_data1.read(4))[0]
	ipph['dsize'] = unpack("I", ip_data1.read(4))[0]

	ip_data2 = _xtea.decrypt_all(ip_data1.read(ipph['esize']), MT2_XTEAKEY_IPX)
	if EXT_DEBUG_MODE:
		ttt=open(iproto+".unxtea", "wb");ttt.write(ip_data2);ttt.close()

	ip_data3 = lzo.decompress("\xf0"+pack("!L", ipph['dsize'])+ip_data2[4:ipph['csize']+4])
	if EXT_DEBUG_MODE:
		ttt=open(iproto+".unlzo", "wb");ttt.write(ip_data3);ttt.close()
	#ima_maker(iproto, iph, ip_data3)
	ip_data2,ip_data1,ipph=None,None,None
	return iph, ip_data3
def ima_maker(iproto, iph, ip_data):
	pack, unpack = struct.pack, struct.unpack
	import cStringIO
	cSIO_SIO = cStringIO.StringIO

	ipm_io = cSIO_SIO(ip_data)
	ipm_io_read = ipm_io.read

	ip_file = open(iproto+".ima", "w")
	ip_file_write = ip_file.write

	ip_file_write("!%d\n@%d\n#count: %d\n#author: %s\n#datetime: %s\n"%(iph['version'], iph['struct'], iph['count'], "martysama0134`s PythonMetin2Archiver", strftime("Data: %d:%m:%Y Ora: %H:%M:%S")))
	ipm_rsc = None

	for idx in xrange(iph['count']):
		ipm_rsc = cSIO_SIO(ipm_io_read(iph['struct']))
		ipm_rsc_read = ipm_rsc.read
		itemData = ""
		itemData += "vnum=%d|" % (unpack("I", ipm_rsc_read(4))[0])#vnum
		if iph['struct']==156 or iph['struct']==158:
			itemData += "vnum_range=%d|" % (unpack("I", ipm_rsc_read(4))[0])#vnum_range
		itemData += "name=%s|" % (ipm_rsc_read(25).replace('\0', ''))#name
		itemData += "locale_name=%s|" % (ipm_rsc_read(25).replace('\0', ''))#locale_name
		itemData += "type=%d|" % (unpack("B", ipm_rsc_read(1))[0])#type
		itemData += "subtype=%d|" % (unpack("B", ipm_rsc_read(1))[0])#subtype
		itemData += "weight=%d|" % (unpack("B", ipm_rsc_read(1))[0])#weight
		itemData += "size=%d|" % (unpack("B", ipm_rsc_read(1))[0])#size
		itemData += "antiflag=%d|" % (unpack("I", ipm_rsc_read(4))[0])#antiflag
		itemData += "flag=%d|" % (unpack("I", ipm_rsc_read(4))[0])#flag
		itemData += "wearflag=%d|" % (unpack("I", ipm_rsc_read(4))[0])#wearflag
		itemData += "immuneflag=%d|" % (unpack("I", ipm_rsc_read(4))[0])#immuneflag
		itemData += "gold=%d|" % (unpack("I", ipm_rsc_read(4))[0])#gold
		itemData += "buy_price=%d|" % (unpack("I", ipm_rsc_read(4))[0])#buy_price
		itemData += "limittype0=%d|" % (unpack("B", ipm_rsc_read(1))[0])#limittype0
		itemData += "limitvalue0=%d|" % (unpack("I", ipm_rsc_read(4))[0])#limitvalue0
		itemData += "limittype1=%d|" % (unpack("B", ipm_rsc_read(1))[0])#limittype1
		itemData += "limitvalue1=%d|" % (unpack("I", ipm_rsc_read(4))[0])#limitvalue1
		itemData += "applytype0=%d|" % (unpack("B", ipm_rsc_read(1))[0])#applytype0
		itemData += "applyvalue0=%d|" % (unpack("I", ipm_rsc_read(4))[0])#applyvalue0
		itemData += "applytype1=%d|" % (unpack("B", ipm_rsc_read(1))[0])#applytype1
		itemData += "applyvalue1=%d|" % (unpack("I", ipm_rsc_read(4))[0])#applyvalue1
		itemData += "applytype2=%d|" % (unpack("B", ipm_rsc_read(1))[0])#applytype2
		itemData += "applyvalue2=%d|" % (unpack("I", ipm_rsc_read(4))[0])#applyvalue2
		itemData += "value0=%d|" % (unpack("I", ipm_rsc_read(4))[0])#value0
		itemData += "value1=%d|" % (unpack("I", ipm_rsc_read(4))[0])#value1
		itemData += "value2=%d|" % (unpack("I", ipm_rsc_read(4))[0])#value2
		itemData += "value3=%d|" % (unpack("I", ipm_rsc_read(4))[0])#value3
		itemData += "value4=%d|" % (unpack("I", ipm_rsc_read(4))[0])#value4
		itemData += "value5=%d|" % (unpack("I", ipm_rsc_read(4))[0])#value5
		itemData += "socket0=%d|" % (unpack("I", ipm_rsc_read(4))[0])#socket0
		itemData += "socket1=%d|" % (unpack("I", ipm_rsc_read(4))[0])#socket1
		itemData += "socket2=%d|" % (unpack("I", ipm_rsc_read(4))[0])#socket2
		itemData += "refined_vnum=%d|" % (unpack("I", ipm_rsc_read(4))[0])#refined_vnum
		itemData += "refine_set=%d|" % (unpack("H", ipm_rsc_read(2))[0])#refine_set
		itemData += "magic_pct=%d|" % (unpack("B", ipm_rsc_read(1))[0])#magic_pct
		itemData += "specular=%d|" % (unpack("B", ipm_rsc_read(1))[0])#specular
		itemData += "socket_pct=%d" % (unpack("B", ipm_rsc_read(1))[0])#socket_pct
		if iph['struct']==158:
			itemData += "|wearable_flag=%d" % (unpack("H", ipm_rsc_read(2))[0])#unk1
		ip_file_write("%s\n" % itemData)

	if ipm_rsc:
		ipm_rsc = None
	ipm_io = None
	ip_file.close(); del ip_file
def ima_loader(iproto):
	def nullpadder(str, msize=25):
		np_len = len(str)
		if not np_len:
			return '\0'*msize
		npp_len = np_len % msize
		if not npp_len:
			return str
		elif npp_len>msize:
			return str[:25]
		else:
			return str+((msize-npp_len)*'\0')
	pack, unpack = struct.pack, struct.unpack

	import re
	re_findall = re.findall

	ip_imaX = open(iproto+".ima", "r")
	ip_ima = ip_imaX.read().split("\n")
	ip_imaX.close(); del ip_imaX

	pat156 = r'^vnum=(\d+)\|vnum_range=(\d+)\|name=([^\|]+)\|locale_name=([^\|]+)\|type=(\d+)\|subtype=(\d+)\|weight=(\d+)\|size=(\d+)\|antiflag=(\d+)\|flag=(\d+)\|wearflag=(\d+)\|immuneflag=(\d+)\|gold=(\d+)\|buy_price=(\d+)\|limittype0=(\d+)\|limitvalue0=(\d+)\|limittype1=(\d+)\|limitvalue1=(\d+)\|applytype0=(\d+)\|applyvalue0=(\d+)\|applytype1=(\d+)\|applyvalue1=(\d+)\|applytype2=(\d+)\|applyvalue2=(\d+)\|value0=(\d+)\|value1=(\d+)\|value2=(\d+)\|value3=(\d+)\|value4=(\d+)\|value5=(\d+)\|socket0=(\d+)\|socket1=(\d+)\|socket2=(\d+)\|refined_vnum=(\d+)\|refine_set=(\d+)\|magic_pct=(\d+)\|specular=(\d+)\|socket_pct=(\d+)$'
	pat152 = r'^vnum=(\d+)\|name=([^\|]+)\|locale_name=([^\|]+)\|type=(\d+)\|subtype=(\d+)\|weight=(\d+)\|size=(\d+)\|antiflag=(\d+)\|flag=(\d+)\|wearflag=(\d+)\|immuneflag=(\d+)\|gold=(\d+)\|buy_price=(\d+)\|limittype0=(\d+)\|limitvalue0=(\d+)\|limittype1=(\d+)\|limitvalue1=(\d+)\|applytype0=(\d+)\|applyvalue0=(\d+)\|applytype1=(\d+)\|applyvalue1=(\d+)\|applytype2=(\d+)\|applyvalue2=(\d+)\|value0=(\d+)\|value1=(\d+)\|value2=(\d+)\|value3=(\d+)\|value4=(\d+)\|value5=(\d+)\|socket0=(\d+)\|socket1=(\d+)\|socket2=(\d+)\|refined_vnum=(\d+)\|refine_set=(\d+)\|magic_pct=(\d+)\|specular=(\d+)\|socket_pct=(\d+)$'
	m_struct = 152
	m_version = 1

	ip_out = open(iproto+".ima.ipraw", "wb")
	ip_out_write = ip_out.write

	m_count = 0
	for iima in ip_ima:
		if not iima or iima[0]=='#':
			continue
		elif iima[0]=='@':
			m_struct = int(iima[1:])
			continue
		elif iima[0]=='!':
			m_version = int(iima[1:])
			continue
		if m_struct==156:
			m = re_findall(pat156, iima)[0]
			if not len(m)==38:
				continue
			ip_out_write(pack("I", long(m[0])))
			ip_out_write(pack("I", long(m[1])))
			ip_out_write(nullpadder(m[2]))
			ip_out_write(nullpadder(m[3]))
			ip_out_write(pack("B", long(m[4])))
			ip_out_write(pack("B", long(m[5])))
			ip_out_write(pack("B", long(m[6])))
			ip_out_write(pack("B", long(m[7])))
			ip_out_write(pack("I", long(m[8])))
			ip_out_write(pack("I", long(m[9])))
			ip_out_write(pack("I", long(m[10])))
			ip_out_write(pack("I", long(m[11])))
			ip_out_write(pack("I", long(m[12])))
			ip_out_write(pack("I", long(m[13])))
			ip_out_write(pack("B", long(m[14])))
			ip_out_write(pack("I", long(m[15])))
			ip_out_write(pack("B", long(m[16])))
			ip_out_write(pack("I", long(m[17])))
			ip_out_write(pack("B", long(m[18])))
			ip_out_write(pack("I", long(m[19])))
			ip_out_write(pack("B", long(m[20])))
			ip_out_write(pack("I", long(m[21])))
			ip_out_write(pack("B", long(m[22])))
			ip_out_write(pack("I", long(m[23])))
			ip_out_write(pack("I", long(m[24])))
			ip_out_write(pack("I", long(m[25])))
			ip_out_write(pack("I", long(m[26])))
			ip_out_write(pack("I", long(m[27])))
			ip_out_write(pack("I", long(m[28])))
			ip_out_write(pack("I", long(m[29])))
			ip_out_write(pack("I", long(m[30])))
			ip_out_write(pack("I", long(m[31])))
			ip_out_write(pack("I", long(m[32])))
			ip_out_write(pack("I", long(m[33])))
			ip_out_write(pack("H", long(m[34])))
			ip_out_write(pack("B", long(m[35])))
			ip_out_write(pack("B", long(m[36])))
			ip_out_write(pack("B", long(m[37])))
		elif m_struct==152:
			m = re_findall(pat152, iima)[0]
			if not len(m)==37:
				continue
			ip_out_write(pack("I", long(m[0])))
			ip_out_write(nullpadder(m[1]))
			ip_out_write(nullpadder(m[2]))
			ip_out_write(pack("B", long(m[3])))
			ip_out_write(pack("B", long(m[4])))
			ip_out_write(pack("B", long(m[5])))
			ip_out_write(pack("B", long(m[6])))
			ip_out_write(pack("I", long(m[7])))
			ip_out_write(pack("I", long(m[8])))
			ip_out_write(pack("I", long(m[9])))
			ip_out_write(pack("I", long(m[10])))
			ip_out_write(pack("I", long(m[11])))
			ip_out_write(pack("I", long(m[12])))
			ip_out_write(pack("B", long(m[13])))
			ip_out_write(pack("I", long(m[14])))
			ip_out_write(pack("B", long(m[15])))
			ip_out_write(pack("I", long(m[16])))
			ip_out_write(pack("B", long(m[17])))
			ip_out_write(pack("I", long(m[18])))
			ip_out_write(pack("B", long(m[19])))
			ip_out_write(pack("I", long(m[20])))
			ip_out_write(pack("B", long(m[21])))
			ip_out_write(pack("I", long(m[22])))
			ip_out_write(pack("I", long(m[23])))
			ip_out_write(pack("I", long(m[24])))
			ip_out_write(pack("I", long(m[25])))
			ip_out_write(pack("I", long(m[26])))
			ip_out_write(pack("I", long(m[27])))
			ip_out_write(pack("I", long(m[28])))
			ip_out_write(pack("I", long(m[29])))
			ip_out_write(pack("I", long(m[30])))
			ip_out_write(pack("I", long(m[31])))
			ip_out_write(pack("I", long(m[32])))
			ip_out_write(pack("H", long(m[33])))
			ip_out_write(pack("B", long(m[34])))
			ip_out_write(pack("B", long(m[35])))
			ip_out_write(pack("B", long(m[36])))
		m_count+=1
	ip_out.close()
	ip_ima = None
	return m_version, m_count, m_struct
def iproto_save(ipin, ipout, m_version, m_count, m_struct):
	def nullpadding(mlen, msize=8):
		retlen = ''
		mpad = mlen%msize
		if mpad:
			retlen = (msize-mpad)*chr(0)
		return retlen
	pack, unpack = struct.pack, struct.unpack
	global MT2_MAGIC1, MT2_MAGIC3, MT2_XTEAKEY_IPX, LZO_COMPRESSION_LEVEL

	ip_out2X = open(ipin, "rb")
	ip_out2 = ip_out2X.read()
	ip_out2X.close(); del ip_out2X

	ipl_out2 = len(ip_out2)
	ip_out3 = lzo.compress(ip_out2, LZO_COMPRESSION_LEVEL)
	ipd_out3 = unpack("!L", ip_out3[1:5])[0]

	ipp_out3 = ip_out3[5:]
	ipl_out3 = len(ipp_out3)
	ip_out4 = ipp_out3+nullpadding(ipl_out3)

	ip_out5 = _xtea.encrypt_all(MT2_MAGIC1+ip_out4+chr(0)*4, MT2_XTEAKEY_IPX)
	ipl_out5 = len(ip_out5)

	ipp_h1 = MT2_MAGIC3+pack("I", m_version)+pack("I", m_struct)+pack("I", m_count)+pack("I", ipl_out5+16)
	ipp_hl2 = MT2_MAGIC1+pack("I", ipl_out5)+pack("I", ipl_out3)+pack("I", ipd_out3)

	ip_outX = open(ipout, "wb")
	ip_outX.write(ipp_h1+ipp_hl2+ip_out5)
	ip_outX.close()

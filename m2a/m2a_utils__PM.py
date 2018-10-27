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
import os
import sys
import struct
#nstd
import lzo
import _xtea

from m2a import EIX_EXTS,EPK_EXTS,MT2_MAGIC1,MT2_MAGIC2,\
	EIX_COMPRESSION,LZO_COMPRESSION_LEVEL,\
	LFR2_AUTO_TYPE,LFR2_TYPE_EXTS,LFR2_SKIP_EXTS,\
	listPackTypes,\
	MT2_XTEAKEY_INDEX,MT2_XTEAKEY_DATA,\
	DEBUG_MODE,EXT_DEBUG_MODE

# PACKS
class PMAExtractError(Exception): pass
class PMACompactError(Exception): pass

FILENAME_G = "Noname"

def eix_load(modulename):
	unpack = struct.unpack

	global EIX_EXTS,MT2_MAGIC1,MT2_MAGIC2
	global FILENAME_G
	filename = FILENAME_G = modulename+EIX_EXTS

	eix_header = {}

	eix_file = open(filename, "rb")
	eix_s = eix_file.read(16)
	if(len(eix_s)<16):
		raise PMAExtractError, "The %s eix-file is too small. (header missing?)"%filename
	eix_header["magic"] = eix_s[0:4]
	eix_res,eix_data = None,None
	if eix_header["magic"] in (MT2_MAGIC1,):
		eix_header["esize"] = unpack("I", eix_s[4:8])[0]
		eix_header["csize"] = unpack("I", eix_s[8:12])[0]
		eix_header["dsize"] = unpack("I", eix_s[12:16])[0]
		if eix_header["esize"]&7:
			eix_header["esize"]=(eix_header["esize"]&0xfffffff8)+8
		# print eix_header["esize"],eix_header["csize"],eix_header["dsize"]
		eix_data = eix_file.read(eix_header["esize"])
		if not eix_data or len(eix_data)<eix_header["csize"]:
			raise PMAExtractError, "The %s eix-file is too small. (data missing?)"%filename
		#print eix_header["csize"]
		eix_res = eix_unpack_LZO(*eix_unpack_XTEA(eix_data, eix_header))
	elif eix_header["magic"]==MT2_MAGIC2:
		eix_file.seek(0)
		eix_data = eix_file.read()
		if not eix_data:
			raise PMAExtractError, "The %s eix-file is too small. (data missing?)"%filename
		eix_res = eix_data
	else:
		raise PMAExtractError, "The %s eix-file has an unrecognized magic header."%filename
	eix_file.close();del eix_file

	del unpack
	del filename,eix_s,eix_data,eix_header
	return eix_res
def eix_unpack_XTEA(eix_data1, eix_header):
	def nullpadding(mlen, msize=8):
		retlen = ''
		mpad = mlen%msize
		if mpad:
			retlen = (msize-mpad)*chr(0)
		return retlen
	global FILENAME_G,EXT_DEBUG_MODE
	filename = FILENAME_G
	if eix_header["esize"]==0:
		raise PMAExtractError, "The %s eix-file has not an encrypted index. (wrong file?)"%filename

	if EXT_DEBUG_MODE:
		ttt=open("%s._inxtea"%filename, "wb");ttt.write(eix_data1);ttt.close()
	#print len(eix_data1)
	#if eix_header["esize"]&7:
	#	eix_header["esize"]=(eix_header["esize"]&0xfffffff8)+8
	global MT2_XTEAKEY_INDEX
	eix_decrypted = _xtea.decrypt_all(eix_data1+nullpadding(len(eix_data1)), MT2_XTEAKEY_INDEX)
	#print len(eix_data1)
	#print len(eix_decrypted)
	#open("pc.eix._unxtea", "wb").write(eix_decrypted)
	if EXT_DEBUG_MODE:
		ttt=open("%s._inxtea"%filename, "wb");ttt.write(eix_data1);ttt.close()
		ttt=open("%s._unxtea"%filename, "wb");ttt.write(eix_decrypted);ttt.close()
	if eix_decrypted[0:4] not in (MT2_MAGIC1,):
		raise PMAExtractError, "The %s eix-file has an unrecognized xtea key."%(filename)
	return eix_decrypted[4:eix_header["csize"]+1]+"\x11\0\0", eix_header["dsize"]
def eix_unpack_LZO(eix_data2, out_len):
	pack = struct.pack
	return lzo.decompress("\xf0"+pack("!L", out_len)+eix_data2)
def eix_analyze(eix_data3):
	unpack = struct.unpack

	eix_header = {}
	eix_header["magic"] = eix_data3[0:4]
	eix_header["version"] = unpack("I", eix_data3[4:8])[0]
	eix_header["count"] = unpack("I", eix_data3[8:12])[0]
	if eix_header["version"]!=2:
		raise PMAExtractError, "The %d eix-version is not supported."%eix_header["version"]
	import cStringIO
	eix_sio = cStringIO.StringIO(eix_data3[12:])
	eix_sio_read = eix_sio.read

	eix_index = []
	for idx in xrange(eix_header["count"]): #192
		eix_index.append({
			"id":				unpack("I", eix_sio_read(4))[0],
			"filename":			eix_sio_read(161).replace("\0", ""),
			"filename_mp":		eix_sio_read(3)[0],
			"filename_crc":		unpack("I", eix_sio_read(4))[0],
			"real_data_size":	unpack("I", eix_sio_read(4))[0],
			"data_size":		unpack("I", eix_sio_read(4))[0],
			"data_crc":			unpack("I", eix_sio_read(4))[0],
			"data_position":	unpack("I", eix_sio_read(4))[0],
			"compressed_type":	unpack("b", eix_sio_read(1))[0],
			"compressed_type_mp":		eix_sio_read(3)[0]
		})
	del eix_header,eix_sio,eix_sio_read
	return eix_index

def epk_load(modulename, eix_index):
	global EPK_EXTS,MT2_XTEAKEY_DATA
	filename = modulename+EPK_EXTS
	text,mlist=None,None
	def clean_all(text, mlist=r'\:*?"<>'):
		for i in mlist:
			text = text.replace(i, "")
		return text
	mlen,msize=None,None
	def nullpadding(mlen, msize=8):
		retlen = ''
		mpad = mlen%msize
		if mpad:
			retlen = (msize-mpad)*chr(0)
		return retlen
	pathname1,pathname2=None,None
	def pathmake(pathname1):
		if not os.path.exists(pathname1):
			os.makedirs(pathname1)
		#if not os.path.isdir(pathname1):
		#	raise IOError, "%s is not a directory!"%pathname1
	def pathcheck(pathname2):
		# bugfix for xml inside filename bug
		# pathname2=pathname2.split()[0]
		#print pathname2
		if ":" in pathname2:
			pathname2 = pathname2[3:]
		pathname2 = clean_all(pathname2)
		if pathname2:
			pathname2 = modulename+"/"+pathname2
		if "/" in pathname2:
			pathmake("/".join(pathname2.split("/")[:-1]))
		return pathname2
	pathmake(modulename)

	pack, unpack = struct.pack, struct.unpack
	lzo_decompress = lzo.decompress
	xtea_decrypt_all = _xtea.decrypt_all

	global DEBUG_MODE
	if DEBUG_MODE:
		bla1=open(filename+".eix_index.txt","w")
		for idx in eix_index:
			bla1.write(str(idx)+"\n")
		bla1.close()
		bla2=open(filename+".epk_header.txt","w")
	###return
	epk_file = open(filename, "rb")
	epk_file_seek = epk_file.seek
	epk_file_read = epk_file.read

	epk_header = {}
	out_name,out_nameX=None,None
	epk_data0,epk_data1,epk_data1b,epk_data2=None,None,None,None
	#m_i=1
	#eix_index_l = len(eix_index)
	global EXT_DEBUG_MODE
	if EXT_DEBUG_MODE:
		epk_header_sp = {}
	for idx in eix_index:
		epk_file_seek(idx["data_position"])
		#print str(idx)
		epk_header["magic"] = epk_file_read(4)
		epk_header["esize"] = unpack("I", epk_file_read(4))[0]
		epk_header["csize"] = unpack("I", epk_file_read(4))[0]
		epk_header["dsize"] = unpack("I", epk_file_read(4))[0]
		#sys.stdout.write("\rExtraction of %s in progress"%idx['filename'])
		#sys.stdout.write("Extraction of %s in progress\n"%idx['filename'])
		#sys.stdout.write("\rExtraction in progress: %d/%d"%(m_i, eix_index_l))
		#m_i+=1
		#print idx
		if idx["compressed_type"] == 0:
			epk_file_seek(idx["data_position"])
			epk_data0 = epk_file_read(idx["data_size"])
			out_name = pathcheck(idx["filename"])
			if out_name:
				out_nameX = open(out_name, "wb")
				out_nameX.write(epk_data0)
				out_nameX.close()
			else:
				print "<bug!>\n%s\n%s"%(str(epk_header),str(idx))
		elif idx["compressed_type"] == 1:
			if DEBUG_MODE:
				bla2.write(str(epk_header)+"\n")
			epk_file_seek(idx["data_position"]+16)
			if epk_file_read(4)!=MT2_MAGIC1:
				print epk_header, idx
				raise PMAExtractError, "The %s epk-file has an unrecognized lzo compression."%filename
			epk_data0 = epk_file_read(epk_header["csize"])
			epk_data1 = lzo_decompress("\xf0"+pack("!L", epk_header["dsize"])+epk_data0[:-3]+"\x11\0\0")
			out_name = pathcheck(idx["filename"])
			if out_name:
				out_nameX = open(out_name, "wb")
				out_nameX.write(epk_data1)
				out_nameX.close()
				if EXT_DEBUG_MODE:
					ttt=open("%s.load.unlzo"%out_name, "wb");ttt.write(epk_data1);ttt.close()
			else:
				print "<bug!>\n%s\n%s"%(str(epk_header),str(idx))
		elif idx["compressed_type"] == 2:
			if DEBUG_MODE:
				bla2.write(str(epk_header)+"\n")
			#out_name = pathcheck(idx["filename"])
			#if not out_name:
			#	continue
			epk_file_seek(idx["data_position"]+16)
			if epk_header["esize"]&7:
				epk_header["esize"]=(epk_header["esize"]&0xfffffff8)+8
			epk_data0 = epk_file_read(epk_header["esize"])
			epk_data1 = xtea_decrypt_all(epk_data0, MT2_XTEAKEY_DATA)
			#epk_data1 = xtea_decrypt_all(epk_data0+nullpadding(len(epk_data0)), MT2_XTEAKEY_DATA)
			if epk_data1[0:4]!=MT2_MAGIC1:
				print epk_header, idx
				raise PMAExtractError, "The %s epk-file has an unrecognized xtea key."%filename
			#print epk_data1[4].encode('hex')
			#print idx, len(epk_data1), epk_header
			epk_data1b = epk_data1[4:epk_header["csize"]+1]+"\x11\0\0"
			#open(out_name+".unxtea", "wb").write(epk_data1)
			epk_data2 = lzo_decompress("\xf0"+pack("!L", epk_header["dsize"])+epk_data1b[:-3]+"\x11\0\0")

			out_name = pathcheck(idx["filename"])
			if out_name:
				out_nameX = open(out_name, "wb")
				out_nameX.write(epk_data2)
				out_nameX.close()
				if EXT_DEBUG_MODE:
					#epk_file_seek(idx["data_position"])
					ttt=open("%s.load.inxtea"%out_name, "wb");ttt.write(epk_file_read(16)+epk_data0);ttt.close()
					ttt=open("%s.load.unxtea"%out_name, "wb");ttt.write(epk_data1);ttt.close()
					ttt=open("%s.load.unlzo"%out_name, "wb");ttt.write(epk_data1b);ttt.close()
			else:
				print "<bug!>\n%s\n%s"%(str(epk_header),str(idx))
			#open(out_name, "wb").write(epk_data2)
		else:
			print "The %d type is not supported."%idx["compressed_type"]
		#epk_data0,epk_data1,epk_data1b,epk_data2,epk_header=None,None,None,None,{}
	if DEBUG_MODE:
		bla2.close()
	#sys.stdout.write("\n")
	#del nullpadding,pathcheck
	#clean_all,nullpadding,pathmake,pathcheck=None,None,None,None
	#del filename,text,mlist,mlen,msize,pathname1,pathname2
	#del pack,unpack,lzo_decompress,xtea_decrypt_all
	#del epk_header,out_name,out_nameX
	#del epk_data0,epk_data1,epk_data1b,epk_data2
def xml_maker(modulename, eix_index):
	def clean_all(text, mlist=r'\:*?"<>'):
		text_replace = text.replace
		for i in mlist:
			text = text_replace(i, "")
		return text
	#		<File archivedPath="d:/ymir work/effect/affect/3spot.dds" type="1"><![CDATA[sukame\ymir work\effect\affect\3spot.dds]]></File>
	#		r'<File archivedPath="%s" type="%d"><![CDATA[%s]]></File>'
	#print "checking %s"%modulename
	datxml = '\t\t<File archivedPath="%s" type="%d"><![CDATA[%s]]></File>\n'

	xmldump = open("%s.xml"%modulename, "w")
	xmldump.write('<Buildfile version="1.1">\n\t<Action type="create" output="%s">\n'%modulename)

	for i in eix_index:
		xmldump.write(datxml%(i["filename"], i["compressed_type"], modulename+clean_all(i["filename"][2:]).replace("/", "\\")))
		#print i["filename"], i["compressed_type"]
	xmldump.write('\t</Action>\n</Buildfile>\n')
	xmldump.close()

def pma_generate(modulename):
	def detect_type(fileName):
		for ty1,el1 in listPackTypes.iteritems():
			for el2 in el1:
				if fileName.endswith(el2):
					return ty1
		print "no type found for %s"%fileName
		return 0
	def fixSlashes(fileName):
		if "\\" in fileName:
			return fileName.replace("\\", "/")
		return fileName
	def MergeDirnFiles(modulename, subdir, file):
		# print modulename, subdir, file
		subdir = subdir[len(modulename)+1:]
		if subdir:
			return fixSlashes("%s/%s" % (subdir, file))
		return fixSlashes(file)
	eix_index = []
	for subdir, dirs, files in os.walk(modulename):
		for file in files:
			idx = {
				'compressed_type':detect_type(file),
				'filename':MergeDirnFiles(modulename, subdir, file),
			}
			# print subdir, file, idx["filename"]
			eix_index.append(idx)
	pma_maker(modulename, eix_index)

def pma_maker(modulename, eix_index):
	def clean_all(text, mlist=r'\:*?"<>'):
		text_replace = text.replace
		for i in mlist:
			text = text_replace(i, "")
		return text
	pathname2 = None
	def pathcheck(pathname2):
		#print pathname2
		if ":" in pathname2:
			pathname2 = pathname2[3:]
		pathname2 = clean_all(pathname2)
		if pathname2:
			pathname2 = modulename+"/"+pathname2
		return pathname2
	l_index = len(eix_index)
	f_index = open(modulename+".pma", "wb")
	f_index_write = f_index.write

	#f_index_write("@%s\n"%modulename)
	out_name = None
	for idx in eix_index:
		out_name = pathcheck(idx['filename'])
		if out_name:
			f_index_write("%d|%s|%s\n"%(idx['compressed_type'], idx['filename'], out_name))
	f_index.close()

	del pathname2
	del l_index,f_index,out_name
def pma_loader(modulename, pin):
	def pma_analyze(m_header):
		os_path_exists = os.path.exists
		for m_data in m_header:
			if not os_path_exists(m_data['r_path']):
				raise PMACompactError, "%s file not exists"%m_data['r_path']
	import re
	re_findall = re.findall

	module_dataX = open(modulename+".pma", "r")
	module_data = module_dataX.read().split("\n")
	module_dataX.close(); del module_dataX
	#m_process = ''
	m_header = []
	m = None
	for m_data in module_data:
		if not m_data:
			continue
		#if m_data[0]=="@":
		#	m_process = m_data[1:]
		#m=re.findall(r'^([0-9]+)\|([^\|\\\:\*\?\"\<\>]+)\|([^\|\\\:\*\?\"\<\>]+)$', m_data)
		m=re_findall(r'^([0-9]+)\|([^\|]+)\|([^\|]+)$', m_data)
		for m_type,v_path,r_path in m:
			if (not m_type) or (not v_path) or (not r_path):
				continue
			#print m_type,v_path,r_path
			m_header.append({'type':int(m_type),'v_path':v_path,'r_path':r_path})
	pma_analyze(m_header)#, m_process)
	return modulename, pin, m_header

class GoOut1stLevelLoop(Exception): pass
class GoOut2ndLevelLoop(Exception): pass
class GoOut3rdLevelLoop(Exception): pass
def deduct_type(module_data, rexme):
	#m_process = ''
	m_header = []
	m,m_type = None,None
	global LFR2_AUTO_TYPE,LFR2_TYPE_EXTS,LFR2_SKIP_EXTS
	os_path_isdir = os.path.isdir
	for m_data in module_data:
		if not m_data:
			continue
		#if m_data[0]=="@":
		#	m_process = m_data[1:]
		#m=re.findall(r'^([0-9]+)\|([^\|\\\:\*\?\"\<\>]+)\|([^\|\\\:\*\?\"\<\>]+)$', m_data)
		m=re_findall(rexme, m_data)
		for m_type,v_path,r_path in m:
			if (not m_type) or (not v_path) or (not r_path):
				continue
			#print m_type,v_path,r_path
			m_type2 = int(m_type)
			if 1:#not m_type2 in (0,1,2):
				if LFR2_AUTO_TYPE:
					v_path_endswith = v_path.endswith
					try:
						for lte_i,lte_t in LFR2_TYPE_EXTS.iteritems():
							try:
								for lte_el in lte_t:
									if v_path_endswith(lte_el):
										m_type2 = lte_i
										raise GoOut3rdLevelLoop
							except GoOut3rdLevelLoop:
								break
							for lse_el in LFR2_SKIP_EXTS:
								if v_path_endswith(lse_el):
									print v_path, "skipped (illegal extension %s)"%lse_el
									raise GoOut2ndLevelLoop
							if os_path_isdir(r_path):
								print v_path, "skipped (path %s)"%r_path
								raise GoOut2ndLevelLoop
					except GoOut2ndLevelLoop:
						continue
			m_header.append({'type':m_type2,'v_path':v_path,'r_path':r_path})
	return m_header
def lfr2_loader(modulename, pin):
	def pma_analyze(m_header):
		os_path_exists = os.path.exists
		for m_data in m_header:
			if not os_path_exists(m_data['r_path']):
				raise PMACompactError, "%s file not exists"%m_data['r_path']
	import re
	re_findall = re.findall

	module_dataX = open(modulename+".lfr", "r")
	module_data = module_dataX.read().split("\n")
	module_dataX.close(); del module_dataX

	#pma_analyze(m_header)#, m_process)
	pma_analyze(deduct_type(module_data, r'^\ttype\:([0-9]+)\|intPath\:([^\|]+)\|extPath\:([^\|]+)$'))

	return modulename, pin, m_header

def eix_maker(modulename, pin, m_header):
	pack, unpack = struct.pack, struct.unpack
	def nullpadder(str, msize=25):
		np_len = len(str)
		if not np_len:
			return '\0'*msize
		npp_len = np_len % msize
		if not npp_len:
			return str
		elif npp_len>msize:
			return str[:msize]
		else:
			return str+((msize-npp_len)*'\0')
	def nullpadding(mlen, msize=8):
		retlen = ''
		mpad = mlen%msize
		if mpad:
			retlen = (msize-mpad)*chr(0)
		return retlen
	import zlib
	crc32 = zlib.crc32
	lzo_compress, xtea_encrypt_all = lzo.compress, _xtea.encrypt_all
	eix_out = open(modulename+pin[0], "wb")#MT2_MAGIC1
	epk_out = open(modulename+pin[1], "wb")

	#eix_out.write('\0'*12)
	"""EIX-NODE HEADER
		t_id = unpack("I",	eix_sio.read(4))[0]						#0
		t_filename =		eix_sio.read(161+3).replace("\0", "")	#4
		t_filename_crc =	eix_sio.read(4).encode('hex')			#168
		t_real_data_size =	unpack("I", eix_sio.read(4))[0]			#172
		t_data_size =		unpack("I", eix_sio.read(4))[0]			#176
		t_data_crc =		eix_sio.read(4).encode('hex')			#180
		t_data_position =	unpack("I", eix_sio.read(4))[0]			#184
		t_compressed_type =	unpack("4B", eix_sio.read(1),0,0,0)[0]	#188
	"""
	global LZO_COMPRESSION_LEVEL,MT2_MAGIC1,MT2_XTEAKEY_DATA
	loff = 0
	add_off = 0
	m_len = len(m_header)

	idx,tmp_fileX,tmp_file,tmp_sfile,tmp_crcfile=None,None,None,None,None
	tmp_file1,tmp_dsize1,tmp_fileb1,tmp_csize1=None,None,None,None
	tmp_file2,tmp_esize2=None,None

	eix_out_write = eix_out.write
	epk_out_write = epk_out.write
	for lidx in xrange(m_len):
		idx = m_header[lidx]
		#print idx
		eix_out_write(pack("I", lidx))#id 0
		eix_out_write(nullpadder(idx['v_path'], 161+3))#filename 4
		eix_out_write(pack("I", crc32(idx['v_path'])&0xFFFFFFFF))#filename_crc 168

		tmp_fileX = open(idx['r_path'], "rb")
		tmp_file = tmp_fileX.read()
		tmp_fileX.close()

		tmp_sfile = len(tmp_file)
		tmp_crcfile = crc32(tmp_file)&0xFFFFFFFF
		if idx['type']==0 or idx['type']==10 or idx['type']==20:
			tmp_rsfile = tmp_sfile + (256 - (tmp_sfile % 256))
			epk_out_write(tmp_file)#+nullpadding(tmp_rsfile-tmp_sfile))

			eix_out_write(pack("I", tmp_rsfile)) #real_data_size #172
			eix_out_write(pack("I", tmp_sfile)) #data_size size compressed file+header #176
			eix_out_write(pack("I", tmp_crcfile)) #data_crc #180

			add_off = tmp_sfile#tmp_rsfile#tmp_sfile
		elif idx['type']==1 or idx['type']==11 or idx['type']==21:
			tmp_file1 = lzo_compress(tmp_file, LZO_COMPRESSION_LEVEL)
			tmp_dsize1 = unpack("!L", tmp_file1[1:5])
			tmp_fileb1 = tmp_file1[5:]
			tmp_csize1 = len(tmp_fileb1)
			tmp_rsfile = (tmp_csize1+20) + (256 - ((tmp_csize1+20) % 256))

			epk_out_write(MT2_MAGIC1+pack("I", 0)+pack("I", tmp_csize1)+pack("I", tmp_sfile)+MT2_MAGIC1)
			epk_out_write(tmp_fileb1)#+nullpadding(tmp_rsfile-tmp_csize1-20))

			eix_out_write(pack("I", tmp_rsfile)) #real_data_size #172
			eix_out_write(pack("I", tmp_csize1+4+16)) #data_size size compressed file+header #176
			eix_out_write(pack("I", crc32(tmp_file1)&0xFFFFFFFF)) #data_crc #180

			add_off = tmp_csize1+20#tmp_rsfile#tmp_csize1+20
		elif idx['type']==2 or idx['type']==12 or idx['type']==22:
			tmp_file1 = lzo_compress(tmp_file, LZO_COMPRESSION_LEVEL)
			tmp_dsize1 = unpack("!L", tmp_file1[1:5])
			tmp_fileb1 = tmp_file1[5:]
			tmp_csize1 = len(tmp_fileb1)

			tmp_file2 = xtea_encrypt_all(MT2_MAGIC1+tmp_fileb1+nullpadding(tmp_csize1+4), MT2_XTEAKEY_DATA)
			tmp_esize2 = len(tmp_file2)
			tmp_rsfile = (tmp_esize2+16) + (256 - ((tmp_esize2+16) % 256))
			#print tmp_esize2, tmp_esize2%8
			#magic+esize+csize+dsize
			tmp_hdr = MT2_MAGIC1+pack("I", tmp_esize2)+pack("I", tmp_csize1)+pack("I", tmp_sfile)
			epk_out_write(tmp_hdr)
			epk_out_write(tmp_file2)#+nullpadding(tmp_rsfile-tmp_esize2-16))

			eix_out_write(pack("I", tmp_rsfile))#real_data_size #172
			eix_out_write(pack("I", tmp_esize2+16))#tmp_esize2)) #data_size size compressed file+header #176
			eix_out_write(pack("I", crc32(tmp_hdr+tmp_file2)&0xFFFFFFFF))#tmp_file2))) #data_crc #180
			#xxx=open(idx['r_path']+"xxx", "wb");xxx.write(tmp_hdr+tmp_file2);xxx.close()

			add_off = tmp_esize2+16#tmp_rsfile#tmp_esize2+16
		else:
			raise PMACompactError, "Unrecognized type %d"%idx['type']

		eix_out_write(pack("I", loff)) #data_position 184
		loff+=add_off
		eix_out_write(pack("I", long(idx['type']))) #compressed_type #188
	###@ GC CLEAN BEGIN
	add_off = 0
	idx,tmp_fileX,tmp_file,tmp_sfile,tmp_crcfile=None,None,None,None,None
	tmp_file1,tmp_dsize1,tmp_fileb1,tmp_csize1=None,None,None,None
	tmp_file2,tmp_esize2=None,None
	###@ GC CLEAN END
	eix_out.close(); del eix_out
	epk_out.close(); del epk_out
	return 2, m_len
def eix_save(modulename, pin, pout, m_version, m_len):
	def nullpadding(mlen, msize=8):
		retlen = ''
		mpad = mlen%msize
		if mpad:
			retlen = (msize-mpad)*chr(0)
		return retlen
	pack, unpack = struct.pack, struct.unpack
	lzo_compress, xtea_encrypt_all = lzo.compress, _xtea.encrypt_all

	global EIX_COMPRESSION,MT2_MAGIC1,MT2_MAGIC2,MT2_XTEAKEY_INDEX,EIX_EXTS,EPK_EXTS
	eix_raw = open(modulename+pin[0], "rb")
	eix_new = open(modulename+pout+EIX_EXTS, "wb")
	if EIX_COMPRESSION==1:
		s_magic1 = MT2_MAGIC1
		eix_new0 = MT2_MAGIC2+pack("I", m_version)+pack("I", m_len)+eix_raw.read()
		eix_new1 = lzo_compress(eix_new0)
		eix_new1_dl = unpack("!L", eix_new1[1:5])[0]
		eix_new1_f = eix_new1[5:]
		eix_new1_cl = len(eix_new1_f)

		eix_new2 = xtea_encrypt_all(s_magic1+eix_new1_f+nullpadding(eix_new1_cl+4), MT2_XTEAKEY_INDEX)
		eix_new2_el = len(eix_new2)

		eix_new.write(s_magic1+pack("I", eix_new2_el)+pack("I", eix_new1_cl)+pack("I", eix_new1_dl))
		eix_new.write(eix_new2)

		eix_new0,eix_new1,eix_new1_dl,eix_new1_f,eix_new1_cl,eix_new2,eix_new2_el=None,None,None,None,None,None,None
	elif EIX_COMPRESSION==0:
		eix_new.write(MT2_MAGIC2+pack("I", m_version)+pack("I", m_len))
		eix_new.write(eix_raw.read())
	else:
		raise PMACompactError, "%s eix compression not exists"%EIX_COMPRESSION
	eix_raw.close(); del eix_raw
	eix_new.close(); del eix_new

	try: os.remove(modulename+pout+EPK_EXTS)
	except: pass#print sys.exc_info()[:2],0,modulename+pout+EPK_EXTS
	try: os.remove(modulename+pin[0])
	except: print sys.exc_info()[1],1
	try: os.rename(modulename+pin[1], modulename+pout+EPK_EXTS)
	except: print sys.exc_info()[1],2
#

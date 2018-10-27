# Copyright (c) 2013, martysama0134
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# Neither the name of martysama0134 nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
### CLASSES
import os
import time

GetPath = os.getcwd
SetPath = os.chdir

from m2a_utils__PM import \
	eix_load, eix_analyze, epk_load, eix_save, eix_maker,\
	pma_generate, pma_maker, pma_loader, xml_maker, lfr2_loader,\
	EXT_DEBUG_MODE
class PackManager(object):
	'''Metin2 Pack Archiver Module
	Extract:
		>>> import m2a
		>>> pa=m2a.PackManager("root")
		>>> pa.Extract()
		>>> pa.Extract_PMAONLY()
		>>> pa.Extract_PMAONLY_ALL()
		>>> pa.Extract_XMLONLY()
		>>> pa.Extract_XMLONLY_ALL()
	Compact:
		>>> import m2a
		>>> pa=m2a.PackManager("root")
		>>> pa.Compact()
		>>> pa.Compact_ALL()
	'''
	def __init__(self, module="root", pout=".pdone"):
		self.module = module
		self.pin = (".eixraw", ".epkraw")
		self.pout = pout
	def Extract(self):
		t_start = time.time()
		global eix_load, eix_analyze, pma_maker, epk_load

		e = eix_load(self.module);#open(self.module+".eix._unlzo", "wb").write(e[12:])
		global EXT_DEBUG_MODE
		if EXT_DEBUG_MODE:
			ttt=open(self.module+".eix._unlzo", "wb"); ttt.write(e); ttt.close()
		f = eix_analyze(e)
		pma_maker(self.module, f)
		epk_load(self.module, f)

		print time.time()-t_start
	def Extract_ALL(self, path="."):
		t_start = time.time()

		cmp_file = os.listdir(path)
		for cmp_f in cmp_file:
			if cmp_f.endswith(".eix"):
				self.module = ".".join(cmp_f.split(".")[:-1]).lower()
				print "Processing... %s"%self.module
				self.Extract()

		print time.time()-t_start
	def Extract_PMAONLY(self):
		t_start = time.time()
		global eix_load, eix_analyze, pma_maker

		e = eix_load(self.module);
		f = eix_analyze(e)
		pma_maker(self.module, f)

		print time.time()-t_start
	def Extract_PMAONLY_ALL(self, path="."):
		t_start = time.time()

		cmp_file = os.listdir(path)
		for cmp_f in cmp_file:
			if cmp_f.endswith(".eix"):
				self.module = ".".join(cmp_f.split(".")[:-1]).lower()
				print "Processing... %s"%self.module
				self.Extract_PMAONLY()

		print time.time()-t_start
	def Extract_XMLONLY(self):
		t_start = time.time()
		global eix_load, eix_analyze, xml_maker

		e = eix_load(self.module);
		f = eix_analyze(e)
		xml_maker(self.module, f)

		print time.time()-t_start
	def Extract_XMLONLY_ALL(self, path="."):
		t_start = time.time()

		cmp_file = os.listdir(path)
		for cmp_f in cmp_file:
			if cmp_f.endswith(".eix"):
				self.module = ".".join(cmp_f.split(".")[:-1]).lower()
				print "Processing... %s"%self.module
				self.Extract_XMLONLY()

		print time.time()-t_start
	def Compact(self):
		t_start = time.time()
		global pma_loader, eix_maker, eix_save

		a = eix_maker(*pma_loader(self.module, self.pin))
		eix_save(self.module, self.pin, self.pout, *a)

		print time.time()-t_start
	def Compact_ALL(self, path="."):
		t_start = time.time()

		cmp_file = os.listdir(path)
		for cmp_f in cmp_file:
			if cmp_f.endswith(".pma"):
				self.module = ".".join(cmp_f.split(".")[:-1]).lower()
				print "Processing... %s"%self.module
				self.Compact()

		print time.time()-t_start
	def CompactLFR2(self):
		t_start = time.time()
		global lfr2_loader, eix_maker, eix_save

		a = eix_maker(*lfr2_loader(self.module, self.pin))
		eix_save(self.module, self.pin, self.pout, *a)

		print time.time()-t_start
	def CompactLFR2_ALL(self, path="."):
		t_start = time.time()

		cmp_file = os.listdir(path)
		for cmp_f in cmp_file:
			if cmp_f.endswith(".lfr"):
				self.module = ".".join(cmp_f.split(".")[:-1]).lower()
				print "Processing... %s"%self.module
				self.CompactLFR2()

		print time.time()-t_start
	def Generate_PMAONLY(self):
		t_start = time.time()
		pma_generate(self.module)
		print time.time()-t_start

from m2a_utils__IPM import iproto_load, ima_maker, ima_loader, iproto_save
class IProtoManager(object):
	'''Metin2 ItemProto Archiver Module
	Extract:
		>>> import m2a
		>>> pa=m2a.IProtoManager("item_proto")
		>>> pa.Extract()
	Compact:
		>>> import m2a
		>>> pa=m2a.IProtoManager("item_proto")
		>>> pa.Compact()
	'''
	def __init__(self, iproto="item_proto", ipout=".done"):
		self.iproto = iproto
		self.ipin = ".ima.ipraw"
		self.ipout = ipout
	def Extract(self):
		t_start = time.time()

		global iproto_load, ima_maker
		a = iproto_load(self.iproto)
		ima_maker(self.iproto, *a)

		print time.time()-t_start
	def Compact(self):
		t_start = time.time()

		global ima_loader, iproto_save
		a = ima_loader(self.iproto)
		iproto_save(self.iproto+self.ipin, self.iproto+self.ipout, *a)

		print time.time()-t_start
	def ConvertIMA2SQL(mode=0):
		t_start = time.time()

		pass
		print time.time()-t_start


from m2a_utils__MPM import mproto_load, mma_maker, mma_loader, mproto_save
class MProtoManager(object):
	'''Metin2 MobProto Archiver Module
	Extract:
		>>> import m2a
		>>> pa=m2a.MProtoManager("mob_proto")
		>>> pa.Extract()
	Compact:
		>>> import m2a
		>>> pa=m2a.MProtoManager("mob_proto")
		>>> pa.Compact()
	'''
	def __init__(self, mproto="mob_proto", mpout=".done"):
		self.mproto = mproto
		self.mpin = ".mma.mpraw"
		self.mpout = mpout
	def Extract(self):
		t_start = time.time()

		global mproto_load, mma_maker
		a = mproto_load(self.mproto)
		mma_maker(self.mproto, *a)

		print time.time()-t_start
	def Compact(self):
		t_start = time.time()

		global mma_loader, mproto_save
		a = mma_loader(self.mproto)
		mproto_save(self.mproto+self.mpin, self.mproto+self.mpout, a)

		print time.time()-t_start
	def ConvertMMA2SQL(mode=0):
		t_start = time.time()

		pass
		print time.time()-t_start

from m2a_utils__AM import laddr_load, laddr_save
class AddrManager(object): #addr_archiver.py ctrl+c -> ctrl+v here
	'''Metin2 locale_%s.addr Archiver Module
	Extract:
		>>> import m2a
		>>> pa=m2a.AddrManager("locale_pa")
		>>> pa.Extract()
	Compact:
		>>> import m2a
		>>> pa=m2a.AddrManager("locale_pa")
		>>> pa.Compact()
	'''
	def __init__(self, laddr="locale_it"):
		self.laddr = laddr
	def Extract(self):
		t_start = time.time()

		global laddr_load
		daddr = laddr_load(self.laddr)

		daddrX = open(self.laddr+".txt", "wb")
		daddrX.write(str(daddr))
		daddrX.close()

		print time.time()-t_start
	def Compact(self):
		t_start = time.time()

		daddrX = open(self.laddr+".txt", "r")
		daddr = eval(daddrX.read())
		daddrX.close(); del daddrX

		global laddr_save
		laddr_save(daddr, self.laddr)

		print time.time()-t_start









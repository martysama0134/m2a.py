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
#nstd
import _xtea
#pkg
from m2a import MT2_XTEAKEY_ADDR

### LOCALE_%S.ADDR
def laddr_load(laddr):
	def nullpadding(mlen, msize=8):
		retlen = ''
		mpad = mlen%msize
		if mpad:
			retlen = (msize-mpad)*chr(0)
		return retlen

	global MT2_XTEAKEY_ADDR
	addr_dataX = open(laddr+".addr", "rb")
	addr_data = addr_dataX.read()
	addr_dataX.close(); del addr_dataX

	addr_dec = _xtea.decrypt_all(addr_data+nullpadding(len(addr_data)), MT2_XTEAKEY_ADDR)

	import cPickle
	return cPickle.loads(addr_dec[4:])
def laddr_save(daddr, laddr):
	def nullpadding(mlen, msize=8):
		retlen = ''
		mpad = mlen%msize
		if mpad:
			retlen = (msize-mpad)*chr(0)
		return retlen

	import cPickle
	info = cPickle.dumps(daddr)

	addr_res = _xtea.encrypt_all(struct.pack("I", len(info))+info+nullpadding(len(info))+chr(0)*4, MT2_XTEAKEY_ADDR)
	addr_out = open(laddr+".addr", "wb")
	addr_out.write(addr_res)
	addr_out.close()

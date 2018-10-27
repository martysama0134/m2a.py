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
from m2a import *

if __name__ == "__main__":
	def Usage():
		print '''Usage:
### PYTHON METIN2 ARCHIVER COMMAND-LINE USAGE
	(item_proto)
	# python m2a_g.py --ip -u item_proto
	0.871999979019

	# python m2a_g.py --ip -p item_proto
	0.858000040054

	# python m2a_g.py --ip -u locale_it\locale\it\item_proto
	0.873000144958

	# python m2a_g.py --ip -p locale_it\locale\it\item_proto
	0.851000070572

	(mob_proto)
	# python m2a_g.py --mp -u locale_it\locale\it\mob_proto
	0.873000144958

	# python m2a_g.py --mp -p locale_it\locale\it\mob_proto
	0.851000070572

	(.eix||.epk)
	# python m2a_g.py --pm -p root
	0.0859999656677

	# python m2a_g.py --pm -u root
	0.0859999656677

	# python m2a_g.py --pm -g root
	0.0859999656677

	(locale_it.addr)
	# python m2a_g.py --am -u locale_it
	0.00500011444092

	# python m2a_g.py --am -p locale_it
	0.0090000629425

	# python m2a_g.py --xmlonly -u locale_it
	0.0090000629425

'''
	import getopt
	import sys
	try:
		optlist, args = getopt.getopt(sys.argv[1:],"p:u:",('pm','ip','mp','am','pack=','unpack=','pmaonly','xmlonly'))

		#t_file, t_fname = None, ""
		#t_key = None
		#t_mode = 0
		proc_file = ""
		proc_mode = 0
		proc_type = 0
		proc_subtype = 0
		for o, a in optlist:
			if o in ('-p', '--pack'):
				proc_file = a
				proc_mode = 1
			elif o in ('-u', '--unpack'):
				proc_file = a
				proc_mode = 2
			elif o in ('--pmaonly',):
				proc_subtype = 1
			elif o in ('--xmlonly',):
				proc_subtype = 2
			elif o in ('--pm',):
				proc_type = 1
			elif o in ('--ip',):
				proc_type = 2
			elif o in ('--mp',):
				proc_type = 3
			elif o in ('--am',):
				proc_type = 4
		if (not proc_file) or (not proc_mode) or (not proc_type):
			sys.exit(Usage())

		#pack
		if proc_type==1:
			pa = PackManager(proc_file, "")
			if proc_mode==1:
				if proc_subtype==1:
					pa.Generate_PMAONLY()
				elif proc_subtype==2:
					pa.Generate_XMLONLY()
				else:
					pa.Compact()
			elif proc_mode==2:
				if proc_subtype==1:
					pa.Extract_PMAONLY()
				elif proc_subtype==2:
					pa.Extract_XMLONLY()
				else:
					pa.Extract()
		#item_proto
		elif proc_type==2:
			pa = IProtoManager(proc_file, "")
			if proc_mode==1:
				pa.Compact()
			elif proc_mode==2:
				pa.Extract()
		#mob_proto
		elif proc_type==3:
			pa = MProtoManager(proc_file, "")
			if proc_mode==1:
				pa.Compact()
			elif proc_mode==2:
				pa.Extract()
		#locale_%s.addr
		elif proc_type==4:
			pa = AddrManager(proc_file)
			if proc_mode==1:
				pa.Compact()
			elif proc_mode==2:
				pa.Extract()
	except getopt.GetoptError, err:
		sys.exit(err)

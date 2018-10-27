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
from m2a import MPROTO_STRUCT_TYPE, MT2_MAGIC1, MT2_MAGIC4, MT2_XTEAKEY_MPX, LZO_COMPRESSION_LEVEL, EXT_DEBUG_MODE

### MOB_PROTO
def mproto_load(mproto):
	pack, unpack = struct.pack, struct.unpack
	mp_f1 = open(mproto, "rb")
	mph = {}
	mph['magic'] = mp_f1.read(4)
	mph['count'] = unpack("I", mp_f1.read(4))[0]
	mph['esize'] = unpack("I", mp_f1.read(4))[0]

	import cStringIO
	mp_data1 = cStringIO.StringIO(mp_f1.read(mph['esize']))
	mp_f1.close()

	mpph = {}
	mpph['magic'] = unpack("I", mp_data1.read(4))[0]
	mpph['esize'] = unpack("I", mp_data1.read(4))[0]
	mpph['csize'] = unpack("I", mp_data1.read(4))[0]
	mpph['dsize'] = unpack("I", mp_data1.read(4))[0]

	global MT2_XTEAKEY_MPX
	mp_data2 = _xtea.decrypt_all(mp_data1.read(mpph['esize']), MT2_XTEAKEY_MPX)
	if EXT_DEBUG_MODE:
		ttt=open(mproto+".unxtea", "wb");ttt.write(mp_data2);ttt.close()

	mp_data3 = lzo.decompress("\xf0"+pack("!L", mpph['dsize'])+mp_data2[4:mpph['csize']+4])
	if EXT_DEBUG_MODE:
		ttt=open(mproto+".unlzo", "wb");ttt.write(mp_data3);ttt.close()
	return mph, mp_data3
def mma_maker(mproto, mph, mp_data):
	pack, unpack = struct.pack, struct.unpack

	import cStringIO
	cSIO_SIO = cStringIO.StringIO

	mpm_io = cSIO_SIO(mp_data)
	mpm_io_read = mpm_io.read

	mp_file = open(mproto+".mma", "w")
	mp_file.write("#count: %d\n#author: %s\n#datetime: %s\n"%(mph['count'], "martysama0134`s PythonMetin2Archiver", strftime("%d/%m/%Y %H:%M:%S")))

	MOB_SKILL_MAX_NUM = 0
	global MPROTO_STRUCT_TYPE
	if MPROTO_STRUCT_TYPE==1:
		MOB_SKILL_MAX_NUM = 1
		mpm_ml1,mpm_ml2=235,5
	elif MPROTO_STRUCT_TYPE==2:
		MOB_SKILL_MAX_NUM = 5
		mpm_ml1,mpm_ml2=255,25
	elif MPROTO_STRUCT_TYPE==3:
		MOB_SKILL_MAX_NUM = 5
		mpm_ml1,mpm_ml2=256,26
	elif MPROTO_STRUCT_TYPE==4:
		MOB_SKILL_MAX_NUM = 5
		mpm_ml1,mpm_ml2=262,32
	elif MPROTO_STRUCT_TYPE==5:
		MOB_SKILL_MAX_NUM = 5
		mpm_ml1,mpm_ml2=263,26
	elif MPROTO_STRUCT_TYPE==6:
		MOB_SKILL_MAX_NUM = 5
		mpm_ml1,mpm_ml2=275,26
	for idx in xrange(mph['count']):
		mpm_rsc = cSIO_SIO(mpm_io_read(mpm_ml1))
		mpm_rsc_read = mpm_rsc.read
		mobData = ""
		mobData += "vnum=%d|" % (unpack("I", mpm_rsc_read(4))[0])#vnum
		mobData += "name=%s|" % (mpm_rsc_read(25).replace('\0', ''))#name
		mobData += "locale_name=%s|" % (mpm_rsc_read(25).replace('\0', ''))#locale_name
		mobData += "type=%d|" % (unpack("B", mpm_rsc_read(1))[0])#type
		mobData += "rank=%d|" % (unpack("B", mpm_rsc_read(1))[0])#rank
		mobData += "battle_type=%d|" % (unpack("B", mpm_rsc_read(1))[0])#battle_type
		mobData += "level=%d|" % (unpack("B", mpm_rsc_read(1))[0])#level
		if MPROTO_STRUCT_TYPE in (4,5,6):
			mobData += "lvl_pct=%d|" % (unpack("B", mpm_rsc_read(1))[0])#unk1 (always 100)
		mobData += "size=%d|" % (unpack("B", mpm_rsc_read(1))[0])#size
		mobData += "gold_min=%d|" % (unpack("I", mpm_rsc_read(4))[0])#gold_min
		mobData += "gold_max=%d|" % (unpack("I", mpm_rsc_read(4))[0])#gold_max
		mobData += "exp=%d|" % (unpack("I", mpm_rsc_read(4))[0])#exp
		mobData += "max_hp=%d|" % (unpack("I", mpm_rsc_read(4))[0])#max_hp
		mobData += "regen_cicle=%d|" % (unpack("B", mpm_rsc_read(1))[0])#regen_cicle
		mobData += "regen_percent=%d|" % (unpack("B", mpm_rsc_read(1))[0])#regen_percent
		mobData += "def=%d|" % (unpack("H", mpm_rsc_read(2))[0])#def
		mobData += "ai_flag=%d|" % (unpack("I", mpm_rsc_read(4))[0])#ai_flag
		mobData += "race_flag=%d|" % (unpack("I", mpm_rsc_read(4))[0])#race_flag
		mobData += "immune_flag=%d|" % (unpack("I", mpm_rsc_read(4))[0])#immune_flag
		mobData += "st=%d|" % (unpack("B", mpm_rsc_read(1))[0])#st
		mobData += "dx=%d|" % (unpack("B", mpm_rsc_read(1))[0])#dx
		mobData += "ht=%d|" % (unpack("B", mpm_rsc_read(1))[0])#ht
		mobData += "iq=%d|" % (unpack("B", mpm_rsc_read(1))[0])#iq
		mobData += "damage_min=%d|" % (unpack("I", mpm_rsc_read(4))[0])#damage_min
		mobData += "damage_max=%d|" % (unpack("I", mpm_rsc_read(4))[0])#damage_max
		mobData += "attack_speed=%d|" % (unpack("h", mpm_rsc_read(2))[0])#attack_speed
		mobData += "move_speed=%d|" % (unpack("h", mpm_rsc_read(2))[0])#move_speed
		mobData += "aggressive_hp_pct=%d|" % (unpack("B", mpm_rsc_read(1))[0])#aggressive_hp_pct
		mobData += "aggressive_sight=%d|" % (unpack("H", mpm_rsc_read(2))[0])#aggressive_sight
		mobData += "attack_range=%d|" % (unpack("H", mpm_rsc_read(2))[0])#attack_range
		mobData += "enchant_curse=%d|" % (unpack("b", mpm_rsc_read(1))[0])#enchant_curse
		mobData += "enchant_slow=%d|" % (unpack("b", mpm_rsc_read(1))[0])#enchant_slow
		mobData += "enchant_poison=%d|" % (unpack("b", mpm_rsc_read(1))[0])#enchant_poison
		mobData += "enchant_stun=%d|" % (unpack("b", mpm_rsc_read(1))[0])#enchant_stun
		mobData += "enchant_critical=%d|" % (unpack("b", mpm_rsc_read(1))[0])#enchant_critical
		mobData += "enchant_penetrate=%d|" % (unpack("b", mpm_rsc_read(1))[0])#enchant_penetrate
		mobData += "resist_sword=%d|" % (unpack("b", mpm_rsc_read(1))[0])#resist_sword
		mobData += "resist_twohand=%d|" % (unpack("b", mpm_rsc_read(1))[0])#resist_twohand
		mobData += "resist_dagger=%d|" % (unpack("b", mpm_rsc_read(1))[0])#resist_dagger
		mobData += "resist_bell=%d|" % (unpack("b", mpm_rsc_read(1))[0])#resist_bell
		mobData += "resist_fan=%d|" % (unpack("b", mpm_rsc_read(1))[0])#resist_fan
		mobData += "resist_bow=%d|" % (unpack("b", mpm_rsc_read(1))[0])#resist_bow
		if MPROTO_STRUCT_TYPE in (4,5,6):
			mobData += "resist_claw=%d|" % (unpack("b", mpm_rsc_read(1))[0])#resist_claw
		mobData += "resist_fire=%d|" % (unpack("b", mpm_rsc_read(1))[0])#resist_fire
		mobData += "resist_elect=%d|" % (unpack("b", mpm_rsc_read(1))[0])#resist_elect
		mobData += "resist_magic=%d|" % (unpack("b", mpm_rsc_read(1))[0])#resist_magic
		mobData += "resist_wind=%d|" % (unpack("b", mpm_rsc_read(1))[0])#resist_wind
		mobData += "resist_poison=%d|" % (unpack("b", mpm_rsc_read(1))[0])#resist_poison
		if MPROTO_STRUCT_TYPE in (3,4,5,6):
			mobData += "resist_bleeding=%d|" % (unpack("b", mpm_rsc_read(1))[0])#resist_bleeding
		if MPROTO_STRUCT_TYPE==6:
			mobData += "unk2=%s|" % (unpack("B"*9, mpm_rsc_read(9))[0])#unk2
		mobData += "summon=%d|" % (unpack("I", mpm_rsc_read(4))[0])#summon (always 0)
		mobData += "drop_item=%d|" % (unpack("I", mpm_rsc_read(4))[0])#drop_item
		mobData += "mount_capacity=%d|" % (unpack("B", mpm_rsc_read(1))[0])#mount_capacity (always 0)
		mobData += "on_click=%d|" % (unpack("H", mpm_rsc_read(2))[0])#on_click
		mobData += "folder=%s|" % (mpm_rsc_read(65).replace('\0', ''))#folder
		mobData += "dam_multiply=%.2f|" % (unpack("f", mpm_rsc_read(4))[0])#dam_multiply
		mobData += "summon=%d|" % (unpack("I", mpm_rsc_read(4))[0])#summon
		mobData += "drain_sp=%d|" % (unpack("I", mpm_rsc_read(4))[0])#drain_sp
		mobData += "mob_color=%d|" % (unpack("I", mpm_rsc_read(4))[0])#mob_color
		mobData += "polymorph_item=%d|" % (unpack("I", mpm_rsc_read(4))[0])#polymorph_item
		for lvl in xrange(MOB_SKILL_MAX_NUM):
			mobData += "skill_vnum%d=%d|" % (lvl, unpack("I", mpm_rsc_read(4))[0])
			mobData += "skill_level%d=%d|" % (lvl, unpack("B", mpm_rsc_read(1))[0])
		mobData += "sp_berserk=%d|" % (unpack("B", mpm_rsc_read(1))[0])#sp_berserk (always 0)
		mobData += "sp_stoneskin=%d|" % (unpack("B", mpm_rsc_read(1))[0])#sp_stoneskin (always 0)
		mobData += "sp_godspeed=%d|" % (unpack("B", mpm_rsc_read(1))[0])#sp_godspeed (always 0)
		mobData += "sp_deathblow=%d|" % (unpack("B", mpm_rsc_read(1))[0])#sp_deathblow (always 0)
		mobData += "sp_revive=%d" % (unpack("B", mpm_rsc_read(1))[0])#sp_revive (always 0)
		if MPROTO_STRUCT_TYPE in (5,6):
			mobData += "|unk4=%s" % (unpack("I", mpm_rsc_read(4))[0]) # (always 0)
			mobData += "|unk4=%s" % (unpack("B", mpm_rsc_read(1))[0]) # (always 0)
		if MPROTO_STRUCT_TYPE==6:
			mobData += "unk3=%s|" % (unpack("B"*3, mpm_rsc_read(3))[0])#unk3
		mp_file.write("%s\n" % mobData)
	mp_file.close()
def mma_loader(mproto):
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

	mp_imaX = open(mproto+".mma", "r")
	mp_ima = mp_imaX.read().split("\n")
	mp_imaX.close(); del mp_imaX

	pat = r'^vnum=(\d+)\|name=([^\|]+)\|locale_name=([^\|]+)\|type=(\d+)\|rank=(\d+)\|battle_type=(\d+)\|level=(\d+)\|size=(\d+)\|gold_min=(\d+)\|gold_max=(\d+)\|exp=(\d+)\|max_hp=(\d+)\|regen_cicle=(\d+)\|regen_percent=(\d+)\|def=(\d+)\|ai_flag=(\d+)\|race_flag=(\d+)\|immune_flag=(\d+)\|st=(\d+)\|dx=(\d+)\|ht=(\d+)\|iq=(\d+)\|damage_min=(\d+)\|damage_max=(\d+)\|attack_speed=(\-{0,1}\d+)\|move_speed=(\-{0,1}\d+)\|aggressive_hp_pct=(\d+)\|aggressive_sight=(\d+)\|attack_range=(\d+)\|enchant_curse=(\-{0,1}\d+)\|enchant_slow=(\-{0,1}\d+)\|enchant_poison=(\-{0,1}\d+)\|enchant_stun=(\-{0,1}\d+)\|enchant_critical=(\-{0,1}\d+)\|enchant_penetrate=(\-{0,1}\d+)\|resist_sword=(\-{0,1}\d+)\|resist_twohand=(\-{0,1}\d+)\|resist_dagger=(\-{0,1}\d+)\|resist_bell=(\-{0,1}\d+)\|resist_fan=(\-{0,1}\d+)\|resist_bow=(\-{0,1}\d+)\|resist_fire=(\-{0,1}\d+)\|resist_elect=(\-{0,1}\d+)\|resist_magic=(\-{0,1}\d+)\|resist_wind=(\-{0,1}\d+)\|resist_poison=(\-{0,1}\d+)\|summon=(\d+)\|drop_item=(\d+)\|mount_capacity=(\d+)\|on_click=(\d+)\|folder=([^\|]*)\|dam_multiply=([^\|]+)\|summon=(\d+)\|drain_sp=(\d+)\|mob_color=(\d+)\|polymorph_item=(\d+)\|unk4=([^\|]+)\|sp_berserk=(\d+)\|sp_stoneskin=(\d+)\|sp_godspeed=(\d+)\|sp_deathblow=(\d+)\|sp_revive=(\d+)$'

	mp_out = open(mproto+".mma.mpraw", "wb")
	mp_out_write = mp_out.write

	m_count = 0
	global MPROTO_STRUCT_TYPE
	if MPROTO_STRUCT_TYPE==1:
		mp_ml1=5
	elif MPROTO_STRUCT_TYPE==2:
		mp_ml1=25
	elif MPROTO_STRUCT_TYPE==3:
		mp_ml1=26
	elif MPROTO_STRUCT_TYPE==4:
		mp_ml1=32
	for mima in mp_ima:
		if not mima or mima[0]=='#':
			continue
		m = re_findall(pat, mima)[0]
		if not len(m)==62:
			continue
		mp_out_write(pack("I", long(m[0])))#vnum
		mp_out_write(nullpadder(m[1]))#name
		mp_out_write(nullpadder(m[2]))#locale_name
		mp_out_write(pack("B", long(m[3])))#type
		mp_out_write(pack("B", long(m[4])))#rank
		mp_out_write(pack("B", long(m[5])))#battle_type
		mp_out_write(pack("B", long(m[6])))#level
		mp_out_write(pack("B", long(m[7])))#size
		#mp_out_write(nullpadder(m[8].decode('hex'), 8))#unk1 (always 0)
		mp_out_write(pack("I", long(m[8])))#gold_min
		mp_out_write(pack("I", long(m[9])))#gold_max
		mp_out_write(pack("I", long(m[10])))#exp
		mp_out_write(pack("I", long(m[11])))#max_hp
		mp_out_write(pack("B", long(m[12])))#regen_cicle
		mp_out_write(pack("B", long(m[13])))#regen_percent
		mp_out_write(pack("H", long(m[14])))#def
		mp_out_write(pack("I", long(m[15])))#ai_flag
		mp_out_write(pack("I", long(m[16])))#race_flag
		mp_out_write(pack("I", long(m[17])))#immune_flag
		mp_out_write(pack("B", long(m[18])))#st
		mp_out_write(pack("B", long(m[19])))#dx
		mp_out_write(pack("B", long(m[20])))#ht
		mp_out_write(pack("B", long(m[21])))#iq
		mp_out_write(pack("I", long(m[22])))#damage_min
		mp_out_write(pack("I", long(m[23])))#damage_max
		mp_out_write(pack("h", long(m[24])))#attack_speed
		mp_out_write(pack("h", long(m[25])))#move_speed
		mp_out_write(pack("B", long(m[26])))#aggressive_hp_pct
		mp_out_write(pack("H", long(m[27])))#aggressive_sight
		mp_out_write(pack("H", long(m[28])))#attack_range

		mp_out_write(pack("b", long(m[29])))#enchant_curse
		mp_out_write(pack("b", long(m[30])))#enchant_slow
		mp_out_write(pack("b", long(m[31])))#enchant_poison
		mp_out_write(pack("b", long(m[32])))#enchant_stun
		mp_out_write(pack("b", long(m[33])))#enchant_critical
		mp_out_write(pack("b", long(m[34])))#enchant_penetrate
		mp_out_write(pack("b", long(m[35])))#resist_sword
		mp_out_write(pack("b", long(m[36])))#resist_twohand
		mp_out_write(pack("b", long(m[37])))#resist_dagger
		mp_out_write(pack("b", long(m[38])))#resist_bell
		mp_out_write(pack("b", long(m[39])))#resist_fan
		mp_out_write(pack("b", long(m[40])))#resist_bow
		mp_out_write(pack("b", long(m[41])))#resist_fire
		mp_out_write(pack("b", long(m[42])))#resist_elect
		mp_out_write(pack("b", long(m[43])))#resist_magic
		mp_out_write(pack("b", long(m[44])))#resist_wind
		mp_out_write(pack("b", long(m[45])))#resist_poison
		mp_out_write(pack("I", long(m[46])))#summon (always 0)
		mp_out_write(pack("I", long(m[47])))#drop_item
		mp_out_write(pack("B", long(m[48])))#mount_capacity (always 0)
		mp_out_write(pack("H", long(m[49])))#on_click
		mp_out_write(nullpadder(m[50], 65))#folder
		mp_out_write(pack("f", float(m[51])))#dam_multiply
		mp_out_write(pack("I", long(m[52])))#summon
		mp_out_write(pack("I", long(m[53])))#drain_sp
		mp_out_write(pack("I", long(m[54])))#mob_color
		mp_out_write(pack("I", long(m[55])))#polymorph_item
		mp_out_write(nullpadder(m[56].decode('hex'), mp_ml1))#unk4 (always 0)
		mp_out_write(pack("B", long(m[57])))#sp_berserk (always 0)
		mp_out_write(pack("B", long(m[58])))#sp_stoneskin (always 0)
		mp_out_write(pack("B", long(m[59])))#sp_godspeed (always 0)
		mp_out_write(pack("B", long(m[60])))#sp_deathblow (always 0)
		mp_out_write(pack("B", long(m[61])))#sp_revive (always 0)

		m_count+=1
	mp_out.close()
	return m_count
def mproto_save(mpin, mpout, m_count):
	def nullpadding(mlen, msize=8):
		retlen = ''
		mpad = mlen%msize
		if mpad:
			retlen = (msize-mpad)*chr(0)
		return retlen
	pack, unpack = struct.pack, struct.unpack
	global MT2_MAGIC1, MT2_MAGIC4, MT2_XTEAKEY_MPX, LZO_COMPRESSION_LEVEL

	mp_out2X = open(mpin, "rb")
	mp_out2 = mp_out2X.read()
	mp_out2X.close(); del mp_out2X

	mpl_out2 = len(mp_out2)
	mp_out3 = lzo.compress(mp_out2, LZO_COMPRESSION_LEVEL)
	mpd_out3 = unpack("!L", mp_out3[1:5])[0]

	mpp_out3 = mp_out3[5:]
	mpl_out3 = len(mpp_out3)
	mp_out4 = mpp_out3+nullpadding(mpl_out3)

	mp_out5 = _xtea.encrypt_all(MT2_MAGIC1+mp_out4+chr(0)*4, MT2_XTEAKEY_MPX)
	mpl_out5 = len(mp_out5)
	pass

	mpp_h1 = MT2_MAGIC4+pack("I", m_count)+pack("I", mpl_out5+16)
	mpp_hl2 = MT2_MAGIC1+pack("I", mpl_out5)+pack("I", mpl_out3)+pack("I", mpd_out3)

	mpp_outX = open(mpout, "wb")
	mpp_outX.write(mpp_h1+mpp_hl2+mp_out5)
	mpp_outX.close()

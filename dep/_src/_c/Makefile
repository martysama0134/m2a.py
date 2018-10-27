

# pkg install lzo2-2.06_3

# make clean dist
# make clean unin

PREFIX = .setup
POSTFIX = .pydetails
#MODULES = _xtea lzo

all: clean unin inst

inst: dist-install
unin: dist-uninstall
clean: dist-clean

dist-install:
	@python2.7 _xteasetup.py install --record $(PREFIX)._xtea$(POSTFIX)
	@python2.7 lzosetup.py install --record $(PREFIX).lzo$(POSTFIX)
dist-uninstall:
	@cat $(PREFIX)._xtea$(POSTFIX) | xargs rm -rf
	@cat $(PREFIX).lzo$(POSTFIX) | xargs rm -rf
	@rm -f $(PREFIX)._xtea$(POSTFIX) $(PREFIX).lzo$(POSTFIX)
dist-clean:
	@rm -rf build

#rly:
#	$(foreach var,$(MODULES),echo $(var);)

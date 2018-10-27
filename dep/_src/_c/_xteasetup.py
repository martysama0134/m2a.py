from distutils.core import setup, Extension

module1 = Extension(
	'_xtea',
	sources = ['_xteamodule.c']
)

setup(
	author = 'martysama0134',
	author_email = 'martysama0134@gmail.com',
	description = '_xtea package',
	license = 'GNU General Public License (GPL)',
	long_description = '''_xtea encryption package''',
	platforms = 'All',
	url = 'http://docs.python.org/extending/building',

	name = 'python-xtea',
	version = '2.0',
	ext_modules = [module1],
)



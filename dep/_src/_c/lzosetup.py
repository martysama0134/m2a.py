from distutils.core import setup, Extension

module1 = Extension(
	'lzo',
	libraries = ['lzo2'],
	include_dirs = ['/usr/local/include'],
	library_dirs = ['/usr/local/lib'],
	sources = ['lzomodule.c'],
)

setup(
	author = 'Markus F.X.J. Oberhumer',
	author_email = 'markus@oberhumer.com',
	description = 'lzo package',
	license = 'GNU General Public License (GPL)',
	long_description = '''lzo compression package''',
	platforms = 'All',
	url = 'http://docs.python.org/extending/building',

	name = 'python-lzo',
	version = '1.08',
	ext_modules = [module1],
)



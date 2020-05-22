from distutils.core import setup

setup(	name='cryptool',
		version='0.1.0',
		description='Simplified interface for encrypting and decrypting: raw bytes, text, files and directories.',
		author='Marcos C. V. M.',
		url='https://github.com/Marcos-C7/cryptool',
		packages=['cryptool'],			# Name of the package
		package_dir={'cryptool': ''},	# Path of the package root (current working directory in our case)
		classifiers=['Development Status :: 3 - Alpha',
					'License :: Freely Distributable',
					'Programming Language :: Python :: 3',
					'Topic :: Security :: Cryptography'],
		keywords=['cryptography']
	)
'''
The tree of imports of a package is structured as follows:
- package_name.			# Name of the root folder of the package
	- module_name.		# Name of the .py file (wihout the .py).
		- object_name	# Name of the class or function defined within the module name.

In our case, the Cryptool class is defined in the route:
- cryptool.cryptool.Cryptool

If we want to import all the contents of the module 'cryptool' we need:
- from cryptool import cryptool
So that we can use the class Cryptool by:
- x = cryptool.Cryptool()

If we want to import the class Cryptool we can use:
- from cryptool.cryptool import Cryptool
So that we can use the class by:
- x = Cryptool()

We can choose specific classes/objects/functions from modules in the package folder 
and make them available for import. For example, appending in this file the line 
"from .cryptool import Cryptool" we can now import the class Cryptool directly:
- from cryptool import Cryptool
So that we can use the class by:
- x = Cryptool()
'''

from .cryptool import Cryptool

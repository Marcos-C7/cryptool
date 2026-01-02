# To install the package in editable mode, run:
# > pip install -e .
# To generate the installer:
# > pip install build
# > python -m build

from .cryptool import main

res = main()
print(res["status"])
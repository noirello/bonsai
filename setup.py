import os
import sys
import re
try:
    from setuptools import setup, Extension, Command
except ImportError:
    from distutils.core import setup, Extension, Command

class TestCommand(Command):
    description = "Run the tests."
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import unittest
        tests = unittest.defaultTestLoader.discover("./tests")
        suite = unittest.TestSuite()
        suite.addTests(tests)
        #result = unittest.TestResult()
        unittest.TextTestRunner().run(suite)
        sys.exit(0)

sources = ["bonsaimodule.c", "ldapentry.c", "ldapconnectiter.c",
           "ldapconnection.c", "ldapmodlist.c", "ldapvaluelist.c",
           "ldap-xplat.c", "ldapsearchiter.c", "utils.c", "uniquelist.c"]

depends = ["ldapconnection.h", "ldapentry.h", "ldapconnectiter.h",
           "ldapmodlist.h", "ldapvaluelist.h", "ldapsearchiter.h",
           "ldap-xplat.h", "uniquelist.h", "utils.h"]

if sys.platform == "win32":
    libs = ["wldap32", "secur32", "Ws2_32"]
    sources.append("wldap-utf8.c")
    depends.append("wldap-utf8.h")
else:
    libs = ["ldap", "lber"]

sources = [os.path.join('src', x) for x in sources]
depends = [os.path.join('src', x) for x in depends]

pyldap_module = Extension("bonsai._bonsai",
                          libraries=libs,
                          sources=sources,
                          depends=depends)

with open('README.md') as file:
    long_descr = file.read()
    # Change linking format from GitHub style to PyPI compatible format.
    pat = r"\[([a-zA-Z_ ]*)\]\(([a-zA-Z_:/.]*)\)"
    long_descr = re.sub(pat, r"`\g<1> <\g<2>>`_", long_descr)
    # Change codeblock format
    long_descr = long_descr.replace("```python", ".. code-block:: python")
    long_descr = long_descr.replace("```\n", "")

setup(name="bonsai",
      version="0.8.0",
      description="Module for Python 3 to access LDAP directory servers.",
      author="noirello",
      author_email="noirello@gmail.com",
      url="https://github.com/noirello/bonsai",
      long_description=long_descr,
      license="MIT",
      ext_modules=[pyldap_module],
      package_dir = {"bonsai": "lib"},
      packages=["bonsai", "bonsai.asyncio", "bonsai.gevent", "bonsai.tornado"],
      include_package_data=True,
      cmdclass={"test": TestCommand},
      keywords=["python3", "ldap", "libldap", "winldap"],
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: MIT License',
          'Operating System :: Microsoft :: Windows',
          'Operating System :: Unix',
          'Programming Language :: C',
          'Programming Language :: Python :: 3',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP']
      )


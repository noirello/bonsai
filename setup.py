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
        tests = unittest.defaultTestLoader.discover("./tests", pattern="*_test.py")
        suite = unittest.TestSuite()
        suite.addTests(tests)
        #result = unittest.TestResult()
        unittest.TextTestRunner().run(suite)
        sys.exit(0)

sources = ["pyldapmodule.c", "ldapentry.c", "ldapconnectiter.c",
           "ldapconnection.c", "ldapmodlist.c", "ldapvaluelist.c",
           "ldap-xplat.c", "ldapsearchiter.c", "utils.c", "uniquelist.c"]

depends = ["ldapconnection.h", "ldapentry.h", "ldapconnectiter.h",
           "ldapmodlist.h", "ldapvaluelist.h", "ldapsearchiter.h",
           "ldap-xplat.h", "uniquelist.h", "utils.h"]

sources = [os.path.join('src', x) for x in sources]
depends = [os.path.join('src', x) for x in depends]

if sys.platform == "win32":
    libs = ["wldap32", "secur32", "Ws2_32"]
    sources.append("wldap-utf8.c")
    depends.append("wldap-utf8.h")
else:
    libs = ["ldap", "lber"]

pyldap_module = Extension("pyldap._cpyldap",
                          libraries=libs,
                          sources=sources,
                          depends=depends)

with open('README.md') as file:
    long_descr = file.read()
    # Change linking format from GitHub style to PyPI compatible format.
    pat = r"\[([a-zA-Z_ ]*)\]\(([a-zA-Z_:/.]*)\)"
    long_descr = re.sub(pat, r"`\g<1> <\g<2>>`_", long_descr)

setup(name="pyldap",
      version="0.7.5",
      description="Module for Python 3 to access LDAP directory servers.",
      author="noirello",
      author_email="noirello@gmail.com",
      url="https://github.com/Noirello/PyLDAP",
      long_description=long_descr,
      license="MIT",
      ext_modules=[pyldap_module],
      package_dir = {"pyldap": "lib"},
      packages=["pyldap", "pyldap.asyncio", "pyldap.gevent"],
      cmdclass={"test": TestCommand},
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


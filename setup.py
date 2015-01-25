import os
import sys
try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension

sources = ["pyldapmodule.c", "ldapentry.c",
           "ldapconnection.c", "ldapmodlist.c", "ldapvaluelist.c",
           "ldapsearchiter.c", "utils.c", "uniquelist.c"]

depends = ["ldapconnection.h", "ldapentry.h", 
           "ldapmodlist.h", "ldapvaluelist.h", "ldapsearchiter.h",
           "uniquelist.h", "utils.h"]

sources = [ os.path.join('pyldap', x) for x in sources]
depends = [ os.path.join('pyldap', x) for x in depends]

if sys.platform == "win32":
    libs = ["wldap32"]
else:
    libs = ["ldap", "lber"]

pyldap_module = Extension("pyldap._cpyldap",
            libraries = libs,
            sources = sources,
            depends = depends)

with open('README.md') as file:
    long_descr = file.read()

setup(name="pyldap",
      version="0.7.0",
      description = "Module for Python 3 to access LDAP directory servers.",
      author = "noirello",
      author_email = "noirello@gmail.com",
      url="https://github.com/Noirello/PyLDAP",
      long_description = long_descr,
      license = "MIT",
      ext_modules=[pyldap_module],
      packages = ["pyldap"],
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

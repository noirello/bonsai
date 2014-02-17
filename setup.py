import os
import sys
from distutils.core import setup, Extension

sources = ["pyldapmodule.c", "ldapentry.c",
           "ldapconnection.c", "ldapvaluelist.c",
           "utils.c", "uniquelist.c"]

depends = ["ldapconnection.h", "ldapvaluelist.h", "uniquelist.h", "utils.h"]

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

setup(name="pyldap",
      version="0.1.5",
      description = "Module to access LDAP directory servers.",
      author = "noirello",
      author_email = "noirello@gmail.com",
      url="https://github.com/Noirello/PyLDAP",
      long_description = """"This module is a wrapper for libldap2 library
      on Unix and Winldap on Microsoft Windows.
      Heavily under development. Support only Python 3.x.""",
      ext_modules=[pyldap_module],
      packages = ["pyldap"]
)

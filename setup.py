import os
import sys
from distutils.core import setup, Extension

sources = ["pyldapmodule.c", "ldapentry.c", 
           "ldapclient.c", "ldapvaluelist.c", 
           "utils.c", "uniquelist.c"]

depends = ["ldapclient.h", "ldapvaluelist.h", "uniquelist.h", "utils.h"]

sources = [ os.path.join('pyLDAP', x) for x in sources]
depends = [ os.path.join('pyLDAP', x) for x in depends]

if sys.platform == "win32":
    libs = ["wldap32"]
else:
    libs = ["ldap", "lber"]

pyldap_module = Extension("pyLDAP._cpyLDAP", 
            libraries = libs,    
            sources = sources,
            depends = depends)

setup(name="pyLDAP",
      version="0.1.5",
      description = "Module to access LDAP directory servers.",
      author = "noirello",
      author_email = "noirello@gmail.com",
      url="https://github.com/Noirello/pyLDAP",
      long_description = "This module is a wrapper for the OpenLDAP 2.4 library. Heavily under development. Support only Python 3.x.",
      ext_modules=[pyldap_module],
      packages = ["pyLDAP"]
)
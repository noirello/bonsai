import os
from distutils.core import setup, Extension

sources = ["pyldapmodule.c", "ldapentry.c", 
           "ldapclient.c", "ldapvaluelist.c", 
           "errors.c", "utils.c", "uniquelist.c"]

depends = ["errors.h", "ldapclient.h", "ldapvaluelist.h", "uniquelist.h", "utils.h"]

sources = [ os.path.join('pyLDAP', x) for x in sources]
depends = [ os.path.join('pyLDAP', x) for x in depends]

pyldap_module = Extension("pyLDAP._cpyLDAP", 
            libraries=["ldap", "lber"],    
            sources = sources,
            depends = depends)

setup(name="pyLDAP", 
      version="0.1.1",
      description = "Module to access LDAP directory servers.",
      author = "noirello",
      author_email = "noirello@gmail.com",
      long_description = "This module is a wrapper for the OpenLDAP 2.4 library. Heavily under development. Support only Python 3.x.",
      ext_modules=[pyldap_module],
      packages = ["pyLDAP"]
)
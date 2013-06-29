from distutils.core import setup, Extension

pyldap_module = Extension("pyLDAP", 
            libraries=["ldap", "lber"],    
            sources = ["pyldapmodule.c", "ldapentry.c", "ldapclient.c", "ldapvaluelist.c", "errors.c", "utils.c", "uniquelist.c"])

setup(name="pyLDAP", 
      version="0.1.0",
      description = "Module to access LDAP directory servers.",
      author = "noirello",
      author_email = "noirello@gmail.com",
      long_description = "This module is a wrapper for the OpenLDAP 2.4 library. Heavily under development. Support only Python 3.x.",
      ext_modules=[pyldap_module]
)
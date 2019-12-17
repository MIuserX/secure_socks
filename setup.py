#!/usr/bin/python

from distutils.core import setup, Extension

module1 = Extension('MyEncrypt',
                    sources = ['en2.c'],
                    libraries = ['crypto']
                    )

setup (name = 'a demo extension module',
       version = '1.0',
       description = 'This is a demo package',
       ext_modules = [module1])


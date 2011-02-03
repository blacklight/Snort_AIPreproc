#!/usr/bin/python

from distutils.core import setup, Extension
import commands
import re

xml_include = commands.getoutput ( 'pkg-config --cflags libxml-2.0' )
m = re.match ( '^-I\s*(.+?)\s*$', xml_include )

if m:
	xml_include = m.group ( 1 )

xml_libs = commands.getoutput ( 'pkg-config --libs libxml-2.0' )
m = re.match ( '^-l\s*(.+?)\s*$', xml_libs )

if m:
	xml_libs = m.group ( 1 )

setup (
	name = 'snortai',
	version = '0.1',
	description = 'Python interface to SnortAI module',
	author = 'Fabio "BlackLight" Manganiello',
	author_email = 'blacklight@autistici.org',
	ext_modules = [
		Extension (
			'snortai',
			sources = ['snortai_module.c'],
			include_dirs = ['..', '../include', '../uthash', xml_include],
			libraries = [xml_libs]
		)
	]
)


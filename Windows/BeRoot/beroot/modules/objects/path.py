# -*- coding: utf-8 -*-

class Path(object):
	def __init__(self, path=None, hasSpace=None, hasQuotes=False, isDirWritable=False, subDirWritables=[]):
		self.path 				= path
		self.hasSpace 			= hasSpace
		self.hasQuotes 			= hasQuotes
		self.isDirWritable 		= isDirWritable
		self.subDirWritables 	= subDirWritables

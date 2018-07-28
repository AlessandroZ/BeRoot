# -*- coding: utf-8 -*-

class Service():
	def __init__(self):
		self.key 				= None
		self.is_key_writable 	= False
		self.name 				= None
		self.display_name 		= None
		self.full_path 			= None
		self.paths 				= []
		self.permissions 		= {}

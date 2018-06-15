#!/usr/bin/env pythonis_readable
# -*- coding: utf-8 -*-
import pwd
import grp
import os

class Users(): 
	'''
	Get users list with uid and gid
	'''
	def __init__(self):
		self.list 		= pwd.getpwall()
		self.current	= [p for p in self.list if p.pw_uid == os.getuid()][0]
		self.groups 	= grp

from beroot.modules.objects.path import Path
import ntpath
import os
import re

# check the permission of an exe file
def isRootDirectoryWritable(path, isDir=False):	
	if isDir:
		dirname = path
	else:
		dirname = ntpath.dirname(path)

	new_path = os.path.join(dirname, "a.txt")
	
	try:
		f = open(new_path, "w")
		f.close()
		os.remove(new_path)
		return True
	except:
		return False

def getSubDirWritable(path):
	results = []
	path = os.path.dirname(path).split(os.sep)
	tmp_path = os.path.join(path[0], os.sep)
	for i in path[1:]:
		if " " in i and isRootDirectoryWritable(tmp_path, True):				
			results.append(tmp_path)
		tmp_path = os.path.join(tmp_path, i)
	return results


# global variable to not compile it every time
reg = r"(?P<fullpath>\"?[a-zA-Z]:(\\\w[ (?\w\.)?]*)+\.\w\w\w\"?)"
regex = re.compile(reg, re.IGNORECASE)
def get_path_info(path):
	paths = []
	path = os.path.expandvars(path)
	for res in regex.findall(path):
		hasQuotes = False
		hasSpace = False
		path = res[0].strip()

		if ' ' in path:
			hasSpace = True

		if '\'' in path or '"' in path:
			hasQuotes = True
			path = path.replace('\'', '').replace('"', '')

		paths.append(
			Path(
				path=path, 
				hasSpace=hasSpace, 
				hasQuotes=hasQuotes, 
				isDirWritable=isRootDirectoryWritable(path), 
				subDirWritables=getSubDirWritable(path)
			)
		)

	return paths


# check path containing space without quotes
def space_and_no_quotes(data):
	results = []
	for sk in data:
		for p in sk.paths:
			if p.hasSpace and not p.hasQuotes and p.subDirWritables:
				results.append(format_results(sk, p, True))
	return results


# check if the directory containing the exe is writable (useful for dll hijacking or to replace the exe if possible)
def exe_with_writable_directory(data):
	results = []
	for sk in data:
		for p in sk.paths:
			if p.isDirWritable:
				results.append(format_results(sk, p))
	return results


# format result into a tab
def format_results(sk, p, checkSubdir=False):
	results = {}
	if 'key' in dir(sk):
		if sk.key:
			results['Key'] = sk.key

	if 'permissions' in dir(sk):
		if sk.permissions:
			results['permissions'] = str(sk.permissions)

	if 'runlevel' in dir(sk):
		if sk.runlevel:
			results['Runlevel'] = sk.runlevel

	if 'userid' in dir(sk):
		if sk.userid:
			results['UserId'] = sk.userid

	results['Name'] = sk.name
	results['Full path'] = sk.full_path
	
	if not checkSubdir:
		results['Writable directory'] = os.path.dirname(p.path)
	else:
		results['Writables path found'] = []
		for d in p.subDirWritables:
			results['Writables path found'].append(d)

	return results

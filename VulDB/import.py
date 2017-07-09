#!/usr/bin/env python
# -*- coding: utf-8 -*-
# version 0.1 update by le @ 2017.7.6

import argparse
from argparse import RawTextHelpFormatter
from Parser_Nsfocus import GetVulDetails
from db import DBO
import zipfile,tempfile,os


def import_nsfoucs(ReportFiles, TaskID, Department, Project="tj.cmcc"):
	dbo = DBO()
	# dbo.graph.delete_all()
	
	dbo.add_department(Project, Department)
	for zip in ReportFiles:
		if zipfile.is_zipfile(zip):
			print "[ Working on\t %s ]"%zip.name
			tmp=tempfile.mkdtemp(".tmp","nsfocus_")#创建唯一的临时文件，避免冲突
			zipfile.ZipFile(zip).extractall(path=tmp)
			# taskpath = os.path.abspath(dir)
			for data in GetVulDetails(tmp):
				# add more meta info
				data[u"TaskID"] = TaskID.strip()
				data[u"扫描器"] = "nsfocus"
				# store data
				dbo.add_vul(Department, data)
			os.unlink(tmp)
	print "[ Store complete! ]"


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='''
    import many vul scanner data to core database.
    ''', formatter_class=RawTextHelpFormatter)
	parser.add_argument("-d", dest="Department", type=str, default="网络安全部",
	                    help="Report belong to which department")
	parser.add_argument("-t", dest="TaskID", type=str,
	                    help="Unique TaskID for identify task and export.")
	parser.add_argument("--nessus", dest="Nessus", type=file, nargs="+",
	                    help="Support nessus export xml format files: .nessus")
	parser.add_argument("--nsfocus", dest="Nsfocus", type=file, nargs="+",
	                    help="Support nsfocus export html format file: .html.zip")
	args = parser.parse_args()
	if args.Nessus:
		pass
	elif args.Nsfocus:
		import_nsfoucs(args.Nsfocus, args.TaskID, args.Department)
	
	else:
		print "== Please at least special one scanner report type and file"

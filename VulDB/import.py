#!/usr/bin/env python
# -*- coding: utf-8 -*-
# version 1.1 update by le @ 2017.7.6

from argparse import RawTextHelpFormatter
from Parser4nsfocus import GetNsfocusVulDetails
from Parser4nessus import GetNessusVulDetails
from db import DBO
import zipfile, tempfile, argparse, shutil


def import_nsfoucs(ReportFiles, TaskID, Project, Department, Application):
	dbo = DBO()
	dbo.add_app(Project, Department,Application)
	for zip in ReportFiles:
		if zipfile.is_zipfile(zip):
			print "[ Working on\t %s ]" % zip.name
			tmp = tempfile.mkdtemp(".tmp", "nsfocus_")  # 创建唯一的临时文件，避免冲突
			zipfile.ZipFile(zip).extractall(path=tmp)
			for data in GetNsfocusVulDetails(Application,tmp):
				# add more meta info
				data[u"TaskID"] = TaskID.strip()
				data[u"Scanner"] = "nsfocus"
				# store data
				dbo.add_vul(data)
			print "nsfocus Report done:\t%s" % zip.name
			shutil.rmtree(tmp)
	print "[ Store complete! ]"


def import_nessus(ReportFiles, TaskID, Project, Department, Application):
	dbo = DBO()
	dbo.add_app(Project, Department, Application)
	for xml in ReportFiles:
		print "[ Working on\t %s ]" % xml.name
		for data in GetNessusVulDetails(Application, xml):
			# add more meta info
			data[u"TaskID"] = TaskID.strip()
			data[u"Scanner"] = "nessus"
			# store data
			dbo.add_vul(data)
		print "nessus Report done:\t%s" % xml.name
	print "[ Store complete! ]"


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='''
    Import many vul scanner report data to core database.
    ''', formatter_class=RawTextHelpFormatter)
	parser.add_argument("-p", dest="Project", type=str, default="tj.cmcc",
	                    help="Report belong to which project")
	parser.add_argument("-d", dest="Department", type=str, default="",
	                    help="Report belong to which department")
	parser.add_argument("-a", dest="App", type=str, default="",
	                    help="Report belong to which application system")
	parser.add_argument("-t", dest="TaskID", type=str,
	                    help="Unique TaskID for identify task and export.")
	parser.add_argument("--nessus", dest="Nessus", type=file, nargs="+",
	                    help="Support nessus export xml format files: .nessus")
	parser.add_argument("--nsfocus", dest="Nsfocus", type=file, nargs="+",
	                    help="Support nsfocus export html format file: _html.zip")
	args = parser.parse_args()
	
	if not (args.Nessus or args.Nsfocus):
		print "== Please at least special one scanner report type and file"
		print parser.print_usage()
	if args.Nessus:
		import_nessus(args.Nessus, args.TaskID, args.Project, args.Department, args.App)
	if args.Nsfocus:
		import_nsfoucs(args.Nsfocus, args.TaskID, args.Project, args.Department, args.App)
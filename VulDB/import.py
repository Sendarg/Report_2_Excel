#!/usr/bin/env python
# -*- coding: utf-8 -*-
# version 0.1 update by le @ 2017.7.6

from argparse import RawTextHelpFormatter
from Parser4nsfocus import GetNsfocusVulDetails
from Parser4nessus import GetNessusVulDetails
from db import DBO
import zipfile, tempfile, argparse, shutil


def import_nsfoucs(ReportFiles, TaskID, Project, Department, Application):
	dbo = DBO()
	# dbo.graph.delete_all()
	dbo.add_department(Project, Department)
	for zip in ReportFiles:
		if zipfile.is_zipfile(zip):
			print "[ Working on\t %s ]" % zip.name
			tmp = tempfile.mkdtemp(".tmp", "nsfocus_")  # 创建唯一的临时文件，避免冲突
			zipfile.ZipFile(zip).extractall(path=tmp)
			# taskpath = os.path.abspath(dir)
			for data in GetNsfocusVulDetails(tmp):
				# add more meta info
				data[u"TaskID"] = TaskID.strip()
				data[u"扫描器"] = "nsfocus"
				# store data
				dbo.add_vul(Department, data)
			shutil.rmtree(tmp)
	print "[ Store complete! ]"


def import_nessus(ReportFiles, TaskID, Project, Department, Application):
	dbo = DBO()
	# dbo.graph.delete_all()
	dbo.add_department(Project, Department)
	for xml in ReportFiles:
		print "[ Working on\t %s ]" % xml.name
		# taskpath = os.path.abspath(dir)
		for data in GetNessusVulDetails(xml):
			# add more meta info
			data[u"TaskID"] = TaskID.strip()
			data[u"扫描器"] = "nessus"
			# store data
			dbo.add_vul(Department, data)
	print "[ Store complete! ]"


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='''
    import many vul scanner data to core database.
    ''', formatter_class=RawTextHelpFormatter)
	parser.add_argument("-p", dest="Project", type=str, default="tj.cmcc",
	                    help="Report belong to which project")
	parser.add_argument("-d", dest="Department", type=str, default="noname",
	                    help="Report belong to which department")
	parser.add_argument("-a", dest="App", type=str, default="noname",
	                    help="Report belong to which application system")
	parser.add_argument("-t", dest="TaskID", type=str,
	                    help="Unique TaskID for identify task and export.")
	parser.add_argument("--nessus", dest="Nessus", type=file, nargs="+",
	                    help="Support nessus export xml format files: .nessus")
	parser.add_argument("--nsfocus", dest="Nsfocus", type=file, nargs="+",
	                    help="Support nsfocus export html format file: _html.zip")
	args = parser.parse_args()
	if args.Nessus:
		import_nessus(args.Nessus, args.TaskID, args.Project, args.Department, args.App)
	elif args.Nsfocus:
		import_nsfoucs(args.Nsfocus, args.TaskID, args.Project, args.Department, args.App)
	
	else:
		print "== Please at least special one scanner report type and file"

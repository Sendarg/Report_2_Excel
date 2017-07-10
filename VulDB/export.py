#!/usr/bin/env python
# -*- coding: utf-8 -*-
# version 0.1 update by le @ 2017.7.6

import argparse
from argparse import RawTextHelpFormatter
from db import MetaData, DBO
from openpyxl import load_workbook


def template_tj(TaskID, Scanner, OutputFileName):
	wb = load_workbook("template_tj.xlsx")
	sheet = wb.active
	if not OutputFileName:
		OutputFileName = TaskID
	outFile = OutputFileName + ".xlsx"
	headers = []
	for c in sheet.columns:
		headers.append(c[0].value)
		c[0].value = ""  # delete for quickly # empty headers, can't remove line use openpyxl
	# todo : more details
	'''
	整体修改：
		部门名称、应用系统名称、主机信息
	'''
	i = 0  # auto line number
	condition = 'n.等级<>"None" and not n.解决办法 =~ ".*可以不做?修复.*" and n.解决办法 <>""'
	if Scanner:
		condition = 'n.Scanner="%s" and n.等级<>"None" and not n.解决办法 =~ ".*可以不做?修复.*" and n.解决办法 <>""' % Scanner
	for v in DBO().enum_vul(TaskID, condition):
		line = []
		i += 1
		for c in headers:
			line.append(v[c])
		line[0] += str(i).zfill(5)
		sheet.append(line)
	
	# remove template data
	wb.remove(wb.get_sheet_by_name("Headers"))
	wb.save(outFile)
	print "[ Save as %s]\n" % outFile


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='''
    Export template data to file.
    ''', formatter_class=RawTextHelpFormatter)
	parser.add_argument("-c", dest="Columns", action='store_true',
	                    help="Print support data key, Use in excel Columns for user defined template.")
	parser.add_argument("-t", dest="TaskID", type=str,
	                    help="Unique TaskID for identify task and export.")
	# further todo:add more:department\app
	parser.add_argument("-s", dest="Scanner", type=str, choices=["nessus", "nsfocus"],
	                    help="Select one scanner results.")
	parser.add_argument("-p", dest="Template", type=str, choices=["tj"],
	                    help="Export some data to predefine templates")
	parser.add_argument("-o", dest="OutputFileName", type=str,
	                    help="File Name to store")
	
	args = parser.parse_args()
	if args.Columns:
		cols = MetaData().data.keys()
		cols.sort()
		for i in cols:
			print i
	if args.Template == "tj":
		template_tj(args.TaskID, args.Scanner, args.OutputFileName)
	# print "==== Save to file %s."%(args.FileName+".xlsx")
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# update @ 2017.6.10

import os, glob, urllib2
import os.path as P

import lxml.html as H
from openpyxl import Workbook


def task2sheet(WookBk, SingleTaskPath):
	# get all absolute file path in TaskPath
	iphtmls = glob.glob(SingleTaskPath + '/host/*.html')
	if not len(iphtmls):
		print "---- Path has Nothing:\t%s" % SingleTaskPath
		return None
	
	## set task name as sheet name
	# get task name !!!! task name between _ don't have any excel not like char like [ ]
	names = SingleTaskPath.decode('utf-8').split('/')
	task = sheetname = names[0]
	sheet = WookBk.create_sheet(sheetname)
	titles = [u"任务",
	          u"IP地址",
	          u"NSFOCUS",
	          u"详细描述",
	          u"CVE编号",
	          u"应用",
	          u"解决办法",
	          u"威胁类别",
	          u"威胁分值",
	          u"漏洞名称",
	          u"vulid",
	          u"BUGTRAQ",
	          u"plgid",
	          u"端口返回",
	          u"协议",
	          u"服务",
	          u"端口号",  # jq limit
	          u"等级",
	          u"发现日期",
	          u"危险插件",
	          u"CNVD编号",
	          u"CNNVD编号",
	          u"CNCVE编号",
	          u"CVSS评分"]
	sheet.append(titles)
	
	for iphtml in iphtmls:
		IPfile = P.basename(iphtml)
		# if it is ip.html file
		if IPfile.count('.') == 4:
			# ippath=P.join(taskpath,iphtml)
			IP = IPfile[:-5]
			
			## get html content
			content = urllib2.urlopen(url="file:./" + iphtml).read()
			html = H.fromstring(content.decode('utf-8'))
			
			# VulTable = html.xpath('//*[@id="vul_detail"]/table/tr')
			vul_trs = html.xpath('//*[@id="vul_detail"]/table/tr')
			count = len(vul_trs) / 2
			for l in range(count):
				title_index = l * 2
				details_index = title_index + 1
				
				# store all head data
				data = {
					u"任务": "",
					u"IP地址": "",
					u"NSFOCUS": "",
					u"详细描述": "",
					u"CVE编号": "",
					u"应用": "",
					u"解决办法": "",
					u"威胁类别": "",
					u"威胁分值": "",
					u"漏洞名称": "",
					u"vulid": "",
					u"BUGTRAQ": "",
					u"plgid": "",
					u"端口返回": "",
					u"协议": "",
					u"服务": "",
					u"端口号": "",
					u"等级": "",
					u"发现日期": "",
					u"危险插件": "",
					u"CNVD编号": "",
					u"CNNVD编号": "",
					u"CNCVE编号": "",
					u"CVSS评分": ""
				}
				data[u"任务"] = task
				data[u"IP地址"] = IP
				
				# get basic Data from html <title>
				data[u"vulid"] = vul_trs[title_index].attrib["data-id"]  # nsfocus defined uniqe ID
				data[u"端口号"] = vul_trs[title_index].attrib["data-port"]
				Level = vul_trs[title_index].xpath('./td/img[2]')[0]
				data[u"等级"] = Level.attrib["src"].split("/")[3][5:-4]
				data[u"漏洞名称"] = vul_trs[title_index].xpath('./td/span')[0].text
				
				# get port information
				PortReturn = html.xpath('//*[@data-id="%s"]/div' % data["vulid"])
				if len(PortReturn) > 0:
					data[u"端口返回"] = get_br_text(PortReturn[0])
				else:
					data[u"端口返回"] = ""
				PortInfo = html.xpath('//*[@data-id="%s"]/../../../../../td' % data["vulid"])
				data[u"端口号"] = PortInfo[0].text
				data[u"协议"] = PortInfo[1].text
				data[u"服务"] = PortInfo[2].text
				
				# get vul details Data
				vul_table = vul_trs[details_index].xpath('./td/table/tr')
				for tr in vul_table:
					th = tr.xpath('./th')[0].text
					td = tr.xpath('./td')[0]
					# print IP, th
					data[th] = get_pure_text(td)
				
				# some replace fix
				if data[u"端口号"] == "--":
					data[u"端口号"] = "0"
				if data[u"服务"] == "--":
					data[u"服务"] = ""
				
				# write down to excel sheet
				line = [data[u"任务"],
				        data[u"IP地址"],
				        data[u"NSFOCUS"],
				        data[u"详细描述"],
				        data[u"CVE编号"],
				        data[u"应用"],
				        data[u"解决办法"],
				        data[u"威胁类别"],
				        data[u"威胁分值"],
				        data[u"漏洞名称"],
				        data[u"vulid"],
				        data[u"BUGTRAQ"],
				        data[u"plgid"],
				        data[u"端口返回"],
				        data[u"协议"],
				        data[u"服务"],
				        data[u"端口号"],
				        data[u"等级"],
				        data[u"发现日期"],
				        data[u"危险插件"],
				        data[u"CNVD编号"],
				        data[u"CNNVD编号"],
				        data[u"CNCVE编号"],
				        data[u"CVSS评分"]
				        ]
				
				sheet.append(line)
		
		print "IP:\t%s is done" % iphtml
	print  "Sheet:\t%s is done" % sheetname
	return True


def get_task_name():
	# for now,different report dir process to diff excel sheet
	# todo:get full task name from index.html,how to marge them to 1 single sheet like jq does
	#
	pass


def get_pure_text(xpathElement):
	# get text from td , remove other html label
	if xpathElement.findall("a"):  # only a like
		text = xpathElement.xpath('./a')[0].text.strip()
	elif xpathElement.findall("br"):  # only br text
		text = xpathElement.text.strip()
		for br in xpathElement.findall("br"):
			if br.tail.strip():  # not add empty line
				text += "\n" + br.tail.strip()
	else:
		text = xpathElement.text.strip()
	return text


def get_br_text(xpathElement):
	t1 = xpathElement.text.strip()
	for x in range(11):
		br = xpathElement.xpath('./br[%s]' % x)
		if len(br) > 0:
			t1 += "\n" + br[0].tail.strip()
	return t1


def get_a_text(xpathElement):
	text = xpathElement.text
	a = xpathElement.xpath('./a')
	if text and len(a) > 0:
		text += a[0].text
	else:
		text = a[0].text
	return text


## seq all ip.html in some dir
# get report dir at same dir
for dir in os.listdir(os.getcwd()):
	if P.isdir(dir) and (not dir.startswith(".")):
		wb = Workbook()
		wb.remove_sheet(wb.active)  # delete default sheet1
		# get all task dir in a store file
		print "[ Working on " + dir + " :]"
		# taskpath = os.path.abspath(dir)
		if task2sheet(wb, dir):
			outFile = dir + ".xlsx"
			# 单 sheet 保存？
			wb.save(outFile)
			print "[ Save as %s]\n" % outFile

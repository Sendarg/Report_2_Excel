#!/usr/bin/env python
# -*- coding: utf-8 -*-
# version 1.1 update by le @ 2017.7.6

import glob, urllib2
import os.path as P
import lxml.html as H
from db import MetaData,DBO
import linecache


def GetNsfocusVulDetails(Application,SingleTaskPath):
	# get all absolute file path in TaskPath
	iphtmls = glob.glob(SingleTaskPath + '/host/*.*.*.*.html')
	if not len(iphtmls):
		msg="---- Path has Nothing:\t%s Change directory..." % SingleTaskPath
		print msg
		SingleTaskPath=glob.glob(SingleTaskPath+'/*_html')[0]
		iphtmls = glob.glob(SingleTaskPath + '/host/*.*.*.*.html')
	
	#get scanner task info
	index = glob.glob(SingleTaskPath + '/index.html')[0]
	taskname = linecache.getline(index, 43).strip()[4:-5]
	taskdate=linecache.getline(index, 76).strip()[9:-6]
	
	
	for iphtml in iphtmls:
		IPfile = P.basename(iphtml)
		# if it is ip.html file
		if IPfile.count('.') == 4:
			IP = IPfile[:-5]
			DBO().add_host(Application,IP)
			## get html content
			content = urllib2.urlopen(url="file:" + iphtml).read()
			html = H.fromstring(content.decode('utf-8'))
			## todo:get more data from html
			vul_trs = html.xpath('//*[@id="vul_detail"]/table/tr')
			count = len(vul_trs) / 2
			for l in range(count):
				title_index = l * 2
				details_index = title_index + 1
				#
				data=MetaData().data
				# store all head data
				
				data[u"任务时间"] = taskdate
				data[u"报告名称"] = taskname
				data[u"IP"] = IP
				
				# get basic Data from html <title>
				data[u"ID"]=data[u"vulid"] = vul_trs[title_index].attrib["data-id"]  # nsfocus defined uniqe ID
				data[u"Port"] = vul_trs[title_index].attrib["data-port"]
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
				data[u"Port"] = PortInfo[0].text
				data[u"协议"] = PortInfo[1].text
				data[u"服务"] = PortInfo[2].text
				
				# get vul details Data
				vul_table = vul_trs[details_index].xpath('./td/table/tr')
				table={}
				for tr in vul_table:
					th = tr.xpath('./th')[0].text
					td = tr.xpath('./td')[0]
					# print IP, th
					table[th] = get_pure_text(td)
				
				data.update(table)
				# some replace fix
				if data[u"Port"] == "--":
					data[u"Port"] = "0"
				if data[u"服务"] == "--":
					data[u"服务"] = ""
				if data[u"等级"] =="low":
					data[u"等级"]="Low"
				elif data[u"等级"] =="middle":
					data[u"等级"]="Medium"
				if data[u"等级"] == "high":
					data[u"等级"] = "High"
					
				yield data
		print "IP:\t%s is done" % iphtml


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

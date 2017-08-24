#!/usr/bin/env python
# -*- coding: utf-8 -*-
# version 1.1 update by le @ 2017.7.6

import glob, urllib2
import os.path as P
import lxml.html as H
from db import MetaData, DBO
import linecache
from  gevent.pool import Pool
from gevent import monkey

monkey.patch_all()
import tempfile, zipfile, shutil


def GetNsfocusVulDetails(TaskID, Application, SingleZipPath):
	global APPLICATION, TASKID, taskname, taskdate, rsas_version  # global only use in function
	
	TASKID = TaskID.strip()
	APPLICATION = Application
	
	tmpTask = tempfile.mkdtemp(".tmp", "nsfocus_")  # 创建唯一的临时文件，避免冲突
	zipfile.ZipFile(SingleZipPath).extractall(path=tmpTask)
	# get all absolute file path in TaskPath
	iphtmls = glob.glob(tmpTask + '/host/*.*.*.*.html')
	if not len(iphtmls):
		msg = "---- Path has Nothing:\t%s Change directory..." % tmpTask
		print msg
		tmpTask = glob.glob(tmpTask + '/*_html')[0]
		iphtmls = glob.glob(tmpTask + '/host/*.*.*.*.html')
	
	# get scanner task info
	index_HTML = glob.glob(tmpTask + '/index.html')[0]
	taskname = linecache.getline(index_HTML, 43).strip()[4:-5]
	taskdate = linecache.getline(index_HTML, 76).strip()[9:-6]
	rsas_version = linecache.getline(index_HTML, 89).strip()[4:-5]
	
	pool = Pool(size=8)
	[pool.spawn(process_iphtml, iphtml) for iphtml in iphtmls]
	pool.join()

	# clean up
	shutil.rmtree(tmpTask)


def process_iphtml(iphtml):
	IPfile = P.basename(iphtml)
	IP = IPfile[:-5]
	DBO().add_host(APPLICATION, IP)
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
		data = MetaData().data
		
		# add more meta info
		data[u"TaskID"] = TASKID
		data[u"Scanner"] = "nsfocus"
		# store all head data
		
		data[u"任务时间"] = taskdate
		data[u"报告名称"] = taskname
		data[u"IP"] = IP
		
		# get basic Data from html <title>
		data[u"ID"] = data[u"vulid"] = vul_trs[title_index].attrib["data-id"]  # nsfocus defined uniqe ID
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
		
		## version diff
		if rsas_version == "V6.0R02F03SP02":  # some different
			PortXpath = '//*[@data-id="%s"]/../../../../td' % data["vulid"]
		else:  # V6.0R02F03
			PortXpath = '//*[@data-id="%s"]/../../../../../td' % data["vulid"]
		PortInfo = html.xpath(PortXpath)
		data[u"Port"] = PortInfo[0].text
		data[u"协议"] = PortInfo[1].text
		data[u"服务"] = PortInfo[2].text
		
		# get vul details Data
		vul_table = vul_trs[details_index].xpath('./td/table/tr')
		table = {}
		for tr in vul_table:
			th = tr.xpath('./th')[0].text
			td = tr.xpath('./td')[0]
			table[th] = get_pure_text(td)
			
			# ## debug td NoneType
			# try:
			# 	table[th] = get_pure_text(td)
			# except AttributeError:
			# 	print data[u"IP"], data[u"漏洞名称"], th
		
		data.update(table)
		# some replace fix
		if data[u"Port"] == "--":
			data[u"Port"] = "0"
		if data[u"服务"] == "--":
			data[u"服务"] = ""
		if data[u"等级"] == "low":
			data[u"等级"] = "Low"
		elif data[u"等级"] == "middle":
			data[u"等级"] = "Medium"
		if data[u"等级"] == "high":
			data[u"等级"] = "High"
		
		# store data
		DBO().add_vul(data)
	print "IP:\t%s is done" % P.basename(iphtml)
	

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
		if xpathElement is None: # sometimes is null
			return ""
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

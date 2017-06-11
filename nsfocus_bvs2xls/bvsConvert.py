#!/usr/bin/env python
# -*- coding: utf-8 -*-
# import need lib
import os
import os.path as P
import glob
import urllib2
import lxml.html as H
from xlwt import Workbook,easyxf



def task2sheet(WookBk,SingleTaskPath):
	## defile all need var in a sheet for output
	# var for export
	item = ''
	No1 = ''
	describ=''
	no2 = ''
	itm = ''
	valu = ''
	rul = ''
	base = ''
	confdoc = ''
	# store all output in a LiST
	aline = ['']*9
	# line number 0 as title  1 for data begin
	line = 1

	## set task name as sheet name 
	# get task name !!!! task name between _ don't have any excel not like char like [ ]
	names=SingleTaskPath.decode('gb2312').split('_')
	sheetname = names[1]
	sheet = WookBk.add_sheet(sheetname) 
	# print titiles			
	Titles = [u"序号",u"主机IP",u"业务系统",u"检查项",u"项序号",u"描述",u"点序号",u"检查点",u"获取值",u"匹配规则",u"标准值",u"参考配置方法",u"基线模板",u"备注"]
	for tit in Titles:
		# print Titles.index(tit)
		sheet.write(0,Titles.index(tit),tit,styleTitle)
	# get all absolute file path in TaskPath
	iphtmls = glob.glob(SingleTaskPath+'/*')
	for iphtml in iphtmls:
		bsname = P.basename(iphtml)
		# if it is ip.html file
		if bsname.count('.')==4:
			# ippath=P.join(taskpath,iphtml)
			ip=bsname.split('(')[0]

			## get html content
			f = urllib2.urlopen(url = "file:./"+iphtml)
			content = f.read()
			html = H.fromstring(content.decode('utf-8'))

			# get baseline name 
			h3 = html.xpath('//*[@id="content"]/div[4]/div[2]/div/div[1]')
			baselinename = h3[0].text
			# find main content
			trs = html.xpath('//*[@id="content"]/div[4]/div[2]/div/table/tr')
			# seq all man tr content 
			for tr in trs:
				# get all unaccord <tr> in one sub seq 
				if "unaccord" in str(tr.attrib):
					# refresh list
					# get main catlog
					if "hide" not in str(tr.attrib):
						tds = tr.xpath('./td')
						# key-value
						item1 = tds[0].text_content()
						if item1!=' ':item = item1
						No1 = tds[1].text_content()
						describ = tds[2].text_content()
						# store in aline for next refrence
						aline[0]=item
						aline[1]=No1
						aline[2]=describ
					# then do all sub catlog and detiles 
					else:
						tss = tr.xpath('./td[3]/div/table/tr[@class="unaccord"]')
						for ts in tss:
							ths=ts.xpath('./*')
							## seq append aline[]
							# don't get no2－－－GET ！
							no22 = ths[0].text_content()
							if no22.isdigit():
								no2 = no22
								for c in range(0,6):
									aline[c+3]=ths[c].text_content()##不获取小标号，获取内容向后偏移一位－－－Get!
							else:
								aline[3]=no2
								for c in range(0,5):
									aline[c+4]=ths[c].text_content()
							# key-value
							# itm = ths[1].text_content().encode('utf-8')
							# valu = ths[2].text_content().encode('utf-8')
							# rul = ths[3].text_content().encode('utf-8')
							# base = ths[4].text_content().encode('utf-8')
							# confdoc = ths[5].text_content().encode('utf-8')
							## seq all field and write a line 
							# print aline[8].encode('utf-8')
							## print all output 
							## print content					
							#print lineNO
							sheet.write(line,0,line,style0)
							# print ip
							sheet.write(line,1,ip,style0)
							# print all main content
							for a in range(0,len(aline)):#
								sheet.write(line,a+3,aline[a],style0)
							# print baseline at last
							sheet.write(line,len(aline)+3,baselinename,style0)
							line += 1
						# print item,'\t',No1,'\t',describ,'\t',no2,'\t',itm,'\t',valu,'\t',rul,'\t',base,'\t',confdoc
	print sheetname+"\tis done"



# define out write wookbook style
style0=easyxf('font: name Microsoft YaHei, height 180; align: vert centre') # wrap on
styleTitle=easyxf('font: name Microsoft YaHei, height 200; align: wrap on, vert centre, horiz center')
## seq all ip.html in some dir
# get report dir at same dir
for reportdir in os.listdir(os.getcwd()):
	if P.isdir(reportdir):
		xls = Workbook() 
		# get all task dir in a store file 
		print "[ Working on "+reportdir+" :]"
		for task in os.listdir(reportdir):
			taskpath = P.join(reportdir,task)
			task2sheet(xls,taskpath)
			# 单 sheet 保存？
		xls.save(reportdir+".xls")
		print "[ Save as "+reportdir+".xls ]\n"
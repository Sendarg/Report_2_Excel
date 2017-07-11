#!/usr/bin/env python
# -*- coding: utf-8 -*-
# version 0.1 update by le @ 2017.7.6

import xmltodict
from db import MetaData,DBO


def GetNessusVulDetails(Application,single_nessus_xml):
	xml = xmltodict.parse(single_nessus_xml)
	taskname = xml["NessusClientData_v2"]["Report"]["@name"]
	for host in xml["NessusClientData_v2"]["Report"]["ReportHost"]:
		hostAttrib = {}
		for tag in host["HostProperties"]["tag"]:  # turn list to dict
			hostAttrib[tag["@name"]] = tag['#text']
		# add host first
		DBO().add_host(Application,host["@name"])
		items=host["ReportItem"]
		if type(items)!=list:
			one=[]
			one.append(items)
			items=one
		for item in items:
			data = MetaData().data
			
			data[u"任务时间"] = hostAttrib["HOST_START"]
			data[u"结束时间"] = hostAttrib["HOST_END"]  # add
			data[u"报告名称"] = taskname
			
			data[u"OS类型"] = force_map(hostAttrib,"os")  # add
			data[u"OS"] = force_map(hostAttrib, "operating-system")  # add
			
			data[u"ID"] = item["@pluginID"]
			data[u"IP"] = host["@name"]
			data[u"详细描述"] = item["description"]
			data[u"应用"] = ""
			data[u"解决办法"] = item["solution"]
			data[u"威胁类别"] = item["plugin_type"]  # fix
			data[u"漏洞名称"] = item["plugin_name"]
			data[u"端口返回"] = force_map(item, "plugin_output")
			data[u"协议"] = item["@protocol"]
			data[u"服务"] = item["@svc_name"]
			data[u"Port"] = item["@port"]
			data[u"等级"] = item["risk_factor"]  # fix
			# more details
			data[u"发现日期"] = force_map(item, "vuln_publication_date")
			data[u"CVE编号"] = may_list2str(force_map(item, "cve"))
			data[u"CVSS评分"] = force_map(item, "cvss_base_score")  # fix
			data[u"CVSS3评分"] = force_map(item, "cvss3_base_score")  # add
			# only nsfocus
			data[u"威胁分值"] = ""
			data[u"危险插件"] = ""
			data[u"vulid"] = ""
			data[u"NSFOCUS"] = ""
			data[u"plgid"] = ""
			data[u"CNVD编号"] = ""
			data[u"CNNVD编号"] = ""
			data[u"CNCVE编号"] = ""
			data[u"BUGTRAQ"] = ""
			# only nessus
			data[u"pluginID"] = item["@pluginID"]
			data[u"pluginFamily"] = item["@pluginFamily"]
			data[u"plugin_publication_date"] = force_map(item, "plugin_publication_date")
			data[u"plugin_version"] = force_map(item, "script_version")
			data[u"see_also"] = force_map(item, "see_also")  # add
			data[u"synopsis"] = force_map(item, "synopsis")
			data[u"检测脚本"] = force_map(item, "fname")  # add
			data[u"metasploit"] = force_map(item, "metasploit_name")  # add
			data[u"xref"] = may_list2str(force_map(item, "xref"))  # add
			data[u"bid"] = may_list2str(force_map(item, "bid"))  # add
			data[u"osvdb"] = may_list2str(force_map(item, "osvdb"))  # add
			
			# fix data
			if not data[u"威胁分值"]:
				data[u"威胁分值"] = data[u"CVSS评分"]
			if data[u"Port"] == "--":
				data[u"Port"] = "0"
			if data[u"服务"] == "--":
				data[u"服务"] = ""
			if data[u"解决办法"] == "n/a":
				data[u"解决办法"] = ""
			
			yield data
		print "IP done:\t%s" % host["@name"]


def force_map(dict, key):
	if dict.has_key(key):
		return dict[key]
	else:
		return ""


def may_list2str(object):
	if type(object) == list:
		s = ",".join(object)
		return s
	else:
		return object

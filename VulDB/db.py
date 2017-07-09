#!/usr/bin/env python
# -*- coding: utf-8 -*-
# version 0.1 update by le @ 2017.7.6

from py2neo import Graph, Node, Relationship, NodeSelector


class MetaData(object):
	def __init__(self):
		self.data = {
			# task
			u"TaskID": "",  # 唯一任务ID，导入导出用，检查不可重复
			u"扫描器": "",
			# attrib
			u"任务时间": "",
			u"报告名称": "",  # nessus-reportname:"",nsfocus-taskname
			# vul details
			u"ID": "",  # 唯一ID:"",nsfocus-vulid:"",nessus-
			u"IP": "",
			u"详细描述": "",  # description
			u"CVE编号": "",  # cve
			u"应用": "",
			u"解决办法": "",  # solution
			u"威胁类别": "",
			u"威胁分值": "",
			u"漏洞名称": "",  # name:"",pluginName
			u"BUGTRAQ": "",
			u"端口返回": "",  # plugin_output
			u"协议": "",  # protocol:"",
			u"服务": "",
			u"端口": "",  # port
			u"等级": "",  # severity:"漏洞等级",
			u"发现日期": "",  # vuln_publication_date
			u"危险插件": "",
			u"CNVD编号": "",
			u"CNNVD编号": "",
			u"CNCVE编号": "",
			u"CVSS评分": "",  # cvss_base_score
			# mark-add
			u"误报": "",  # 常见经验:是不是误报
			u"误报原因": "",  # 常见误报原因:oracle:\ssh:\
			# nsfoucs
			u"vulid": "",
			u"NSFOCUS": "",
			u"plgid": "",
			# todo: review for all attrib in nessus
			u"svc_name": "",
			u"bid": "",
			u"pluginID": "",
			u"pluginFamily": "",
			u"plugin_publication_date": "",
			u"plugin_version": "",
			u"see_also": "",
			u"synopsis": "",
			u"xref": "",
		}


class DBO(object):
	# 初始化,连接后台数据库
	def __init__(self):
		self.graph = Graph(user='neo4j', password='neoXX00')
	
	def enum_vul(self, TaskID, Cypher_Conditions=None):
		""" enum vul by condition.
        :param labels: node labels to match
        :param condition: .where("_.name =~ 'J.*'", "1960 <= _.born < 1970"); "_.Port='%s'"
        :return: :py:list
        """
		selector = NodeSelector(self.graph)
		if Cypher_Conditions:
			# selector.select.where not good for use , not support zh_cn just pure cypher
			cypher = 'MATCH (n:HostVul) where n.TaskID="07091" and %s RETURN n ' % Cypher_Conditions
			for data in self.graph.data(cypher):
				yield data["n"]
		else:
			selected = selector.select("HostVul", TaskID=TaskID)
			for data in list(selected):
				yield data
	
	def add_vul(self, Department, Vul_Data):
		Host_IP = Vul_Data[u"IP"]
		if not self.graph.find_one("Host", "IP", Host_IP):
			self.add_host(Department, Host_IP)
		
		# uniq = Vul_Data[u"IP"] + "^^^" + Vul_Data[u"端口"] + "^^^" + Vul_Data[u"ID"]
		if len(self.HostVul_exists(Vul_Data)) == 0:
			Host = self.graph.find_one("Host", "IP", Host_IP)
			vul = Node("HostVul")
			vul.update(Vul_Data)
			rel = Relationship(Host, "have", vul)
			self.graph.create(rel)
		# print "Created\t%s" % uniq
		else:
			# print "Exists\t%s" % uniq
			pass
	
	def HostVul_exists(self, Vul_Data):
		selector = NodeSelector(self.graph)
		selected = selector.select("HostVul", IP=Vul_Data[u"IP"], Port=Vul_Data[u"端口"], ID=Vul_Data[u"ID"])
		# .where("_.IP = '%s'" % Vul_Data[u"IP"],
		#                                        "_.Port='%s'" % Vul_Data[u"端口"],
		#                                        "_.ID='%s'" % Vul_Data[u"ID"])
		vul = list(selected)
		return vul
	
	def add_host(self, Department, host):
		self.node_simple_add("Host", "IP", host)
		host = self.graph.find_one("Host", "IP", host)
		dep = self.graph.find_one("Department", "name", Department)
		self.rel_simple_add(dep, "own", host)
	
	def add_department(self, Project, Department):
		self.node_simple_add("Project", "name", Project)
		self.node_simple_add("Department", "name", Department)
		
		pro = self.graph.find_one("Project", property_key="name", property_value=Project)
		dep = self.graph.find_one("Department", property_key="name", property_value=Department)
		self.rel_simple_add(pro, "own", dep)
	
	### meta operate
	def node_exists(self, label, Key, Value):
		Find = self.graph.find_one(label, property_key=Key, property_value=Value)
		if Find:
			print "Node %s already exists" % Find[Key]
			return 2
		else:
			return 0
	
	def node_simple_add(self, label, Key, Value):
		Find = self.graph.find_one(label, property_key=Key, property_value=Value)
		if Find:
			print "Node %s already exists" % Find[Key]
			return 2
		else:
			n = Node(label)
			n.update({Key: Value})
			self.graph.create(n)
			return 1
	
	def rel_exists(self, start_node, rel, end_node):
		Find = self.graph.match_one(start_node=start_node, rel_type=rel, end_node=end_node)
		if type(Find) == Relationship:
			print "Relationship already exists"
			return 2
		else:
			return 0
	
	def rel_simple_add(self, start_node, rel_type, end_node):
		Find = self.graph.match_one(start_node=start_node, rel_type=rel_type, end_node=end_node)
		if type(Find) == Relationship:
			print "Relationship already exists"
			return 2
		else:
			rel = Relationship(start_node, rel_type, end_node)
			self.graph.create(rel)
			return 1
	
	##############
	
	
	def modify_node(self, req, label=None):
		REQ = self.graph.find_one(label, property_key="name", property_value=req['name'])
		if REQ:
			REQ.update(req)
			self.graph.push(REQ)
	
	def get_node_by_name(self, name, label=None):
		REQ = self.graph.find_one(label, property_key="name", property_value=name)
		if REQ:
			return REQ
	
	def get_label_by_node(self, node):
		label = []
		for i in node.labels():
			label.append(i)
		return label
	
	def get_relationship_by_node(self, rel=None, start_node=None, end_node=None):
		relation = self.graph.match_one(start_node=start_node, rel_type=rel, end_node=end_node)
		return relation
	
	def delete_relationship_by_node(self, rel=None, start_node=None, end_node=None):
		relation = self.graph.match_one(start_node=start_node, rel_type=rel, end_node=end_node)
		self.graph.delete(relation)
	
	def delete_node_by_name(self, name, label=None):
		REQ = self.graph.find_one(label, property_key="name", property_value=name)
		self.graph.delete(REQ)
	
	def add_relationship_by_node(self, a, relationship, b):
		new = Relationship(a, relationship, b)
		self.graph.create(new)
	
	def remove_properity_by_name(self, NodeName, PropName, label=None):
		n = self.graph.find_one(label, property_key="name", property_value=NodeName)
		n["%s" % PropName] = None
		n.update(n)
		n.push()

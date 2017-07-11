#!/usr/bin/env python
# -*- coding: utf-8 -*-
# version 1.0 update by le @ 2017.7.6

from db import DBO

Rules = {}
# "类型":"查询条件","原因","证明材料"# detail prove information
Rules[u"Oracle"] = [
	u' v.漏洞名称 =~ "^Oracle 20.*漏洞.*" or  v.漏洞名称 =~ "^Oracle Data.*漏洞.*" or  v.漏洞名称 =~ "^Oracle数据库.*漏洞.*"  or  v.漏洞名称 =~ "^Oracle.*组件.*漏洞.*"',
	u"不精确的版本判断", '']
Rules[u"MySQL"] = [u' v.漏洞名称 =~ "^MySQL.*漏洞.*" or v.漏洞名称 =~ "^Oracle MySQL.*漏洞.*" ', u"不精确的版本判断", '']
Rules[u"OpenSSH"] = [u' lower(v.漏洞名称) =~ "^openssh.*漏洞.*" ', u"不精确的版本判断", '']
Rules[u"IBM"] = [u' v.漏洞名称 = "IBM AIX TCP Large Send Denial of Service Vulnerability" ', u"不支持识别厂家补丁版本", '']


def mark_false():
	for r in Rules.iteritems():
		print "= Process rule:\t\t%s" % (r[0])
		cypher = u"match(v:HostVul) where %s" % r[1][0]
		cypher += u' set v.误报="可能", v.误报类型="%s", v.误报原因="%s"' % (r[0], r[1][1])
		
		run = DBO().graph.run(cypher)
		num = run.stats()['properties_set']
		print "+ Marked Oracle:\t%s" % num
	print "== Mark Complated!"


def clean_mark():
	cypher = u'match(v:HostVul) where v.误报="可能" set v.误报="", v.误报类型="", v.误报原因=""'
	DBO().graph.run(cypher)


if __name__ == '__main__':
	mark_false()

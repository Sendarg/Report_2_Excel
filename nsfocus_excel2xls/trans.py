# -*- coding: utf-8 -*-
from  trans_sheet_4 import trans


path_=u'.\\全部漏洞信息.xls'


import glob
files = glob.glob(path_)



#
##保存生产文件
# 报告文件，过滤关键字
book=trans(files)



book.save(u'tmp1.xls')





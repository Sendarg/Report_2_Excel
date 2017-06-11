# -*- coding: utf-8 -*-
from  trans_sheet import trans
from os import path

paths="report"
## 方法一 : 获得路径  但出现解数组和组装数组的问题
#files=listdir(path_)
#filePath=[0]
#for name in files:
#    filePa=path.join(path_,name)
#    filePath.append(filePa)
#
#filePath.remove(0)

# 方法二 ；  中文编码有问题
import glob
files=[]
for file in glob.glob1(paths,"*.xls"):
        files.append(path.join(paths,file))

#
##保存生产文件
# 报告文件，过滤关键字
# book=trans(files,'SSL')
book=trans(files)
book.save(u'tmp.xls')





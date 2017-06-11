# -*- coding: utf-8 -*-

'''
Created on 2012-11-6
Modified by Lele @ 2016-02-22
convert BS edition venus detail host report to isca report
！！！
原版功能（制作出全部信息的详尽xls）具体化：筛选以某个关键词得到漏洞名称
的全部信息
@author: Lele
'''

def trans(reportfile,keyword=''):
    import xlrd
    from os import path
    from xlwt import Workbook,easyxf
    
    #最后样式
    style0=easyxf('font: name Microsoft YaHei,height 180')
    red=easyxf('pattern: pattern solid, fore_colour red;font: name Microsoft YaHei,height 180')
    yel=easyxf('pattern: pattern solid, fore_colour yellow;font: name Microsoft YaHei,height 180')
    
    # 输出处理 sheet
    book = Workbook()
    # 首页统计数目
    count=book.add_sheet(u'首页')
    for xlsPath in reportfile:
        print "==== Processing %s ===="%xlsPath
        # read report xls file 
        data = xlrd.open_workbook(xlsPath)
        sheet = data.sheet_by_name(u'漏洞详细')
        rows=sheet.nrows #行数
        bs=16 #bs为一个漏洞详细块的行数
        line=(rows+(bs-6))/bs-1 # 条目数   N-M,M为行前的无效行数 /N为一个漏洞详细块的行数 ，最终需要减去一个无效块
        ## output sheet      
        # 获取文件名 排除路径和后准名
        sheet_name=path.basename(xlsPath)
        she= book.add_sheet(sheet_name,1)
        j=0 #初始化行号
        # 循环读取并转换位置并写入新sheet
        for i in range(line):
            # 获取所需各列原始数据
            v=i*bs+6 #/+X为整体行中名称的偏移
            vlu = sheet.cell_value(v,4).replace(u'● ', '') #脆弱点名称 # 删除名称中的特殊字符
            h=i*bs+16
            host=sheet.cell_value(h,5)#主机
            # 详细信息
            c=i*bs+8
            category=sheet.cell_value(c,5)#漏洞分类
            lv=i*bs+9
            level=sheet.cell_value(lv,5)#漏洞等级
            p=i*bs+10
            effPlantform=sheet.cell_value(p,5)#影响平台
            cv=i*bs+11
            cvss=float(sheet.cell_value(cv,5))#漏洞评分 #mdf
            ce=i*bs+13
            cve=sheet.cell_value(ce,5)#cve编号 #add
            simp=i*bs+17
            simpleDesc=sheet.cell_value(simp,5)#简单描述 #mdf
            detil=i*bs+18
            detailDesc=sheet.cell_value(detil,5)#详细描述 #mdf
            fix=i*bs+19
            fixSuggest=sheet.cell_value(fix,5)#修补建议 #mdf
            url=i*bs+20
            urlRelated=sheet.cell_value(url,5)#参考网址 #add
            ## 细节处理控制
            # 0、处理关键字
            if keyword in vlu or keyword =='':
    #            # 1、遇到低等级跳出
    #            if (level =="低"):
    #                break
                # 2、ip拆分为单个写入
                #每个IP后面2个空格一个TAB间隔
                hosts=host.strip().replace(u"　","").replace(u"  "," ").split()
                for host_one in hosts:
                    # 3、写入sheet    
                    ran = [host_one.strip(),vlu,category,effPlantform,simpleDesc,detailDesc,fixSuggest,urlRelated,level,cvss]
                    for col in ran:
                        # 高中等级标色 需识别 为该等级列、等级值
                        #重置 样式
                        style=style0 
                        if (level==u'高危险' and col==level):
                            style=red                        
                        if (level==u'中危险' and col==level):
                            style=yel
                        she.write(j,ran.index(col),col,style)                                                         
                    j += 1
        ## 在首页写入各项总行数：总漏洞数目
        #行号
        rownum=reportfile.index(xlsPath)+6 #首页放置位置偏移
        count.write(rownum,3,sheet_name)
        count.write(rownum,4,j)
    return book
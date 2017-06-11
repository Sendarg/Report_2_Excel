# -*- coding: utf-8 -*-


def trans(reportfile):
    import xlrd
    from xlwt import Workbook
    
    # 输出处理 sheet
    book = Workbook()
    m=0
    j=0
    host=""
    vlu=""
    detils=""
    solu=""
    wxfz=""
    wxcj=""
    date=""
    cve=""
    cncve=""
    cvss=""

    for xlsPath in reportfile:        
        # read report xls file 
        data = xlrd.open_workbook(xlsPath)
        sheet = data.sheet_by_name(u'Sheet1')
        rows=sheet.nrows #行数
        cols=sheet.ncols

        she= book.add_sheet(u'Name',0)        
        # 循环读取并转换位置并写入新sheet
        while 1:
            for i in range(j,rows):
                field = sheet.cell_value(i,0)
                field2 = sheet.cell_value(i,1)
                if (field==u"受影响主机") :
                    host = field2#主机
                    vlu=sheet.cell_value(i-1,0)
                if (field==u"详细描述") :
                    for o in range(1,1000):
                        detils3=sheet.cell_value(i+o,1)
                        mark=sheet.cell_value(i+o,0)
                        if (mark==u"解决办法"):
                            break                              
                        if (detils3!=""):
                            field2 += "\n"
                            field2 += unicode(detils3)
                    detils=field2.replace(u"NSFOCUS","")
                if (field==u"解决办法") :
                    for o in range(1,1000):
                        solu3=sheet.cell_value(i+o,1)
                        mark=sheet.cell_value(i+o,0)
                        if (mark==u"威胁分值"):
                            break                              
                        if (solu3!=""):
                            field2 += "\n"
                            field2 += unicode(solu3)
                    solu=field2.replace(u"NSFOCUS","")
                if (field==u"威胁分值") :wxfz = field2#主机
                if (field==u"危险插件") :wxcj = field2#主机
                if (field==u"发布日期") :date = field2#主机
                if (field==u"CVE编号") :cve = field2#主机
                if (field==u"CNCVE编号") :cncve = field2#主机
                if (field==u"CVSS评分") :
                    cvss = field2#主机
                    j=i+1
                    break

            # hosts=host.split(u" ")
            # for host_one in hosts:
            #     # 3、写入sheet    
            #     ran2 = [host_one,vlu,detils,solu,wxfz,wxcj,date,cve,cncve,cvss]
            #     for c in range(10):
            #         c2=ran2[c]
            #         # m2=ran2.index(c)
            #         she.write(m,c,c2)   
            #     # for c in ran2:
            #     #     c2=ran2.index[c]
            #     #     # m2=ran2.index(c)
            #     #     she.write(m,c2,c)                                                         
            #     m += 1

            ## 不要IP
            ran2 = [vlu,detils,solu,wxfz,wxcj,date,cve,cncve,cvss]
            for c in range(9):
                c2=ran2[c]
                she.write(m,c,c2)                                                          
            m += 1
            if (j==rows-1):
                break
    return book
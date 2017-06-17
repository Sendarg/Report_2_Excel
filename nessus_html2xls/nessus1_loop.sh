#!/bin/bash
#
#vision0.1
#jisen20150115
#

#标题行输出到标题文件
sed -n '/Vulnerabilities By Plugin<\/h1>/,$'p $1 |grep 'class="classsection'|awk -F"<h2" '{print $2}'|awk -F">" '{print $2}'>title.txt

#处理标题文件
sed -i 's#\/#\\\\/#g' title.txt
result="result_"`echo $1|cut -d'/' -f2 `".txt"
if [ -f ${result} ];then
   rm -f ${result}
fi

#取标题数量
TITLENUM=`cat title.txt|wc -l`

#count num 
COUNTNUM=0

while read line
do
#取标题
 ATITLE=${line%<*}
 TITLE=${ATITLE%%\'*}
 linshiT=${line:0:5}
 linshiNT=`awk '/'$linshiT'/{a=NR+1}a==NR' title.txt`
 ANEXTTITLE=${linshiNT%<*}
 BNEXTTITLE=${ANEXTTITLE%%\'*}
 NEXTTITLE=${BNEXTTITLE%%\\*}
#echo "$TITLE"
#echo "$NEXTTITLE"
#echo "================="

#取风险值
 RISK=`sed -n '/Vulnerabilities By Plugin<\/h1>/,$'p $1 |sed -n '/'"$TITLE"'/,/'"$NEXTTITLE"'/'p |awk '/Risk Factor/{a=NR+1}a==NR'|awk -F">" '{print $2}'|awk -F"<" '{print $1}'`
#echo "$RISK"

 if [ "${RISK}" = "Critical" ];then
    RISKRESULT="Critical"
 elif [ "${RISK}" = "High" ];then
    RISKRESULT="High"
 elif [ "${RISK}" = "Medium" ];then
    RISKRESULT="Medium"
 elif [ "${RISK}" = "Low" ];then
    RISKRESULT="Low"
 else
    RISKRESULT="None"
 fi

#若风险值为低则不再继续循环
# if [ "${RISKRESULT}" = "None" ];then
#    break;
# fi

#取概要
 sed -n '/Vulnerabilities By Plugin<\/h1>/,$'p $1 |sed -n '/'"$TITLE"'/,/'"$NEXTTITLE"'/'p |sed -n '/>Synopsis</,/>Description</'p|grep -v -e ">Synopsis<" -e ">Description<"|awk -F"span>" '{print $1}'|sed 's/<br>//g'|awk -F">" '{print $2}' |awk -F"<" '{print $1}'|sed '/^$/d' >tmpSynopsis.txt
 dos2unix tmpSynopsis.txt
 sed -i 's/\\/#/g' tmpSynopsis.txt
 SYNOPSIS=`cat tmpSynopsis.txt|tr "\t" " "|tr "\r" " "|sed '/^$/d'|sed 's/\*/(\*)/g'|tr "\n" " ";echo`

#取描述
 sed -n '/Vulnerabilities By Plugin<\/h1>/,$'p $1 |sed -n '/'"$TITLE"'/,/'"$NEXTTITLE"'/'p |sed -n '/>Description</,/>Solution</'p |grep -v -e ">Solution<" -e ">See Also<" -e ">Description<"|awk -F"span>" '{print $1}'|sed 's/<br>//g'|awk -F">" '{print $2}' |awk -F"<" '{print $1}'|sed '/^$/d'>tmpmiaoshu.txt
 dos2unix tmpmiaoshu.txt
 sed -i 's/\\/#/g' tmpmiaoshu.txt
 XXMS=`cat tmpmiaoshu.txt|tr "\t" " "|tr "\r" " "|sed '/^$/d'|sed 's/\*/(\*)/g'|tr "\n" " ";echo`
#echo "$XXMS"
#echo "========================="

#取解决方法
 sed -n '/Vulnerabilities By Plugin<\/h1>/,$'p $1 |sed -n '/'"$TITLE"'/,/'"$NEXTTITLE"'/'p |sed -n '/>Solution</,/>Risk Factor</'p |grep -v -e ">Risk Factor<" -e ">Solution<" |awk -F"span>" '{print $1}'|sed 's/<br>//g'|awk -F">" '{print $2}' |awk -F"<" '{print $1}'>tmpfangfa.txt
 dos2unix tmpfangfa.txt
 sed -i 's/\\/#/g' tmpfangfa.txt
 JJFF=`cat tmpfangfa.txt|tr "\t" " "|tr "\r" " "|sed '/^$/d'|sed 's/\*/(\*)/g'|tr "\n" " ";echo`
#echo "$JJFF"
#echo "############################"

#取插件信息
 sed -n '/Vulnerabilities By Plugin<\/h1>/,$'p $1 |sed -n '/'"$TITLE"'/,/'"$NEXTTITLE"'/'p |sed -n '/>Plugin Information: </,/>Hosts</'p|grep -v -e ">Plugin Information: <" -e ">Hosts<"|awk -F"span>" '{print $1}'|sed 's/<br>//g'|awk -F">" '{print $2}' |awk -F"<" '{print $1}'>tmpPluginInfo.txt
 dos2unix tmpPluginInfo.txt
 sed -i 's/\\/#/g' tmpPluginInfo.txt
 PINFO=`cat tmpPluginInfo.txt|tr "\t" " "|tr "\r" " "|sed '/^$/d'|sed 's/\*/(\*)/g'|tr "\n" " ";echo`

#取地址组
 sed -n '/Vulnerabilities By Plugin<\/h1>/,$'p $1 |sed -n '/'"$TITLE"'/,/'"$NEXTTITLE"'/'p |sed -n '/>Hosts</,/'"$NEXTTITLE"'/'p |grep -v -e "${NEXTTITLE}" -e ">Hosts<" |awk -F"<h2" '{print $2}'|awk -F">" '{print $2}'|awk -F"<" '{print $1}'|sed 's/ //g' |sed '/^$/d' >tmpip.txt
 dos2unix tmpip.txt

#取CVE
 sed -n '/Vulnerabilities By Plugin<\/h1>/,$'p $1 |sed -n '/'"$TITLE"'/,/'"$NEXTTITLE"'/'p |sed -n '/>Risk Factor</,/>Plugin Information: </'p |grep ">CVE-"|awk -F">" '{print $3}'|awk -F"<" '{print $1}'>tmpcve.txt
 dos2unix tmpcve.txt
 CVELIST=`cat tmpcve.txt|tr "\n" " ";echo`

#
#
#根据ip结果正式输出至临时文件
let COUNTNUM=COUNTNUM+1
if [ "$COUNTNUM" -ne "$TITLENUM" ];then
 for ADDIP in `cut -f 1 tmpip.txt`
 do
 echo -e "${ADDIP}\t${ATITLE}\t${CVELIST}\t${SYNOPSIS}\t${XXMS}\t${RISKRESULT}\t${JJFF}\t${PINFO}">>${result}
 done
else
#################
##last one     ##
#################
 #取概要
 sed -n '/Vulnerabilities By Plugin<\/h1>/,$'p $1 |sed -n '/'"$TITLE"'/,/This is a report from the/'p |sed -n '/>Synopsis</,/>Description</'p|grep -v -e ">Synopsis<" -e ">Description<"|awk -F"span>" '{print $1}'|sed 's/<br>//g'|awk -F">" '{print $2}' |awk -F"<" '{print $1}'|sed '/^$/d' >lasttmpSynopsis.txt
 dos2unix lasttmpSynopsis.txt
 sed -i 's/\\/#/g' lasttmpSynopsis.txt
 LASTSYNOPSIS=`cat lasttmpSynopsis.txt|tr "\t" " "|tr "\r" " "|sed '/^$/d'|sed 's/\*/(\*)/g'|tr "\n" " ";echo`

#取描述
 sed -n '/Vulnerabilities By Plugin<\/h1>/,$'p $1 |sed -n '/'"$TITLE"'/,/This is a report from the/'p |sed -n '/>Description</,/>Solution</'p |grep -v -e ">Solution<" -e ">See Also<" -e ">Description<"|awk -F"span>" '{print $1}'|sed 's/<br>//g'|awk -F">" '{print $2}' |awk -F"<" '{print $1}'|sed '/^$/d'>lasttmpmiaoshu.txt
 dos2unix lasttmpmiaoshu.txt
 sed -i 's/\\/#/g' lasttmpmiaoshu.txt
 LASTXXMS=`cat lasttmpmiaoshu.txt|tr "\t" " "|tr "\r" " "|sed '/^$/d'|sed 's/\*/(\*)/g'|tr "\n" " ";echo`

#取解决方法
 sed -n '/Vulnerabilities By Plugin<\/h1>/,$'p $1 |sed -n '/'"$TITLE"'/,/This is a report from the/'p |sed -n '/>Solution</,/>Risk Factor</'p |grep -v -e ">Risk Factor<" -e ">Solution<" |awk -F"span>" '{print $1}'|sed 's/<br>//g'|awk -F">" '{print $2}' |awk -F"<" '{print $1}'>lasttmpfangfa.txt
 dos2unix lasttmpfangfa.txt
 sed -i 's/\\/#/g' lasttmpfangfa.txt
 LASTJJFF=`cat lasttmpfangfa.txt|tr "\t" " "|tr "\r" " "|sed '/^$/d'|sed 's/\*/(\*)/g'|tr "\n" " ";echo`

#取插件信息
 sed -n '/Vulnerabilities By Plugin<\/h1>/,$'p $1 |sed -n '/'"$TITLE"'/,/This is a report from the/'p |sed -n '/>Plugin Information: </,/>Hosts</'p|grep -v -e ">Plugin Information: <" -e ">Hosts<"|awk -F"span>" '{print $1}'|sed 's/<br>//g'|awk -F">" '{print $2}' |awk -F"<" '{print $1}'>lasttmpPluginInfo.txt
 dos2unix lasttmpPluginInfo.txt
 sed -i 's/\\/#/g' lasttmpPluginInfo.txt
 LASTPINFO=`cat lasttmpPluginInfo.txt|tr "\t" " "|tr "\r" " "|sed '/^$/d'|sed 's/\*/(\*)/g'|tr "\n" " ";echo`

#取地址组
 sed -n '/Vulnerabilities By Plugin<\/h1>/,$'p $1 |sed -n '/'"$TITLE"'/,/This is a report from the/'p |sed -n '/>Hosts</,/This is a report from the/'p |grep -v -e "This is a report from the" -e ">Hosts<" |awk -F"<h2" '{print $2}'|awk -F">" '{print $2}'|awk -F"<" '{print $1}'|sed 's/ //g' |sed '/^$/d' >lasttmpip.txt
 dos2unix lasttmpip.txt

#取CVE
 sed -n '/Vulnerabilities By Plugin<\/h1>/,$'p $1 |sed -n '/'"$TITLE"'/,/This is a report from the/'p |sed -n '/>Risk Factor</,/>Plugin Information: </'p |grep ">CVE-"|awk -F">" '{print $3}'|awk -F"<" '{print $1}'>lasttmpcve.txt
 dos2unix lasttmpcve.txt
 LASTCVELIST=`cat lasttmpcve.txt|tr "\n" " ";echo`

#
 for ADDIP in `cut -f 1 lasttmpip.txt`
 do
 echo -e "${ADDIP}\t${ATITLE}\t${LASTCVELIST}\t${LASTSYNOPSIS}\t${LASTXXMS}\t${LASTRISKRESULT}\t${LASTJJFF}\t${LASTPINFO}">>${result}
 done

fi

done<title.txt
rm -rf last*.txt title.txt tmpip.txt tmpSynopsis.txt tmpfangfa.txt tmpPluginInfo.txt tmpmiaoshu.txt tmpcve.txt

exit 0

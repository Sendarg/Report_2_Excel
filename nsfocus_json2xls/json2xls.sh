#!/usr/bin/env bash

rm vuls.txt ports.txt all.txt

## 性能太差，可能是1w以上量的区块统计、索引、multipli太耗时间。
## 准备分不同的目录单独进行乘法计算，最后合并


jq  '.data.report|{k:.task.name,t:.targets[]}|[{k,ip:.t.ip,v:.t.vuln_detail[]}]|sort_by(.v.vul_id)|.[]' -r */*.json>> vuls.txt
jq  '.data.report|{k:.task.name,t:.targets[]}|[{k,ip:.t.ip,v:.t.vuln_scanned[]}]|sort_by(.v.vul_id)|.[]' -r */*.json>> ports.txt

L=`jq 'length' -s vuls.txt`

for l in $(seq 0 $[$L-1])
do
jq '.['$l'] * .['$l'+'$L']' -s vuls.txt ports.txt >> all.txt;
done

echo "任务,IP地址,NSFOCUS,详细描述,CVE编号,应用,解决办法,威胁类别,威胁分值,漏洞名称,vulid,BUGTRAQ
,plgid,端口返回,协议,服务,端口号">all.csv
jq '[.k,.ip,.v[]]|@csv' -r all.txt >> all.csv

enca -x gb18030 all.csv

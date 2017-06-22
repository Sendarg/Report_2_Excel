## 说明
Trans nsfocus scanner html report to excel files
转换绿盟rsas漏洞扫描器的html报告为单独的excel文件。
Excel中包含每一条漏洞的唯一数据，以便进行详细整理、跟踪变化、分发协作。
## 环境
1、安装python环境 [https://www.python.org/downloads/][1]
2、安装依赖库 	`pip install requirements.txt` 

## 使用方法
1. 在扫描器中生成扫描任务html报告（含主机报表）
2. 解压后放入当前目录
3. 直接运行ConvertHtml.py即可  `python ConvertHtml.py`
4. 本地生成（与扫描报告目录）同名的xlsx文件，即为目标数据

[1]:	https://www.python.org/downloads/


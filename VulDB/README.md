# 很很简单的漏洞管理系统
## 背景
这些实际的原因找不到什么可以真正能说的出来的，要能说出的来怕是只有一个，那就是帮助某些项目、某些人，让他有时间去做更重要的事情。

真需要说点什么意义，可能需要把漏洞数据全部关联起来才有点普遍价值吧。目前只是实现了一个很简单的功能，想法还很遥远。
## 依赖
* Neo4j数据库
    * 官方下载安装
    * 在Neoj4j控制台设置密码 :  [http://127.0.0.1:7474](http://127.0.0.1:7474)
    * 在`db.py`中修改为数据库密码:`self.graph = Graph(user='neo4j', password='neo4j')`    
* Python2.7
    * 官方下载安装
    * 安装该项目的依赖库  `pip install -r requirements.txt `
## 使用说明
1. 将支持的报告原始数据导入到数据库中，支持参数详见`import.py`
    * 当前支持:Nessus的输出.nessus格式、绿盟rsas的输出html压缩包
    * 可以指定报告所属项目、部门、系统  
    * 示例:  `python import.py -t test01 -p project1 -d department1 -a app1  --nessus 1.nessus 2.nessus --nsfocus 2_html.zip 3_html.zip`
2. 自定义输出模板，参考`template_default.xlsx`
    * 模板中支持的数据字段见`export.py -c`输出
    * 默认使用预定义模板
    * 支持过滤器，见`export.py`中的`Filters`定义，当前支持可选: 全部漏洞、可整改漏洞、高风险漏洞、排除误报的漏洞。也可自己编写筛选
    *  示例:  `python export.py -t test01 -f high_risk`
3. 标识误报，参见`mark_false_negative.py`
    * 识别误报的规则见`Rules`定义
    * 当前支持识别扫描器常见误报，如Oracle、SSH、MySQL、IBM
## 结语
这近一个月的疲惫不堪，荒废了其它全部，忙碌中未曾有兴奋点，偶见凌晨暴雨过后的耀眼明月，也是惊艳到我了，成为唯一的记忆锚点。

能挤时间编写一些代码去解救某人的那么多时间也算是一个小小的欣慰了。
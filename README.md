# HackLog4j

本项目用来致敬全宇宙最无敌的Java日志库！同时也记录自己在学习Log4j漏洞过程中遇到的一些内容。本项目会持续更新，本项目创建于2021年12月10日，最近的一次更新时间为2021年12月11日。作者：[0e0w](https://github.com/0e0w/HackLog4j)

- [01-Log4j基础知识](https://github.com/0e0w/HackLog4j#01-log4j%E5%9F%BA%E7%A1%80%E7%9F%A5%E8%AF%86)
- [02-Log4j框架识别](https://github.com/0e0w/HackLog4j#02-log4j%E6%A1%86%E6%9E%B6%E8%AF%86%E5%88%AB)
- [03-Log4j上层建筑](https://github.com/0e0w/HackLog4j#03-log4j%E4%B8%8A%E5%B1%82%E5%BB%BA%E7%AD%91)
- [04-Log4j漏洞汇总](https://github.com/0e0w/HackLog4j#04-log4j%E6%BC%8F%E6%B4%9E%E6%B1%87%E6%80%BB)
- [05-Log4j漏洞利用](https://github.com/0e0w/HackLog4j#05-log4j%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8)
- [06-Log4j分析文章](https://github.com/0e0w/HackLog4j#06-log4j%E5%88%86%E6%9E%90%E6%96%87%E7%AB%A0)
- [07-Log4j靶场环境](https://github.com/0e0w/HackLog4j#07-log4j%E9%9D%B6%E5%9C%BA%E7%8E%AF%E5%A2%83)

## 01-Log4j基础知识
- https://github.com/apache/logging-log4j2

## 02-Log4j框架识别

- 待更新

## 03-Log4j上层建筑

**log4j + ？ = rce ！**

- Apache Flink
- Apache Struts2
- flume
- dubbo
- Redis
- logstash
- ElasticSearch
- kafka
- ghidra
- Spring-Boot-strater-log4j2
- 我的世界（Minecraft）
- ......
- https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core/usages
- https://github.com/YfryTchsGD/Log4jAttackSurface
- https://github.com/CrackerCat/Log4jAttackSurface

## 04-Log4j漏洞汇总

- CVE-2021-44228
- CVE-2019-17571
- CVE-2017-5645

## 05-Log4j漏洞利用

- https://github.com/bit4woo/log4jScan
- https://github.com/whwlsfb/Log4j2Scan
- https://github.com/Yihsiwei/Log4j-exp
- https://github.com/FrankHeijden/Log4jFix
- https://github.com/simonis/Log4jPatch
- https://github.com/Szczurowsky/Log4j-0Day-Fix
- https://github.com/Anonymous-ghost/log4jVul
- https://github.com/SumoLogic/sumologic-log4j2-appender
- https://github.com/chaitin/log4j2-vaccine
- https://github.com/ilsubyeega/log4j2-exploits
- https://github.com/rz7d/log4j-force-upgrader
- https://github.com/xsser/log4jdemoforRCE
- https://github.com/zhangyoufu/log4j2-without-jndi
- https://github.com/Cyronlee/log4j-rce
- https://github.com/CreeperHost/Log4jPatcher
- https://github.com/notrhys/Log-4J-Exploit-Fix
- https://github.com/Re1own/Apache-log4j-POC
- https://github.com/boundaryx/cloudrasp-log4j2
- https://github.com/jas502n/Log4j2-CVE-2021-44228
- https://github.com/ChloePrime/fix4log4j
- https://github.com/toString122/log4j2_exp
- https://github.com/shanfenglan/apache_log4j_poc
- https://github.com/dbgee/CVE-2021-44228
- https://github.com/lcosmos/apache-log4j-poc
- https://github.com/DichuuCraft/LOG4J2-3201-fix
- https://github.com/dbgee/CVE-2021-44228
- https://github.com/lcosmos/apache-log4j-poc
- https://github.com/DichuuCraft/LOG4J2-3201-fix
- https://github.com/dbgee/log4j2_rce
- https://github.com/ReadER-L/log4j-rce
- https://github.com/HyCraftHD/Log4J-RCE-Proof-Of-Concept
- https://github.com/Seayon/Log4j2RCE_Demo
- https://github.com/elbosso/Log4J2CustomJMXAppender
- https://github.com/ahus1/logging-and-tracing
- https://github.com/stuartwdouglas/log4j-jndi-agent
- https://github.com/xiajun325/apache-log4j-rce-poc
- https://github.com/caoli5288/log4j2jndiinterceptor
- https://github.com/y35uishere/Log4j2-CVE-2021-44228
- https://github.com/ErdbeerbaerLP/log4jfix
- https://github.com/0x0021h/apache-log4j-rce
- https://github.com/Gav06/RceFix
- https://github.com/UltraVanilla/LogJackFix
- https://github.com/iamsino/log4j2-Exp
- https://github.com/bkfish/Apache-Log4j-Learning
- https://github.com/LoliKingdom/NukeJndiLookupFromLog4j
- https://github.com/tangxiaofeng7/apache-log4j-poc
- https://github.com/h1b1ki/apache-log4j-poc
- https://github.com/EmptyIrony/Log4j2Fixer
- https://github.com/AzisabaNetwork/Log4j2Fix
- https://github.com/apple502j/Log4Jail
- https://github.com/jacobtread/L4J-Vuln-Patch
- https://github.com/stardust1900/log4j-2.15.0
- https://github.com/nest-x/nestx-log4js
- https://github.com/Marcelektro/Log4J-RCE-Implementation
- https://github.com/jdremillard/json-logging
- https://github.com/parayaluyanta/sell-logs-and-peace
- https://github.com/albar965/atools
- https://github.com/Al0sc/Log4j-rce
- https://github.com/ven0n1/Log4jv2Maven
- https://github.com/akunzai/log4j2-sendgrid-appender
- https://github.com/inbug-team/Log4j_RCE_Tool
- https://github.com/zlepper/CVE-2021-44228-Test-Server
- https://github.com/webraybtl/Log4j
- https://github.com/f0ng/log4jscanner
- https://github.com/guguyu1/log4j2_burp_scan
- https://github.com/numanturle/Log4jNuclei
- https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce
- https://github.com/kozmer/log4j-shell-poc
- https://github.com/hackerhackrat/Log4j2-RCE-burp-plugin
- https://github.com/test502git/log4j-fuzz-head-poc
- https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words

## 06-Log4j分析文章

- https://mp.weixin.qq.com/s/4cvooT4tfQhjL7t4GFzYFQ
- https://mp.weixin.qq.com/s/l7iclJRegADs3oiEdcgAvQ
- https://mp.weixin.qq.com/s/nOmQFq4KxM9AZ_HYIq1_CQ
- https://mp.weixin.qq.com/s/K74c1pTG6m5rKFuKaIYmPg
- https://mp.weixin.qq.com/s/AWhV-QdkQ6i2IEZSVhe-Kg
- https://mp.weixin.qq.com/s/iHqwL6jslyCV_0jtdVj82A
- https://lorexxar.cn/2021/12/10/log4j2-jndi
- https://www.t00ls.cc/thread-63705-1-1.html
- https://mp.weixin.qq.com/s/vAE89A5wKrc-YnvTr0qaNg

## 07-Log4j靶场环境

- https://hub.docker.com/u/vulfocus
- https://github.com/jweny/log4j-web-env
- https://github.com/fengxuangit/log4j_vuln
- https://www.t00ls.cc/thread-63695-1-1.html
- https://github.com/christophetd/log4shell-vulnerable-app
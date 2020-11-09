# CICIDS-2017数据集构建调研



## 一、CICIDS-2017数据集平台架构

​      CICIDS-2017数据集平台由两组网络构成，分别是受害者网络和攻击者网络。

​       受害者网络包括一个完备的网络所需要的基础，含有防火墙、路由器、交换机以及常用的三种操作系统（提供PC所需正常服务）

​       攻击者网络则是完全离散式的，直接连接到公网上，他们有不同的公网ip，装有不同的操作系统并在上面执行不同的攻击方案。

![image-20201029152329039](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201029152329039.png)

攻击者网络含有1台路由器、1台交换机和4台PC，其中3台是Win8.1系统，一台是Kali系统。

受害者网络包括3台服务器，1台防火墙，2台交换机和10台PC，它们一起连接到一台域控制器（DC）即活动目录上。

在受害者网络的一台主交换机的一个端口被设为端口镜像，从而能记录网络的所有流量，这个数据集的全部流量也是在此采集的。

域控制器与活动目录：

域控制器是指在“域”模式下，至少有一台服务器负责每一台联入网络的电脑和用户的验证工作，相当于一个单位的门卫一样，称为“域控制器（Domain Controller，简写为DC）”。域控制器( Domain controller，DC)是活动目录的存储位置,安装了活动目录的计算机称为域控制器。域控制器存储着目录数据并管理用户域的交互关系,其中包括用户登录过程、身份验证和目录搜索等。一个域可以有多个域控制器。为了获得高可用性和容错能力,规模较小的域只需两个域控制器,一个实际使用,另一个用于容错性检査;规模较大的域可以使用多个域控制器。

端口镜像：

端口镜像（port Mirroring）功能通过在交换机或路由器上，将一个或多个源端口的数据流量转发到某一个指定端口来实现对网络的监听，指定端口称之为“镜像端口”或“目的端口”，在不严重影响源端口正常吞吐流量的情况下，可以通过镜像端口对网络的流量进行监控分析。在企业中用镜像功能，可以很好地对企业内部的网络数据进行监控管理，在网络出故障的时候，可以快速地定位故障。

## 二、背景流量的生成（B-profile）

虽然数据集中攻击类型的数据是被研究的重点，但生成一个逼真的背景流量也是十分重要，在CICIDS-2017数据集中，作者利用他们自己提出的B-Profile系统来模拟正常用户。

B-Profile系统的作用是为人类交互的抽象行为进行建档并生成一个拟真的良性背景流量。这个数据集的B-Profile提取了25个用户的行为，这25个用户的行为涵盖了常见的网络协议，如HTTP, HTTPS, FTP, SSH，和邮件协议。

拟真背景流量生成步骤如下：

首先，使用机器学习和统计分析技术来从用户的流量信息中概括用户的网络事件，提取为概括的特征。

这些特征包括：

1、一个协议的数据包大小分布。

2、每一个流的数据包数目。

3、有效载荷中的某些模式。

4、有效载荷的大小。

5、协议的请求时间分布。

在提取这些特征后，一个由java编写的代理服务器利用这些特征，随机选取25个用户特征（配置文件）中的某个用户，自动地生成真实的网络事件作用于受害者网络。

## 三、攻击数据的生成和如何打标签

数据集所使用的攻击包括暴力攻击、Dos、Heartbleed Attacks、基于Web的攻击、内网渗透、僵尸网络和DDos攻击。

生成这些攻击的软件来源有两种，有的是使用目前最好的开源软件，有的是作者自己用python编写。

![image-20201030112133247](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201030112133247.png)

数据文件按照攻击类型共分为8个文件：

![image-20201102084959216](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201102084959216.png)

### 3.1 暴力攻击（周二全天）

​       作者选择了Patator作为暴力攻击工具。

​      Patator的优势在于集成了多种爆破方式，支持多线程，并且支持独立日志记录。因此我先猜测作者是根据日志来打标签。

​       数据集在上午使用Patator进行暴力ftp攻击，下午进行暴力ssh攻击。

​       ssh攻击示例:

破解多个用户。用户文件为/root/user.txt，密码文件为/root/newpass.txt，破解效果如下所示。

```
./patator.py ssh_login host=192.168.157.131user=FILE1 1=/root/user.txt password=FILE0 0=/root/newpass.txt
```

![img](http://image.3001.net/images/20180108/15153723781749.png)4

​      可以看出patator的使用较为简单，不过从这个简单的记录可以看出CICIDS-2017数据集不是根据攻击软件的日志来进行打标签的。

​      根据论文中提到的方法，攻击只在一个Kali-Linux操作系统的PC上进行，即可以猜测实际上所有攻击的源IP相同。

​      打开CICIDS-2017数据集的周二记录的csv文件，将所有数据流按源IP排序，可以发现所有的SSH-Patator和FTP-Patator类型的数据源IP均为172.16.0.1！

![image-20201102233436624](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201102233436624.png)

​    但是并不是所有源IP为172.16.0.1的数据均为SSH或FTP攻击，统计后发现少数源端口为443的数据流被标记为了正常数据。

   ![image-20201102233611595](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201102233611595.png)

因此可以推断出周二数据打标签规则如下：

1、源IP为172.16.0.1，源端口为443以外的端口，且在时间在周二上午的数据被标记为FTP-Patator。

2、源IP为172.16.0.1，源端口为443以外的端口，且在时间在周二下午的数据被标记为SSH-Patator。

3、其他数据标记为正常。



### 3.2 Dos攻击（周三上午）

作者使用了Hulk、GoldenEye、Slowloris和Slowhttptest共4种工具进行Dos攻击。

HULK（Http Unbearable Load King）是由安全研究员Barry Shteiman为研究目的开发的Web服务器拒绝服务攻击工具 。它旨在在Web服务器上生成大量独特和混淆的流量，绕过缓存引擎，从而访问服务器的直接资源池。

GoldenEye是由python3编写的Http Dos 测试工具，它的攻击途径利用了Http Keep Alive和No cache。

Slowloris是在2009年由著名Web安全专家RSnake提出的一种攻击方法，其原理是以极低的速度往服务器发送HTTP请求。由于Web Server对于并发的连接数都有一定的上限，因此若是恶意地占用住这些连接不释放，那么Web Server的所有连接都将被恶意连接占用，从而无法接受新的请求，导致拒绝服务。

Slowhttptest是依赖HTTP协议的慢速攻击DoS攻击工具，设计的基本原理是服务器在请求完全接收后才会进行处理，如果客户端的发送速度缓慢或者发送不完整，服务端为其保留连接资源池占用，大量此类请求并发将导致DoS。

结合之前报告的发现（最终的用于机器学习的csv文件与原来的csv文件相比少了源ip，源端口，目的ip，目的端口、时间戳、流ID和协议类型这7个字段）再加上3.1节发现暴力攻击是利用IP和端口这两个字段来打标签，因此尝试用这个7个字段总结出Dos攻击的打标签方式。

![image-20201103143449058](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201103143449058.png)

![image-20201103143619769](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201103143619769.png)

最终发现周三数据打标签与源IP、源端口、时间戳这3个字段相关。

规则如下：

1、源IP为172.16.0.1，源端口为443以外的端口，且在时间在周三上午2：24-10：11的数据被标记为Dos-Slowloris。

2、源IP为172.16.0.1，源端口为443以外的端口，且在时间在周三上午10：15-10：37的数据被标记为Dos-SlowHttptest。

3、源IP为172.16.0.1，源端口为443以外的端口，且在时间在周三上午10：43-11：07的数据被标记为Dos-Hulk。

4、源IP为172.16.0.1，源端口为443以外的端口，且在时间在周三上午11：10-11：19的数据被标记为GoldenEye。

### 3.3 心脏流血攻击（周三下午）

作者使用Heartleech作为攻击工具，并在服务器安装了OpenSSL 1.0.1f作为被攻击的目标（这个版本的OpenSSL易受攻击）。

Heartleech是一个典型的"心脏流血"工具。它可以扫描易受 Bug 攻击的系统，然后用于下载它们。它的优点有：

- 判断目标是否易受攻击的

- 批量下载、多线程

- 自动检索私钥，无需额外步骤

- 一些有限的 Ids 逃避

- STARTTLS 支持

- IPv6 支持

- Tor/Socks5n 代理支持

- 广泛的连接诊断信息

  ​       



![image-20201102234128155](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201102234128155.png)

数据集中的Heartbleed的数据只有11条，可以看出打标签规则如下。

1、源IP为172.16.0.1，源端口为443以外的端口，且在时间在周三下午3：12-3：32的数据被标记为Heartbleed。

### 3.4 基于Web攻击（周四上午）

为了进行Web攻击实验，作者用DVWA开发Web服务器。同时用Selenium框架编写了XSS攻击和暴力破解的自动化软件。此实验中攻击者仍是Kali Linux PC。

DVWA（Damn Vulnerable Web App）是一个基于PHP/MySql搭建的Web应用程序，旨在为安全专业人员测试自己的专业技能和工具提供合法的环境，帮助Web开发者更好的理解Web应用安全防范的过程。

Selenium是一个用于Web应用程序测试的工具。Selenium测试直接运行在浏览器中，就像真正的用户在操作一样。支持的浏览器包括IE（7, 8, 9, 10, 11）、火狐、Chrome浏览器等。这个工具的主要功能包括：测试与浏览器的兼容性——测试你的应用程序看是否能够很好得工作在不同浏览器和操作系统之上。测试系统功能——创建回归测试检验软件功能和用户需求。支持自动录制动作和自动生成.Net、Java等不同语言的测试脚本。

![image-20201103143953690](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201103143953690.png)

观察得到打标签规则如下：

1、源IP为172.16.0.1，源端口为443以外的端口，且在时间在周四上午9：15-10：00的数据被标记为暴力破解。

2、源IP为172.16.0.1，源端口为443以外的端口，且在时间在周四上午10：40-10：42的数据被标记为Sql注入。

3、源IP为172.16.0.1，源端口为443以外的端口，且在时间在周四上午10：15-10：35的数据被标记为XSS攻击。

### 3.5 内网渗透（周四下午）

在内网渗透实验中，作者使用了常见的渗透测试框架Metasploit。

渗透过程共分为两步：

1、受害者PC下载被感染的文件。

2、攻击者在整个受害者网络执行Nmap程序，对受害者网络进行端口扫描。

![image-20201103144205261](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201103144205261.png)

观察得到打标签规则如下：

1、源IP为192.168.10.8，目的IP为205.174.165.73，目的端口为44的数据被标记为内网渗透。

### 3.6 僵尸网络(周五上午）

作者在实验中使用了僵尸网络工具Ares。

Ares工具可以实现远程控制台访问，文件上传和下载，屏幕捕捉和密码记录。

观察数据集，看出Bot标签的源IP、目的IP、源端口、目的端口并不固定。不过考虑到僵尸网络的特性，攻击者和被攻击者之间要进行各种交互。可以看出205.174.165.73是攻击者主机IP。

![image-20201101170732078](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201101170732078.png)

容易看出打标签规则如下：

1、源IP或目的IP为205.174.165.73的数据被设置为Bot攻击。

### 3.7 DDos攻击和端口扫描(周五下午）

在本节中，作者使用LOIC工具来发送UDP、TCP、HTTP响应来进行DDos攻击，攻击者是一组Windows8.1系统的机器。并使用Nmap工具来进行端口扫描攻击。

查看DDos攻击数据文件

![image-20201102083435948](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201102083435948.png)

对IP排序后发现所有DDos攻击的源IP都为172.16.0.1。但并非所有源IP为172.16.0.1的数据都为DDos攻击。

打标签规则：

所有源IP为172.16.0.1,目的端口为80的数据被标记为DDos攻击，其他数据标记为正常。

查看端口扫描攻击数据

对Label排序后容易看出，所有端口扫描攻击的源IP为172.16.0.1

![image-20201102084106343](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201102084106343.png)

在对源IP排序，可以看出除了源目的端口都为0的两条数据，其他源IP为172.16.0.1的数据都被标记为端口扫描攻击。

![image-20201102084501694](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201102084501694.png)

容易看出打标签规则如下：

源IP为172.16.0.1，源端口不为0的数据被标记为端口扫描攻击。

## 四、小结

综合第三节中8种攻击数据的打标签方法，可以看出CICIDS-2017数据集中，作者往往在某个时间段只采用一个攻击者PC来进行所有攻击数据的生成，从而所有攻击数据的源IP、源端口、目的IP、目的端口、时间戳便可以确定出该数据是否是攻击数据。

在后续的工作中，作者把源IP、源端口、目的IP、目的端口、时间戳这几个数据从数据集中去除，得到新数据没有了这些与Label的强相关标签便可以用于机器学习。



# Snort规则异常类型与CICIDS-2017数据集异常类型对比

为了比对Snort规则所探测出的异常与CICIDS-2017数据集所使用的异常，首先需要对snort规则有简要的了解。

### 一、snort规则简介

![image-20201105095003243](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201105095003243.png)

上图是Snort规则的结构，Snort规则可以分为规则头（Rule Header)和规则选项（Rule options）两个部分。

下图是一条Snort规则的示例，以这条示例来介绍snort规则的编写。

![image-20201105095855091](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201105095855091.png)

### 规则头（Rule Header）

Snort规则头包括一条规则的操作、协议、源目的IP、网络掩码和源目的端口。

alert (将要执行的操作) snort规则的第一个条目是这条规则匹配后需要执行的操作，通常是alert（警报）

tcp    (流量的协议类型)snort目前支持对4种协议的可能威胁进行分析，包括TCP、UDP、ICMP和IP协议

$EXTERNAL_NET （源IP） 含义是所有外部IP

$HTTP_PORTS   （源端口）含义是HTTP相关的端口

-> 指向操作符 指向规则适用的流量方向

$HOME_NET （目的IP）含义是内部IP

any （目的端口） 含义是任意端口

### 规则选项（Rule Options）

规则选项是Snort入侵检测引擎的核心，有着灵活易用的特点并支持多种功能。 

所有Snort规则选项都使用分号（；）彼此分开。

规则选项关键字以冒号（：）分隔其参数。

#### 一般规则选项（GENERAL RULE OPTIONS）

***Message：***Msg 关键字告诉snort当匹配某个规则时输出什么信息，msg选项的内容是一个简单的字符串。

示例：msg: “BROWSER-IE Microsoft Internet Explorer CacheSize exploit attempt”;

含义：匹配规则后输出警告信息：浏览器-IE Microsoft Internet ExplorerCacheSize攻击尝试

***Flow：***这个关键字要和TCP流重建联合使用。它允许规则只应用到流量的某个方向上。这将允许规则只应用到客户端或者服务器端。这将能把内网客户端流览web页面的数据包和内网服务器所发送的数据包区分开来。

示例：flow: to_client,established;

含义：to_client 触发服务器上从A到B的响应。 established 只触发已经建立的TCP连接。

***Reference：***reference关键字允许规则包含对外部信息源的引用。

示例：reference:cve,2016-8077;

含义：参考引用cve,2016-8077;

***Classtype：***classtype关键字指明如果攻击成功，这个攻击会属于什么类型。

示例：classtype: attempted-user;

含义：尝试获取用户权限

***sid/rev ：***每条规则的id，通常与rev关键字一起使用。

#### 检测选项（DETECTION OPTIONS）

***Content ：***设置content关键字可以使用户搜索数据包有效负载中的特定内容，并基于该数据触发响应。 选项数据可以包含混合文本和二进制数据。

**offset**

在n个字节后匹配
用法：offset: 字节数;
举例：content:“wan”; offset:2;
从负载的第二个字节开始匹配wan
**depth**
在负载的第n个字节内匹配
用法：depth: 字节数;
举例：content:“wan”; depth:2;
在负载的第二个字节内匹配wan
**distance**
匹配前一个content成功后，第n个字节后匹配
用法：distance: 字节数;
举例：content:“zhu”; content:“wan”; distance:10;
成功匹配第1个zhu后，在10个字节后匹配wan。
**within**
匹配前一个content成功后，第n个字节内匹配
用法：within: 字节数;
举例：content:“zhu”; content:“wan”; within:10;
成功匹配第1个zhu后，在10个字节内匹配wan。



***PCRE ：***pcre关键字允许使用与perl兼容的规则来编写规则，即使用正则表达式。正则表达式比简单内容匹配允许更复杂的匹配。

***Byte test*** ：byte_test选项允许规则针对二进制中的特定值测试多个字节。

示例： byte_test: 1,>,1000,10 

含义：意思是相对于上次content匹配结束的位置，向后偏移10个字节，再取一个数转化为10进制数大于1000，则匹配成功

### 二、snort规则库比对

snort规则库分为社区版、注册版、订阅版三种，西门子公司采取的snort规则库应该是订阅版，不过需要付费，这里我选择规则最少的社区版进行比对。

![image-20201106155128410](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201106155128410.png)

打开下载好的.rules文件，可以直接阅读snort规则库源码。

![image-20201106155823122](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201106155823122.png)

除了文件开头有一小段注释说明文件内容外，剩余代码全部由一条条snort规则组成，整个rules文件一共有约3500条规则，因此不能用snort规则库匹配CICIDS-2017数据集的攻击类型，而要用CICIDS-2017数据集的攻击类型匹配snort规则库。

![image-20201106160131571](C:\Users\ltr\AppData\Roaming\Typora\typora-user-images\image-20201106160131571.png)

####                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          1、暴力攻击：

由于snort规则分类不含暴力攻击，在snort规则库中搜索brute force，得到五个结果如下。

`alert tcp $EXTERNAL_NET any -> $HOME_NET 143 ( msg:"PROTOCOL-IMAP login brute force attempt"; flow:to_server,established; content:"LOGIN",fast_pattern,nocase; detection_filter:track by_dst, count 30, seconds 30; metadata:ruleset community; service:imap; classtype:suspicious-login; sid:2273; rev:10; )`

`alert tcp $EXTERNAL_NET any -> $HOME_NET 110 ( msg:"PROTOCOL-POP login brute force attempt"; flow:to_server,established; content:"USER",fast_pattern,nocase; detection_filter:track by_dst, count 30, seconds 30; metadata:ruleset community; service:pop3; classtype:suspicious-login; sid:2274; rev:9; )`

`alert tcp $SMTP_SERVERS 25 -> $EXTERNAL_NET any ( msg:"SERVER-MAIL AUTH LOGON brute force attempt"; flow:to_client,established; content:"Authentication unsuccessful",offset 54,nocase; detection_filter:track by_dst, count 5, seconds 60; metadata:ruleset community; service:smtp; classtype:suspicious-login; sid:2275; rev:10; )`

`alert tcp $SQL_SERVERS 1433 -> $EXTERNAL_NET any ( msg:"SQL sa brute force failed login attempt"; flow:to_client,established; content:"Login failed for user 'sa'",fast_pattern,nocase; detection_filter:track by_src, count 5, seconds 2; metadata:ruleset community; reference:bugtraq,4797; reference:cve,2000-1209; reference:nessus,10673; classtype:unsuccessful-user; sid:3152; rev:9; )`

`alert tcp $SQL_SERVERS 1433 -> $EXTERNAL_NET any ( msg:"SQL sa brute force failed login unicode attempt"; flow:to_client,established; content:"L|00|o|00|g|00|i|00|n|00| |00|f|00|a|00|i|00|l|00|e|00|d|00| |00|f|00|o|00|r|00| |00|u|00|s|00|e|00|r|00| |00|'|00|s|00|a|00|'|00|"; detection_filter:track by_src, count 5, seconds 2; metadata:ruleset community; reference:bugtraq,4797; reference:cve,2000-1209; reference:nessus,10673; classtype:unsuccessful-user; sid:3273; rev:8; )`

主要关注msg字段：

分析发现5个规则分别是针对IMAP协议、POP协议、SMTP的AUTH LOGON命令（怀疑是写错了，应该是AUTH LOGIN）、sql server的登录尝试、sql server的unicode登录尝试。而CIC-IDS2017的暴力攻击是ftp和ssh攻击，因此猜测snort规则库无法识别数据集里的暴力攻击。

#### 2、Dos攻击：

在snort规则库的classtype中含有Dos攻击类型，分别是attempted-dos(尝试dos攻击）和successful-dos（成功dos攻击）。

搜索attempted-dos：可以发现50多条结果。

示例：windos的SMBv2/SMBv3 缓存越界规则

`alert tcp $EXTERNAL_NET [139,445] -> $HOME_NET any ( msg:"SERVER-SAMBA Microsoft Windows SMBv2/SMBv3 Buffer Overflow attempt"; flow:to_client,established; content:"|FE|SMB|40 00|",depth 6,offset 4; content:"|03 00|",within 2,distance 6; content:"|01|",within 1,distance 2; content:"|10 00|",within 2,distance 47; byte_test:3, >, 1481, 1; metadata:policy balanced-ips drop,policy connectivity-ips drop,policy max-detect-ips drop,policy security-ips drop,ruleset community; reference:cve,2017-0016; classtype:attempted-dos; sid:41499; rev:5; )`

搜索successful-dos：没有匹配结果。

因此猜测snort规则库能识别数据集里的dos攻击。

#### 3、心脏流血攻击

由于snort规则分类不含心脏流血攻击，在snort规则库中搜索heart bleed。

得到几十条匹配规则。

示例： OpenSSL SSLv3 大型心脏流血攻击响应规则

`alert tcp $HOME_NET [21,25,443,465,636,992,993,995,2484] -> $EXTERNAL_NET any ( msg:"SERVER-OTHER OpenSSL SSLv3 large heartbeat response - possible ssl heartbleed attempt"; flow:to_client,established; content:"|16 03 00|"; byte_jump:2,0,relative; content:"|18 03 00|",within 3,fast_pattern; byte_test:2,>,128,0,relative; metadata:policy balanced-ips drop,policy security-ips drop,ruleset community; service:ssl; reference:cve,2014-0160; classtype:attempted-recon; sid:30777; rev:3; )`

从classtype:attempted-recon;可以看出心脏流血攻击被分在了尝试侦察信息这一类。

猜测snort规则库可能识别数据集里的心脏流血攻击。

#### 4、基于Web攻击

上文提到数据集中的Web攻击包括暴力攻击、sql注入、xss攻击三种，下面逐一分析：

**4.1暴力web攻击：**

在1小节对暴力攻击的搜索得到的5个结果的classtype分类中不含web相关内容，因此snort规则库应该识别不出暴力web攻击。

**4.2sql注入**

在snort规则库中搜索sql injection，得到三个结果：

`alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( msg:"INDICATOR-OBFUSCATION large number of calls to chr function - possible sql injection obfuscation"; flow:established,to_server; http_method; content:"GET"; http_uri; content:"CHR(",nocase; content:"CHR(",distance 0,nocase; content:"CHR(",distance 0,nocase; content:"CHR(",distance 0,nocase; content:"CHR(",distance 0,nocase; metadata:ruleset community; service:http; reference:url,isc.sans.org/diary.html?storyid=3823; classtype:web-application-attack; sid:28344; rev:2; )`

`alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( msg:"SERVER-WEBAPP Demarc SQL injection attempt"; flow:to_server,established; http_uri; content:"/dm/demarc"; pkt_data; content:"s_key="; content:"'",distance 0; content:"'",distance 1; content:"'",distance 0; metadata:ruleset community; service:http; reference:bugtraq,4520; reference:cve,2002-0539; classtype:web-application-activity; sid:2063; rev:13; )`

`alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ( msg:"SQL use of sleep function in HTTP header - likely SQL injection attempt"; flow:established,to_server; http_header; content:"User-Agent|3A| "; content:"sleep(",within 200,fast_pattern; pcre:"/User-Agent\x3A\x20[^\r\n]*sleep\x28/"; metadata:policy balanced-ips drop,policy security-ips drop,ruleset community; service:http; reference:url,blog.cloudflare.com/the-sleepy-user-agent/; classtype:web-application-attack; sid:38993; rev:6; )`

三个规则分别是

大量使用chr函数（*返回string，其中包含有与指定的字符代码相关的字符 。*）

Demarc SQL注入尝试

在Http头中使用sleep函数

由于数据集使用的sql注入方法未知，因此snort可能检查出sql注入。

**4.3XSS攻击**

在snort规则库中搜索XSS，得到5个结果：

`alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( msg:"APP-DETECT Acunetix web vulnerability scanner base64 XSS attempt"; flow:to_server,established; http_uri; content:"PHNjcmlwdD",fast_pattern,nocase; metadata:ruleset community; service:http; reference:url,www.acunetix.com; classtype:web-application-attack; sid:25362; rev:2; )`

`alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( msg:"APP-DETECT Acunetix web vulnerability scanner prompt XSS attempt"; flow:to_server,established; http_uri; content:"<ScRiPt>prompt(",fast_pattern,nocase; metadata:ruleset community; service:http; reference:url,www.acunetix.com; classtype:web-application-attack; sid:25364; rev:2; )`

`alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( msg:"APP-DETECT Acunetix web vulnerability scanner XSS attempt"; flow:to_server,established; http_uri; content:">=|5C|xa2",fast_pattern,nocase; metadata:ruleset community; service:http; reference:url,www.acunetix.com; classtype:web-application-attack; sid:25365; rev:2; )`

`alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( msg:"SERVER-WEBAPP JavaScript tag in User-Agent field possible XSS attempt"; flow:to_server,established; http_header; content:"User-Agent|3A| <SCRIPT>",fast_pattern,nocase; metadata:ruleset community; service:http; reference:url,blog.spiderlabs.com/2012/11/honeypot-alert-referer-field-xss-attacks.html; classtype:web-application-attack; sid:26483; rev:2; )`

`alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ( msg:"SERVER-WEBAPP vBulletin XSS redirect attempt"; flow:to_server,established; http_uri; content:"/misc.php?v="; content:"&js=js",within 12; metadata:ruleset community; service:http; reference:url,www.virustotal.com/en/url/6a7664105f1f144930f51e71dd0fec728607b4c9e33037d376cd7bf8351273a9/analysis/1430224991/; classtype:web-application-attack; sid:34287; rev:2; )`

5条规则涵盖了base64 XSS攻击、prompt XSS攻击、普通XSS攻击、用户代理JavaScript标签和XSS重定向攻击。

因此snort规则库可能检查出数据集里的XSS攻击。

#### 5、内网渗透

在snort规则库搜索infiltration，发现没有匹配的结果。

但是内网渗透第二步需要进行端口扫描。

搜索portscan，匹配一条规则。

`alert tcp $EXTERNAL_NET any -> $HOME_NET any ( msg:"INDICATOR-SCAN synscan portscan"; flow:stateless; flags:SF; id:39426; metadata:ruleset community; classtype:attempted-recon; sid:630; rev:10; )`

可见snort能判断出端口扫描攻击，因此有机会检测出内网渗透攻击的第二步骤。

#### 6、僵尸网络

在snort规则库搜索botnet，可以得到十几条规则：

举例如下：

`alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ( msg:"MALWARE-CNC Win.Trojan.Urausy Botnet variant outbound connection"; flow:to_server,established; http_raw_uri; bufferlen:95<=>102; http_header; content:"|29 20|Chrome|2F|"; content:!"|0A|Accept-Encoding|3A 20|"; http_uri; pcre:"/^\x2f[a-z\x2d\x5f]{90,97}\.php$/"; metadata:impact_flag red,policy balanced-ips drop,policy security-ips drop,ruleset community; service:http; reference:url,www.botnets.fr/index.php/Urausy; classtype:trojan-activity; sid:25807; rev:4; )`

这条规则检测了僵尸网络的多种远程控制连接，僵尸网络检测在classtype的类型为trojan-activity，即特洛伊病毒检测。

因此snort有机会扫描出数据集中的僵尸网络攻击。

#### 7、DDos攻击和端口扫描

端口扫描攻击在第五小节中已经提到了，只需要搜索DDos攻击。

snort规则库搜索ddos，发现匹配的规则超过二十条。

举例如下：

`alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any ( msg:"MALWARE-CNC Win.Trojan.BlackRev cnc data command"; flow:to_client,established; file_data; content:"data|7C|",depth 5; pcre:"/^data\x7c\d+\x7c\d+\x7C[a-z0-9]+\x2E[a-z]{2,3}\x7C[a-z0-9]+\x7C/"; metadata:impact_flag red,policy balanced-ips drop,policy security-ips drop,ruleset community; service:http; reference:url,**ddos**.arbornetworks.com/2013/05/the-revolution-will-be-written-in-delphi; classtype:trojan-activity; sid:26735; rev:4; )`

匹配规则基本都是在reference中提到ddos。

可见snort规则库难以直接匹配出ddos攻击，而是匹配出ddos攻击所需要利用的特洛伊病毒。

因此snort有机会扫描出数据集中的ddos攻击。

#### 小结

snort应该无法扫描暴力攻击/暴力web攻击，原因可能是对一个数据包的分析无法看出带有时间性质才能判断的暴力破解。

内网渗透的第一部分--用户下载被感染的文件也很难被snort识别。

数据集其他的攻击类型，snort有大概率能识别出来。






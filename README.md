## deny-ssh-password-attack-V6
***


&ensp; Openwrt 自身没有对抗ssh破解的工具,为了使我们暴露在互联网的路由器更加安全,基于iptables/ip6tables编写了一个小脚本, 脚本通过crontab定时执行.

&ensp; Openwrt does not have its own tools to combat SSH cracking. To make our Internet-exposed routers more secure, a small script based on iptables/ip6tables is written. The script is executed by crontab timing.

&ensp; 脚本的功能是读取 logread 中的失败日志,对于失败次数超过5次的同一个IP,iptables/ip6tables 中增加一条封锁规则,并记录日志到 /tmp/DenyPwdHack.log

### 操作步骤如下:
***

1. 下载文件DenyPwdHackV6.sh , 以root登录，放在 /root/ 目录下。然后执行  在Openwrt增加以下 crontab 内容:
```
chmod u+x /root/DenyPwdHackV6.sh
```

2. 执行命令: 
```
crontab -e
```

3. 按需要贴入以下内容: 
```
0 */3 * * * /root/DenyPwdHackV6.sh   # 每3 小时执行一次脚本例子：
*/1 * * * * /root/DenyPwdHackV6.sh   # 每1分钟执行一次脚本例子： 
```

#### 列出已有封禁规则及序号：
```
iptables -L DenyPwdHack --line-numbers    # ipv4规则
ip6tables -L DenyPwdHack6 --line-numbers   # ipv6规则
```
#### 按照规则序号 手动删除规则：
```
iptables -D DenyPwdHack 0   # ipv4规则  将‘0’替换为需要删除的规则序号
ip6tables -D DenyPwdHack6 0   # ipv6规则 将‘0’替换为需要删除的规则序号
```

#### 查看日志
```
cat /tmp/DenyPwdHack.log
```


### 脚本中的参数：
***

1. 登录失败多少次后封锁IP

   Failed_times=5

2. 查找日志时间范围，单位：秒
   
   findtime=500

3. 检测到ssh或者luci攻击后封禁的端口，针对ip只封禁这几个端口
 
   Deny_Port=22,443，80

4. 黑名单过期时间,单位小时
 
   BlackList_exp=24

5. 日志的绝对路径，因为 /tmp文件系统从内存中开辟的，写到该文件系统速度快，对芯片也安全
 
   LOG_DEST=/tmp/DenyPwdHack.log

6. 白名单IP可以用"|"号隔开,支持grep的正则表达式
 
   exclude_ip="192.168.|127.0.0.1"



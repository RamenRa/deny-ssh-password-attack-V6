#!/bin/bash
## 重启后所有封禁规则全部失效！！！
## 失败次数
Failed_times=5
# 查找日志时间范围，单位：秒
findtime=500
## 检测到攻击时需要针对攻击IP封禁的端口,可以将ssh/luci等端口加上。如果在其他端口上还有服务没有填入以下，即使封禁了该ip依旧可以访问
Deny_Port="22,443,80"
## 黑名单过期时间,单位：小时 
bantime=24
## 日志路径
LOG_DEST=/tmp/DenyPwdHack.log
## 白名单IP可以用"|"号隔开,支持grep的正则表达式
exclude_ip="192.168.4.|127.0.0.1"

## 个别第三方编译的版本可能没有写有版本号，暂时停用
## OpenWRT 版本判断
# Vfile=/etc/banner
# OWTV=`awk 'BEGIN{IGNORECASE=1}/openwrt/ {split($2,v,"."); print v[1]}' $Vfile`
# [[ $OWTV -lt 18 ]] && echo "OpenWRT version must be >= 18" && exit 1

## 用于返回"Tue Oct 3 23:02:25 2023"时间格式的unix时间戳 
## 运行'logred',如果日志时间格式不是以上样式，可能需要执行修改以下get_unix_time函数，或者你的月份是数字的删除整个if判断即可。
function get_unix_time {
  mon="$2"   ## 第二个关键字是月份
  day="$3"
  time_str="$4"
  year="$5"

  array=(${time_str//:/ })  ## 以“：”拆分时间
  hour="${array[0]}"
  min="${array[1]}"
  sec="${array[2]}"

  if [[ $mon == "Jan" ]]
  then
    month="1"
  elif [[ $mon == "Feb" ]]
  then
    month="2"
  elif [[ $mon == "Mar" ]]
  then
    month="3"
  elif [[ $mon == "Ari" ]]
  then
    month="4"
  elif [[ $mon == "May" ]]
  then
    month="5"
  elif [[ $mon == "Jun" ]]
  then
    month="6"
  elif [[ $mon == "Jul" ]]
  then
    month="7"
  elif [[ $mon == "Aut" ]]
  then
    month="8"
  elif [[ $mon == "Sep" ]]
  then
    month="9"
  elif [[ $mon == "Oct" ]]
  then
    month="10"
  elif [[ $mon == "Nov" ]]
  then
     month="11"
  elif [[ $mon == "Dec" ]]
  then
    month="12"
  fi
  datetime="$year-$month-$day $hour:$min:$sec"
  unix_timestamp=$(date -d "$datetime" "+%s")
  echo -e "$unix_timestamp"  ## 返回时间戳
}

## 读取规定时间范围内的日志
function process_logread_output {
  local logread_output="$1"
  local threshold="$2"  ## 新增的参数用于表示时间差的阈值
  local output=""
  while IFS= read -r line; do
    # 提取日志中的时间部分
    log_time=$(echo "$line" | awk '{print $1, $2, $3, $4, $5}')
    # 将时间转换为时间戳
    # timestamp=$(date -d "$log_time" +%s 2>/dev/null)
    timestamp=$(get_unix_time $log_time)
    if [ -n "$timestamp" ]; then
      # 获取当前时间戳
      current_timestamp=$(date +%s)
      # 计算时间戳差值
      time_diff=$((current_timestamp - timestamp))
      # 如果差值小于threshold秒，则输出时间戳和原始日志行
      if [ "$time_diff" -lt "$threshold" ]; then
        # 将结果写入输出变量
        output+="$line\n"
      fi
    else
       : # 如果转换失败
    fi
  done <<< "$logread_output"  # 通过 <<< 运算符传递logread的输出
  # 返回所有echo输出的内容
 echo -e "$output"
}

# 使用logread命令获取日志并调用函数
# logread_output=$(cat /tmp/log/system.log) 
logread_output=$(logread) 
log_output=$(process_logread_output "$logread_output" "$findtime")

# 打印函数的输出
# echo "$log_output"

## 黑名单所在iptables链表
ChainName=DenyPwdHack
ChainNameV6=DenyPwdHack6

INPUT_RULE="INPUT -p tcp -m multiport --dports $Deny_Port -j $ChainName"
INPUT_RULE_IPV6="INPUT -p tcp -m multiport --dports $Deny_Port -j $ChainNameV6"

## 日志关键字,每个关键字可以用"|"号隔开,支持grep的正则表达式
## 注: SSH 攻击可以大量出现四种关键字：Invalid user/Failed password for/Received disconnect from/Disconnected from authenticating
##     Luci 攻击可以出现"luci: failed login on / for root from xx.xx.xx.xx"
LOG_KEY_WORD="auth\.info\s+sshd.*Failed password for|luci:\s+failed\s+login|auth\.info.*sshd.*Connection closed by.*port.*preauth"


## 日志时间
LOG_DT=`date "+%Y-%m-%d %H:%M:%S"`

## 判断链是否存在
iptables -n --list $ChainName > /dev/null 2>&1
if [[ $? -ne 0 ]] ; then
  iptables -N $ChainName
  echo "[$LOG_DT] iptables -N $ChainName" >> $LOG_DEST
fi

## 判断链是否存在 ipv6
ip6tables -n --list $ChainNameV6 > /dev/null 2>&1
if [[ $? -ne 0 ]] ; then
  ip6tables -N $ChainNameV6
  echo "[$LOG_DT] ip6tables -N $ChainNameV6" >> $LOG_DEST
fi

## 判断INPUT跳到链的规则是否存在
iptables -C $INPUT_RULE > /dev/null 2>&1
if [[ $? -ne 0 ]] ; then
  iptables -I $INPUT_RULE
  echo "[$LOG_DT] iptables -I $INPUT_RULE" >> $LOG_DEST
fi

## 判断INPUT跳到链的规则是否存在 IPV6
ip6tables -C $INPUT_RULE_IPV6 > /dev/null 2>&1
if [[ $? -ne 0 ]] ; then
  ip6tables -I $INPUT_RULE_IPV6
  echo "[$LOG_DT] ip6tables -I $INPUT_RULE_IPV6" >> $LOG_DEST
fi

# 从logread读取登陆日志
DenyIPLIst=`echo "$log_output" \
  | awk '/'"$LOG_KEY_WORD"'/ {for(i=1;i<=NF;i++) \
  if($i~/^(([0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/) \
  print $i}' \
  | grep -vE "${exclude_ip}" \
  | sort | uniq -c \
  | awk '{if($1>'"$Failed_times"') print $2}'`

  # 从logread读取登陆日志 IPV6
  DenyIPLIstIPV6=`echo "$log_output" \
  | awk '/'"$LOG_KEY_WORD"'/ {for(i=1;i<=NF;i++) \
  if($i~/^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/) \
  print $i}' \
  | sort | uniq -c \
  | awk '{if($1>'"$Failed_times"') print $2}'`
  
  # 遍历所有违规IP，逐个条件防火墙规则
IPList_sum=`echo "${DenyIPLIst}" | wc -l`
if [[ $IPList_sum -ne 0 ]];then
  for i in ${DenyIPLIst}
    do
    iptables -vnL $ChainName | grep -q $i
    [[ $? -ne 0 ]] && iptables -A $ChainName -s $i -m comment --comment "Added at $LOG_DT by DenyPwdHack" -j DROP \
     && echo "[$LOG_DT] iptables -A $ChainName -s $i -j DROP" >> $LOG_DEST
    done
fi
  # 遍历所有违规IP，逐个条件防火墙规则 IPV6
IPList_sumIPV6=`echo "${DenyIPLIstIPV6}" | wc -l`
if [[ $IPList_sumIPV6 -ne 0 ]];then
  for i in ${DenyIPLIstIPV6}
    do
    ip6tables -vnL $ChainNameV6 | grep -q $i
    [[ $? -ne 0 ]] && ip6tables -A $ChainNameV6 -s $i -m comment --comment "Added at $LOG_DT by DenyPwdHack" -j DROP \
     && echo "[$LOG_DT] iptables -A $ChainNameV6 -s $i -j DROP" >> $LOG_DEST
    done
fi

## 黑名单过期删除
ChainList=`iptables --line-numbers -nL $ChainName |\
  awk '/Added at/ {for(i=1;i<=NF;i++) if($i~/[0-9]{4}(-[0-9]{2}){2}/) print $1","$i" "$(i+1)}' |\
  sort -rn`
 
## 链表必须从后端删除,如果从前端删除,后端的实际rulenum会变
ChainList_num=`echo "${ChainList}" | grep -v "^$" | wc -l`
if [[ ${#ChainList} -ne 0 ]] && [[ $ChainList_num -gt 0 ]] ; then
for tl in `seq 1 $ChainList_num`
do
  Dtime=`echo "${ChainList}" | sed -n ''"$tl"'p' | awk -F, '{print $2}'`
  Stime=`date -d "$Dtime" +%s`
  Ntime=`date +%s`
  if [[ $(($Ntime - $Stime)) -ge $(($bantime * 3600)) ]] ; then
    RuleNum=`echo "${ChainList}" | sed -n ''"$tl"'p' | awk -F, '{print $1}'`
    iptables -D $ChainName $RuleNum
    if [[ $? -eq 0 ]] ; then
      echo "[$LOG_DT] iptables -D $ChainName $RuleNum" >> $LOG_DEST
    else
      echo "[$LOG_DT] execute delete failed: iptables -D $ChainName $RuleNum" >> $LOG_DEST
    fi
  fi
done
fi

 ## 黑名单过期删除 IPV6
 ChainListIPV6=`ip6tables --line-numbers -nL $ChainNameV6 |\
  awk '/Added at/ {for(i=1;i<=NF;i++) if($i~/[0-9]{4}(-[0-9]{2}){2}/) print $1","$i" "$(i+1)}' |\
  sort -rn`

## 链表必须从后端删除 IPV6
ChainList_num_IPV6=`echo "${ChainListIPV6}" | grep -v "^$" | wc -l`
if [[ ${#ChainListIPV6} -ne 0 ]] && [[ $ChainList_num_IPV6 -gt 0 ]] ; then
for tl in `seq 1 $ChainList_num_IPV6`
do
  Dtime=`echo "${ChainListIPV6}" | sed -n ''"$tl"'p' | awk -F, '{print $2}'`
  Stime=`date -d "$Dtime" +%s`
  Ntime=`date +%s`
  if [[ $(($Ntime - $Stime)) -ge $(($bantime * 3600)) ]] ; then
    RuleNum=`echo "${ChainListIPV6}" | sed -n ''"$tl"'p' | awk -F, '{print $1}'`
    ip6tables -D $ChainNameV6 $RuleNum
    if [[ $? -eq 0 ]] ; then
      echo "[$LOG_DT] ip6tables -D $ChainNameV6 $RuleNum" >> $LOG_DEST
    else
      echo "[$LOG_DT] execute delete failed: ip6tables -D $ChainNameV6 $RuleNum" >> $LOG_DEST
    fi
  fi
done
fi

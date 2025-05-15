#!/bin/bash

if [ -z "$1" ]
then
  echo "Usage : ./recon.sh  <IP address>"
  exit 1
  fi

  printf "\n ------------Nmap ---------- \n\n" > results

  echo "Running Nmap...."

  nmap $1 | tail -n +5 | head -n -3 >> results

  while read line
  do 
        if [[ $line == *open* ]] && [[ $line == *http* ]]; then
        	echo "Running gobuster..."
        	gobuster dir -u $1 -w /usr/share/wordlists/dirb/common.txt -qz > temp1

        echo "Running whatweb..."
        whatweb $1 -v > temp2
        fi
    done < results

if [ -e temp1 ]
then
    printf "\n -------DIRS--------\n\n" >> results
    cat temp1 >> results
    rm temp1

fi



if [ -e temp2 ]
then
    printf "\n -------WEB--------\n\n" >> results
    cat temp2 >> results
    rm temp2

fi

cat results
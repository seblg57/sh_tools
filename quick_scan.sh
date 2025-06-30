#!/bin/bash
#
# Minimal TCP Port Scanner
# Author: Sebux
# Description:
#   Scan specified ports on a target host to check if they are open or closed.
#   Supports single ports, comma-separated lists, and port ranges.
# Usage:
#   ./scanner.sh <host> <port|port1,port2,...|start-end>
# Example:
#   ./scanner.sh google.com 80
#   ./scanner.sh 192.168.1.1 22,80,443
#   ./scanner.sh example.com 79-81
#

function alarm {
  local timeout=$1; shift;
  # execute command, store PID
  bash -c "$@" &
  local pid=$!
  {
    sleep "$timeout"
    kill $pid 2> /dev/null
  } &
  wait $pid 2> /dev/null 
  return $?
}
function scan {
  if [[ -z $1 || -z $2 ]]; then
    echo "Usage: ./scanner <host> <port, ports, or port-range>"
    echo "Example: ./scanner google.com 79-81"
    return
  fi

  local host=$1
  local ports=()
  case $2 in
    *-*)
      IFS=- read start end <<< "$2"
      for ((port=start; port <= end; port++)); do
        ports+=($port)
      done
      ;;
    *,*)
      IFS=, read -ra ports <<< "$2"
      ;;
    *)
      ports+=($2)
      ;;
  esac

  for port in "${ports[@]}"; do
    alarm 1 "echo >/dev/tcp/$host/$port" &&
      echo "$port/tcp open" ||
      echo "$port/tcp closed"
  done
}
scan $1 $2
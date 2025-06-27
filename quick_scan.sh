#!/bin/bash
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
  # store user-provided ports in array
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

  # attempt to write to each port, print open if successful, closed if not
  for port in "${ports[@]}"; do
    alarm 1 "echo >/dev/tcp/$host/$port" &&
      echo "$port/tcp open" ||
      echo "$port/tcp closed"
  done
}
scan $1 $2
#!/usr/bin/env python3
"""
Simple Intrusion Detection Script to enforce timeouts to multiple unauthorized attempts accessing ssh service
"""

__author__ = "Derek Wong"

import getopt, sys, os, time
import datetime as dt
import subprocess
import select
import threading
import re
import sh

# Symbolic Constants
DEFAULT_ATTEMPTS_ALLOWED = 3
INDEFINITE_TIMEOUT_SECONDS = "INDEFINITE"
SECURE_LOG_FILE = "/var/log/secure"
FAILED_MATCH_STRING = "Failed password"
BLOCKED_CLIENT_ATTEMPTS_KEY = "num_attempts"
BLOCKED_CLIENT_TIMEOUT_KEY = "timeout_end"
BLOCKED_CLIENT_POLLING_RATE = 0.3
DATTIME_FORMAT = "%H:%M:%S"

# Global variables
client_failed_attempts = {}

def usage():
    print ("Usage: %s [-h] -a num_attempts -t timeout_sec" %(sys.argv[0]))

# Separate thread target function to poll stored client IPs for expiring time limits 
def check_blocked_clients(num_attempts):
    while True:
        for ip_addr in list(client_failed_attempts):
            # Check if client is blocked from accessing server
            if (client_failed_attempts[ip_addr][BLOCKED_CLIENT_TIMEOUT_KEY] != INDEFINITE_TIMEOUT_SECONDS) \
                        and (client_failed_attempts[ip_addr][BLOCKED_CLIENT_ATTEMPTS_KEY] > num_attempts):
                current_time = dt.datetime.now()
                
                # Check if timeout has expired
                if client_failed_attempts[ip_addr][BLOCKED_CLIENT_TIMEOUT_KEY] <= current_time:
                    print("Thread Unblocked at %s" %(current_time.strftime(DATTIME_FORMAT)))
                    subprocess.run(["iptables", "-D", "INPUT", "-s", ip_addr, "-j", "DROP"])
                    del client_failed_attempts[ip_addr]
            
        time.sleep(BLOCKED_CLIENT_POLLING_RATE)

# Watches file changes occuring to the secure log file and handles unauhtorized attempts
def check_secure_logs(num_attempts, timeout_sec):
    f = subprocess.Popen(['tail','-n','0','-F',SECURE_LOG_FILE], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    p = select.poll()
    p.register(f.stdout)

    while True:
        if p.poll(1):
            line = f.stdout.readline()
            if line:
                max_login_handler(line.decode("utf-8"), num_attempts, timeout_sec)

# Check number of login attempts from IP
def max_login_handler(line, num_attempts, timeout_sec):
    match = re.search(FAILED_MATCH_STRING, line)
    if match:
        print(match.string)
        ip_addr = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line).group()
        # Check if unique client attempting login
        if ip_addr in client_failed_attempts:
            # Check if number of login attempts exceeds threshold
            if client_failed_attempts[ip_addr][BLOCKED_CLIENT_ATTEMPTS_KEY] == num_attempts:
                # Drop all incoming traffic from client
                if timeout_sec != INDEFINITE_TIMEOUT_SECONDS:
                    current_time = dt.datetime.now()
                    unblock_time = current_time + dt.timedelta(seconds=timeout_sec)
                    print("Blocking IP: %s for %d seconds" %(ip_addr, timeout_sec))
                    print("Blocking IP: %s\tTime: %s" %(ip_addr,current_time.strftime(DATTIME_FORMAT)))
                    print("Unblocking IP: %s\tTime: %s" %(ip_addr,unblock_time.strftime(DATTIME_FORMAT)))
                    client_failed_attempts[ip_addr][BLOCKED_CLIENT_TIMEOUT_KEY] = unblock_time
                else:
                    print("Blocking IP indefinitely")
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip_addr, "-j", "DROP"])
            client_failed_attempts[ip_addr][BLOCKED_CLIENT_ATTEMPTS_KEY] += 1
        else:
            client_failed_attempts[ip_addr] = {BLOCKED_CLIENT_ATTEMPTS_KEY: 1, BLOCKED_CLIENT_TIMEOUT_KEY: INDEFINITE_TIMEOUT_SECONDS}

# Main entry point of the app
def main():
    if not 'SUDO_UID' in os.environ.keys():
        print ("Program requires superuser privileges")
        sys.exit(1)
    
    num_attempts = DEFAULT_ATTEMPTS_ALLOWED
    timeout_sec = INDEFINITE_TIMEOUT_SECONDS
    
    # Get command line arguments
    full_cmd_arguments = sys.argv
    argument_list = full_cmd_arguments[1:]
    short_options = "ha:t:"
    long_options = ["help", "attempts=", "timeout="]
    found_a = False
    found_t = False
    
    try:
        arguments, values = getopt.getopt(argument_list, short_options, long_options)
                
    except getopt.error as err:
        # Output error, and return with an error code
        print (str(err))
        sys.exit(2)
        
    # Evaluate given options
    for current_argument, current_value in arguments:
        if current_argument in ("-h", "--help"):
            usage()
            sys.exit(2)
        elif current_argument in ("-a", "--attempts"):
            found_a = True
            try:
                num_attempts = int(current_value)
                print ("Number of allowed attempts for each ssh client before timeout: %s" %num_attempts)
            except:
                print ("Number of attempts value invalid: Default value of %d used" %num_attempts)
        elif current_argument in ("-t", "--timeout"):
            found_t = True
            try:
                timeout_sec = int(current_value)
                print ("Timeout of %d seconds will be given after number of allowed attempts exceeded" %timeout_sec)
            except:
                print ("Timeout value invalid: Indefinite timeout enforced")
    
    if not found_a or not found_t:
        usage()
        sys.exit(2)
         
    blocked_clients = threading.Thread(target=check_blocked_clients, args=(num_attempts,), daemon=True)
    blocked_clients.start()
    
    check_secure_logs(num_attempts, timeout_sec)
    
# This is executed when run from the command line
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        subprocess.run(["iptables", "-F"])
        print("Shutdown Application!")
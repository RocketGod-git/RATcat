print("""
__________                  __             __     ________             .___ 
\______   \  ____    ____  |  | __  ____ _/  |_  /  _____/   ____    __| _/ 
 |       _/ /  _ \ _/ ___\ |  |/ /_/ __ \\   __\/   \  ___  /  _ \  / __ |  
 |    |   \(  <_> )\  \___ |    < \  ___/ |  |  \    \_\  \(  <_> )/ /_/ |  
 |____|_  / \____/  \___  >|__|_ \ \___  >|__|   \______  / \____/ \____ |  
        \/              \/      \/     \/               \/              \/  
RATcat by RocketGod
""")

import os
import subprocess
import sys
import platform
import socket

# Function to handle yes/no questions
def ask_yes_no(question, default="yes", color='cyan'):
    valid = {"yes": True, "y": True, "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "

    while True:
        choice = input(colored(question + prompt, color)).lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            print(colored("Please respond with 'yes' or 'no' (or 'y' or 'n').", 'red'))

# Function to check if a module is installed
def is_module_installed(module_name):
    try:
        __import__(module_name)
    except ImportError:
        return False
    else:
        return True

# Function to install a module
def install_module(module_name):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])
    except subprocess.CalledProcessError:
        print(f"Failed to install {module_name}.")
        print("Please manually install it by running: ")
        print(f"pip install {module_name}")
        sys.exit()

# List of required modules
required_modules = ["psutil", "prettytable", "termcolor"]

# Check if the required modules are installed
for module in required_modules:
    if not is_module_installed(module):
        if ask_yes_no(f"The module '{module}' is not installed. Do you want to install it now?", default="no"):
            install_module(module)
        else:
            print("This script requires all the necessary modules to be installed. Exiting...")
            sys.exit()

# After checking for necessary modules, import them
import psutil
from prettytable import PrettyTable
from termcolor import colored
import logging

# Set default CPU and Memory thresholds
cpu_threshold_default = 50.0
mem_threshold_default = 50.0

try:
    # Get the CPU and Memory thresholds
    cpu_threshold = float(input(f"Enter the CPU usage threshold (in percent, default is {cpu_threshold_default}): ") or cpu_threshold_default)
    mem_threshold = float(input(f"Enter the Memory usage threshold (in percent, default is {mem_threshold_default}): ") or mem_threshold_default)
    
    # Get the directories where suspicious processes might run from
    print("We will check for processes running from certain directories that might be suspicious.")
    print("By default, we include 'AppData' on Windows and '/tmp' on Linux.")
    print("You can add more directories to this list. For example, you could input 'C:\\Program Files (x86),C:\\Windows\\Temp'")
    custom_dirs = input("Enter any additional directories from which suspicious processes might run (separated by a comma): ").split(',')
    # If the user didn't enter any directories, use an empty list
    if not custom_dirs[0]:  
        custom_dirs = []
    # Always include the default directories
    if platform.system() == 'Windows':
        suspicious_dirs = ['AppData'] + custom_dirs
    else:
        suspicious_dirs = ['/tmp'] + custom_dirs

    # Ask if the user wants to save the output to a log file
    if ask_yes_no("Do you want to save the output to a log file?", default="no"):
        while True:
            log_file = input("Enter the file to save the log: ")
            if os.path.exists(log_file):
                if ask_yes_no("The file already exists. Do you want to overwrite it?", default="no"):
                    break
            else:
                break

        # Ask for the log level
        log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        log_level = input(f"Enter the log level ({', '.join(log_levels)}, default is INFO): ").upper()
        if log_level == '':
            log_level = 'INFO'
            print("Using default log level: INFO.")
        elif log_level not in log_levels:
            print("Invalid log level. Defaulting to INFO.")
            log_level = 'INFO'

        # Set up logging
        try:
            logging.basicConfig(filename=log_file, level=getattr(logging, log_level))
        except Exception as e:
            print(colored(f"Error setting up logging: {e}", 'red'))
    else:
        logging.basicConfig(level=logging.INFO)

except KeyboardInterrupt:
    print("\nInterrupted by user. Exiting...")
    sys.exit()
except ValueError:
    print("Invalid input. Please enter a number.")
    sys.exit()

# Function to check for suspicious processes
def check_processes():
    print(colored("\nChecking for suspicious processes...", 'yellow'))
    suspicious_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'exe']):
        reason = ''
        if proc.info['cpu_percent'] > cpu_threshold:
            reason += 'High CPU usage; '
        if proc.info['memory_percent'] > mem_threshold:
            reason += 'High memory usage; '
        if proc.info['exe'] and any(dir in proc.info['exe'] for dir in suspicious_dirs):
            reason += f"Running from suspicious directory ({', '.join(suspicious_dirs)}); "
        
        if reason:  # if the reason string is not empty, the process is suspicious
            proc_info = proc.info
            proc_info['reason'] = reason.rstrip('; ')  # remove trailing semicolon and space
            suspicious_processes.append(proc_info)

    if suspicious_processes:
        print(colored("Found suspicious processes:", 'red'))
        table = PrettyTable(['PID', 'Name', 'Username', 'CPU %', 'Memory %', 'Exe', 'Reason'])
        for proc in suspicious_processes:
            table.add_row([proc['pid'], proc['name'], proc['username'], proc['cpu_percent'], proc['memory_percent'], proc['exe'], proc['reason']])
        print(colored(table, 'red'))
        logging.warning(f"Suspicious processes detected: {suspicious_processes}")
    else:
        print(colored("No suspicious processes found.", 'green'))

def check_network():
    print(colored("\nChecking for suspicious network connections...", 'yellow'))
    suspicious_connections = []
    for conn in psutil.net_connections(kind='inet'):
        reason = ''
        if conn.status == 'LISTEN':
            reason += 'Listening for connections; '
        if conn.raddr:
            if conn.raddr.ip != '127.0.0.1' and conn.raddr.ip != '::1':
                reason += 'Connected to external IP; '

        if reason:  # if the reason string is not empty, the connection is suspicious
            conn_info = conn._asdict()  # convert namedtuple to dictionary
            conn_info['reason'] = reason.rstrip('; ')  # remove trailing semicolon and space
            suspicious_connections.append(conn_info)

    if suspicious_connections:
        print(colored("Found suspicious network connections:", 'red'))
        table = PrettyTable(['PID', 'Local address', 'Remote address', 'Status', 'Reason'])
        for conn in suspicious_connections:
            table.add_row([conn['pid'], f"{conn['laddr'][0]}:{conn['laddr'][1]}", f"{conn['raddr'][0]}:{conn['raddr'][1]}" if conn['raddr'] else '', conn['status'], conn['reason']])
        print(colored(table, 'red'))
        logging.warning(f"Suspicious network connections detected: {suspicious_connections}")
    else:
        print(colored("No suspicious network connections found.", 'green'))

# Perform the process and network checks
try:
    check_processes()
    check_network()
except Exception as e:
    print(colored(f"An error occurred: {e}", 'red'))
    sys.exit()
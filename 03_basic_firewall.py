import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP
from email.message import EmailMessage
from app2 import password
import ssl
import smtplib

sender = ''
sender_password = password
reciever = ''

#Sets max allowed packet transfer speed:
THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

# Read IPs from a file
def read_ip_file(filename):
    with open(filename, "r") as file:
        #List comprehension:
        ips = [line.strip() for line in file]
    return set(ips)

# Check for Nimda worm signature
def is_nimda_worm(packet):
    #(Port No.80 indicates a TCP request)
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = packet[TCP].payload
        return "GET /scripts/root.exe" in str(payload)

    return False

# Log events to a file
def log_event(message):
    log_folder = "logs"
    #Creates folder if it doesen't exist yet
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folder, f"log_{timestamp}.txt")
    
    with open(log_file, "a") as file:
        file.write(f"{message}\n")

def packet_callback(packet):
    #Extracts IP address
    src_ip = packet[IP].src

    #Check if IP is in the whitelist
    if src_ip in whitelist_ips:
        return

    # Check if IP is in the blacklist
    if src_ip in blacklist_ips:
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking blacklisted IP: {src_ip}")
        return
    
    # Check for Nimda worm signature
    if is_nimda_worm(packet):
        print(f"Blocking Nimda source IP: {src_ip}")
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking Nimda source IP: {src_ip}")
        subject =(f"Nimda Worm Detected") 
        body=(f"Nimda worm packet detected. Source IP ({src_ip}) blocked.")
        # Email Message code based on tutorial based on Youtuber 'Code with Tomi'
        email = EmailMessage()
        email['From'] = sender
        email['To'] = reciever
        email['Subject'] = subject
        email.set_content(body)

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL('smtp.proton.me',465, context=context) as smtp:
            smtp.login(sender, sender_password)
            smtp.sendmail(sender, reciever, email.as_string())


        return

    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    #DOS detector again:

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval

            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                log_event(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time
#"Main Guard" function
if __name__ == "__main__":
    if os.geteuid() != 0:
        #Root Privilege disclaimer
        print("This script requires root privileges.")
        sys.exit(1)

    # Import whitelist and blacklist IPs
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    #Sniffs IP protocol packets only
    sniff(filter="ip", prn=packet_callback)

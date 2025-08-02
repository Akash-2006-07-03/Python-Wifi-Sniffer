from scapy.all import *
from datetime import datetime

interface="wlan0mon"
probereq=[]

def sniffing(p):
	if p.haslayer(Dot11ProbeReq):
	  netname=p.getlayer(Dot11ProbeReq).info
	  if netname not in probereq:
	    probereq.append(netname)
	    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	    print(f"{timestamp}  ![+] Detected new Probe Request: " +  netname.decode(errors="ignore") + "\n  Sender: " + p.addr2)
	    with open("probe_det.txt","a") as f:
	      f.write(f"{timestamp} SSID: {netname.decode(errors="ignore")}, Sender: {p.addr2}\n")


try:
  sniff(iface=interface, prn=sniffing)
except KeyboardInterrupt:
  print("\n[!] stopped sniffing")





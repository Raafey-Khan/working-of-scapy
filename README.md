pip install scapy


from scapy.all import ARP, Ether, srp

def scan(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    active_hosts = []
    for sent, received in result:
        active_hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return active_hosts

if __name__ == "__main__":
    target_ip_range = "Enter you ip here/24"  # Adjust the IP range as needed

    active_hosts = scan(target_ip_range)
    for host in active_hosts:
        print(f"IP: {host['ip']} | MAC: {host['mac']}")



from scapy.all import sniff, IP, TCP, UDP, ICMP
import time

def packet_callback(packet):
    # This might be used for real-time processing, but for now we'll process the list returned by sniff
    pass

def capture_packets(interface=None, count=10, filter_str=None):
    try:
        # scapy sniff
        # if interface is None, scapy sniffs on all interfaces or the default one
        packets = sniff(count=count, filter=filter_str, iface=interface, timeout=10)
        
        results = []
        for pkt in packets:
            pkt_info = {
                "time": time.strftime('%H:%M:%S', time.localtime(pkt.time)),
                "src": "N/A",
                "dst": "N/A",
                "proto": "Other",
                "summary": pkt.summary(),
                "len": len(pkt)
            }
            
            if IP in pkt:
                pkt_info["src"] = pkt[IP].src
                pkt_info["dst"] = pkt[IP].dst
                pkt_info["proto"] = "IP"
                
            if TCP in pkt:
                pkt_info["proto"] = "TCP"
            elif UDP in pkt:
                pkt_info["proto"] = "UDP"
            elif ICMP in pkt:
                pkt_info["proto"] = "ICMP"
                
            results.append(pkt_info)
            
        return results
    except Exception as e:
        return {"error": str(e)}

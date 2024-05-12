# Tactical Analysis Approach
***Note:*** This page is a work in progress and will be updated as time permits.

The following is a high-level approach to tactical analysis of packet captures. The approach is designed to be fast and effective, and can be used to quickly triage and understand traffic in a packet capture file.
1. Understand what kind of traffic you are dealing with.
2. Filter out the traffic you need to analyze.
3. Extract the data you need.
4. Enrich the data with additional context.
5. Present the findings in a clear and concise manner.

## Understanding the Traffic
While there are many ways to achieve this, one of the fastest ways I've come across to understand what is in a traffic capture is the use of the "demo" tool NDPIReader (https://github.com/ntop/nDPI/tree/dev/example).  

The tool was build to demonstrate the capabilities of the NDPI library, however provides a very fast way to understand flows, protocols and possible applications risks in a traffic capture. It does mischaracterize some communications, but for an initial high level understanding of a capture file, it is extremely useful.

An example of how to use the tool is as follows:
```bash
apt-get update && apt-get install ndpi
ndpiReader -i <input.pcap> -K json -k outfile | tee -a summary.txt
```
This will output a JSON file with the results of the analysis, and a summary of the analysis to the summary text file.

Other tools that can be used to understand traffic are Capinfos, Tshark, Zeek, and Suricata (and others).

## Pre-Filtering
A significant performance improvement can be gained by pre-filtering down to traffic you are assessing.  
As with each of the steps, filtering traffic can be done in many ways. The more ways you know, the better prepared you'll be, however an effective way is to leverage tcpdump to segment data you require from larger captures.

Segmentation can also be done in multiple ways. For example, by flow using the communication 5-tuple (source IP, source port, destination IP, destination port, protocol), by protocol alone using known ports, or by more targeted techniques, such as using magic bytes in the application headers.
Filtering magic bytes is a little more complicated, but once understood can be very powerful. The following example covers this approach for HTTP GET requests, with subsequent explanation:
```bash
tcpdump -r infile.pcap -s 0 -A 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504F5354'
```
Expression Breakdown:

```
tcp[((tcp[12:1] & 0xf0) >> 2):4]
```

This part of the filter performs several operations to pinpoint and extract specific data from a TCP packet:

```
tcp[12:1]:
```
Accesses the TCP header, specifically the byte at offset 12. This byte includes the TCP header's length among other details.
```
& 0xf0:
```

A bitwise AND operation that masks the lower 4 bits of the byte, isolating the upper 4 bits which denote the TCP header length in 32-bit words.
```
>> 2:
```
A right shift operation that converts the header length from 32-bit words to bytes (since each word is 4 bytes).
```
tcp[((tcp[12:1] & 0xf0) >> 2):4]:
```
This refined expression calculates where the TCP header ends and extracts the next 4 bytes from the TCP payload, immediately following the TCP header.
Matching Specific Payload:
```
= 0x504F5354:
```
The extracted 4 bytes are compared against the hexadecimal value 0x504F5354. This corresponds to the ASCII string "POST".
The purpose here is to identify packets where the first four bytes of the TCP payload are "POST," which is indicative of an HTTP POST request.  
***Reference:***
https://www.middlewareinventory.com/blog/tcpdump-capture-http-get-post-requests-apache-weblogic-websphere/#How_to_capture_All_incoming_HTTP_GET_traffic_or_requests



### Further Examples:
#### ARP
```bash
tcpdump -r infile.pcap arp -w filtered.pcap
```
#### ICMP
```bash
tcpdump -r infile.pcap icmp -w filtered.pcap
```
#### SNMP
https://www.rfc-editor.org/rfc/rfc1157
```bash
tcpdump -r infile.pcap -T snmp -n dst portrange 161-162
```
#### Cisco Discovery Protocol (CDP)
https://learningnetwork.cisco.com/s/article/cisco-discovery-protocol-cdp-x
```bash
tcpdump -i eth0 ether dst 01:00:0c:cc:cc:cc
```
#### Rapid Spanning Tree Protocol (RSTP)
https://study-ccna.com/what-is-rstp/
```bash
tcpdump -l -r infile.pcapng -v -nn -e 'ether host 01:00:0c:cc:cc:cd'
```
#### Link-layer Discovery Protocol (LLDP)
```bash
tcpdump -l -r infile.pcapng -v -nn -e 'ether host 01:80:c2:00:00:0e'
```
#### Syslog
**Syslog facilities and levels:**
https://success.trendmicro.com/dcx/s/solution/TP000086250?language=en_US
```bash
tcpdump -r infile.pcap udp port 514
```
Filtering on the PRI header angled brackets:
```bash
tcpdump -r infile.pcap 'udp[8:1] = 0x3c and (udp[10:1] = 0x3e or udp[11:1] = 0x3e or udp[12:1] = 0x3e)'
```
#### HTTP
##### All HTTP
```bash
tcpdump -r infile.pcap -s 0 'tcp port http'
```
##### HTTP GET Requests
```bash
tcpdump -r infile.pcap -s 0 -A 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'
```
##### HTTP POST Requests
```bash
```bash
tcpdump -r infile.pcap -s 0 -A 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504F5354'
```
#### TLS Handshakes
```bash
tcpdump -r infile.pcap -s 0 -A 'tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16 and (tcp[((tcp[12:1] & 0xf0) >> 2) + 1:2] = 0x0301 or tcp[((tcp[12:1] & 0xf0) >> 2) + 1:2] = 0x0302 or tcp[((tcp[12:1] & 0xf0) >> 2) + 1:2] = 0x0303)'
```
***Explanation:***
> 0x16: Content Type = Handshake
> 0x0301: TLS version (TLS v1.0 in this instance)
> We need to split the bytes into two filters as tcpdump only accept 1, 2 or 4 byte sequences

#### Outbound Communications (RFC-1918)
https://www.rfc-editor.org/rfc/rfc1918
```bash
tcpdump -r infile.pcap -nn 'ip and not (dst net 10.0.0.0/8) and not (dst net 192.168.0.0/16) and not (dst net 172.16.0.0/12) and not (dst net 224.0.0.0/4) and not (dst net 169.254.0.0/16) and not (dst net 240.0.0.0/4)' |cut -d " " -f 3,5 | cut -d ":" -f1| awk -F " " '{print $1"."$2}' | awk -F "." '{print $1"."$2"."$3"."$4, $6"."$7"."$8"."$9":"$10}' |sort|uniq -c | sort -rn | head -n 20 
```

#### Inbound Communications (RFC-1918)
https://www.rfc-editor.org/rfc/rfc1918
```bash
tcpdump -r infile.pcap -nn 'ip and not (src net 10.0.0.0/8) and not (src net 192.168.0.0/16) and not (src net 172.16.0.0/12) and not (src net 224.0.0.0/4) and not (src net 169.254.0.0/16) and not (src net 240.0.0.0/4)' |cut -d " " -f 3,5 | cut -d ":" -f1| awk -F "." '{print $1"."$2"."$3"."$4":"$5"."$6"."$7"."$8}' |sort| uniq -c | sort -rn | head -n 20
```

#### Identify traffic with VLAN tags
```bash
tcpdump -r sample.pcap 'vlan and host 10.30.66.37'
```

## Additional Reading / References
TCPDUMP101:  
https://tcpdump101.com/#  

TCPDump-Stats:  
https://www.zenetys.com/en/tips-tricks-quick-traffic-stats-from-your-pcap-files/  

nDPI Quick Start:
https://www.ntop.org/wp-content/uploads/2013/12/nDPI_QuickStartGuide.pdf

HackerTarget TCPDump Examples:
https://hackertarget.com/tcpdump-examples/

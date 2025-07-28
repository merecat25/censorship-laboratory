---
title: "Censored Lab"
date: 2025-05-31T13:28:03-04:00
draft: false
---
Welcome to Censored Lab!

![lab pic](/images/lab_picture.jpg)

### General Information

For general information about how censorship works, and information about IP Addresses, DNS, Deep Packet Inspection, and other subjects, see:

[Censorship and Surveillance in the Digital Age: Part One](https://merecat25.substack.com/p/censorship-and-surveillance-in-the)

[Censorship and Surveillance in the Digital Age: Part Two](https://merecat25.substack.com/p/censorship-and-surveillance-in-the-5a4)

[Golden Shield: The Inner Workings of China's Great Firewall](https://merecat25.substack.com/p/golden-shield-the-inner-workings)

[Behind the Blackout: The Mechanisms, Monitoring, and Impact of Internet Shutdowns](https://merecat25.substack.com/p/golden-shield-the-inner-workings)

See also the [Resources Page](https://merecat25.substack.com/p/circumvention-tools) of this blog for links to anti-censorship tools and other informational sites.

### Lab Setup

For simulating online censorship, a lab can be set up using Virtualbox installed on a host computer. Virtualbox can be downloaded for **Windows, MacOS**, and **Linux** from [HTTPS://www.virtualbox.org](https://www.virtualbox.org/). Be sure to download and install the **extension pack** as well. For Ubuntu and other Linux distros, be sure to download the correct edition (i.e. Ubuntu 24.02) because unmet dependencies can be a problem. I recommend four different virtual machines:

- **IPFire** as a firewall. Will be used for simulating the actions of a government censor. [Download here](https://www.ipfire.org/downloads/ipfire-2.29-core194).
    
- **Windows 10** as one of the censored computers. Should have Psiphon, Lantern, Tor, and a VPN installed. Use the [Microsoft Media Creation Tool](https://www.microsoft.com/en-us/software-download/windows10).
    
- **Kali Linux** for running Wireshark. Can also be used as a censorship platform with iptables and dnsmasq (discussed later). [Download here](https://www.kali.org/).
    
- **Ubuntu 24.04** as another censored machine. [Download Here](https://ubuntu.com/download).
    

*Note: I have had different firewalls work better with certain hosts. IPFire works well on Windows, but other choices include OPNSense (complicated), PFSense (a little less complicated), ClearOS (hard to install) among others. IPFire is easy to install and configure.*

The initial setup will look like this:

![Network Diagram](/images/setup1.png)

The IPFire virtual machine (VM) acts as our firewall, hands out IP Addresses to the other VMs via DHCP, and acts as a DNS server. When IPFire is set up on Virtualbox, there is a GREEN interface and a RED interface. In our case, the green interface is set to the internal network and the red interface to NAT which provides internet access via the host computer. Instructions for installing IPFire on Virtualbox can be found [HERE](https://www.ipfire.org/docs/installation/virtual-box), and instructions for IPFire networking [HERE](https://www.ipfire.org/docs/installation/step5).

The subnet for the internal network is 192.168.1.0/24, and the IPFire VM has an IP Address of 192.168.1.1. Windows 10, Kali, and Ubuntu are all set to internal networking only. This means they can only access the internet via the firewall. So, network settings for all three need the following settings:

- Receive IP Address automatically (DHCP from IPFire)
    
- DNS server to IPFire IP Address (192.168.1.1)
    
- I disabled IPV6 for simplicity, but in real life IPV6 would also have to be blocked to censor access to DNA, etc.
    

For Kali, install Wireshark as follows (if not already installed);

```bash
sudo apt update
sudo apt install wireshark
```

### DNS Blocking and Poisoning

Blocking DNS can be challenging. Modern browsers will fallback to any available DNS servers unless they are all blocked. Blocking DNS (port 53) only works if the browsers don’t have HTTPS over DNS (Port 443). Blocking all traffic to 443 blocks all websites, not just censored sites. Windows caches DNS, so the cache has to be cleared for previously visited sites.

With port 53 and port 443 NOT blocked and DNS servers not blocked, an nslookup (Windows) or dig (Linux) for bbc.com is run and works. Accessing BBC on firefox while Wireshark is running shows the DNS requests:

![dns open](/images/dns_open.png)

Blocking all common DNS servers but not blocking all traffic to port 443 on IPFire and doing the same thing shows a different result. This involved adding rules blocking port 443 for

- **Cloudflare** 1.1.1.1, 1.0.0.1 2606:4700:4700::1111 (IPv6)
    
- **Google** 8.8.8.8, 8.8.4.4 2001:4860:4860::8888 (IPv6)
    
- **Quad9** 9.9.9.9, 149.112.112.112
    
- **NextDNS** 45.90.28.0/24, 45.90.30.0/24
    
- **OpenDNS** 208.67.222.222, 208.67.220.220
    
- **CleanBrowsing** 185.228.168.168, 185.228.169.168
    
- **AdGuard** 94.140.14.14, 94.140.15.15
    
- **Comodo Secure DNS** 8.26.56.26, 8.20.247.20
    
- **Neustar UltraDNS** 156.154.70.1, 156.154.71.1
    
- **Cloudflare for Families** 1.1.1.2, 1.0.0.2
    

When this is done, *ping 8.8.8.8* works because it doesn’t require DNS, but *dig google.com* does not work (DNS is blocked). Lantern also does NOT work with DNS blocked. Tor does not access BBC.com but will connect. Wireshark with filters for port 53 or 443 doesn’t show any captures. This mimics real-world censorship in a country like China.

So, how does a person surfing the web in China get to a website since all foreign DNS serves are blocked? China has servers run by the government. This gives the PRC tight control over what sites can be reached (combined with other methods of censorship). The state controlled DNS servers can be configured to allow access to approved sites or to block or poison requests for censored sites.

**DNS poisoning** can be demonstrated using dnsmasq on Kali. This requires a reconfiguration of the Virtualbox network so traffic from Windows or Ubuntu goes through Kali instead of IPFire. The new setup will look like this:

![setup two](/images/setup2.png)

Kali has dnsmasq installed and also has the Linux firewall iptables. The dnsmasq program will be used to mimic DNS poisoning and can be installed with the commands:

```bash
sudo apt update
sudo apt install dnsmasq
```

**DNS on Ubuntu is set to Kali’s IP**. To setup dnsmasq on Kali to block or poison DNS to certain sites, the config file needs to be edited:

```bash
sudo nano /etc/dnsmasq.conf
```

Then edit the file:

```bash
# Basic DNS settings
port=53
domain-needed
bogus-priv
no-resolv

# Use public DNS servers upstream
server=1.1.1.1
server=8.8.8.8

# Spoofed/poisoned domains
address=/facebook.com/0.0.0.0
address=/youtube.com/0.0.0.0
address=/bbc.com/0.0.0.0
address=/twitter.com/0.0.0.0
address=/instagram.com/0.0.0.0
address=/wikipedia.org/0.0.0.0
```


Save this then exit. Now when Ubuntu is forced to use Kali’s DNS, *dig facebook.com* does not work, but *dig google.com* does. The DNS is poisoned and redirects to 0.0.0.0. This shows how DNS could be blocked by cenosrs. The problem with this method is that the censored computer (Ubuntu) has to have to many configuration changes to make it work. (I had to edit two other files to really block DNS). With Windows 10 instead of Ubuntu, though, DNS was blocked with just dnsmasq changes (the browser could not reach any blocked sites, but could reach any other site).

If Wireshark is run for the requests and filtered for DNS and DNS over HTTPS, surfing to google.com shows the normal DNS request:

![google dns](/images/censored-lab/google_dns.png)

bbc.com on the other hand, shows:

![bbc dns](/images/censored-lab/bbc.png)

What’s really interesting, this was done with DNS over HTTPS off in Firefox. If Privacy and Security settings are changed to use DNS over HTTPS instead, the sites can be accessed. To block this too, DNS over port 443 for all or most common DNS servers has to be blocked as above.

Another interesting thing we can do is set up dnsmasq on Kali to log all attempts to reach blocked sites. We have to modify the config dnsmasq config file again and add

```bash
log-queries
log-facility=/var/log/dnsmasq.log
```

the restart dnsmasq:

```bash
sudo systemctl restart dnsmasq
```

and start logging:

```bash
sudo tail -f /var/log/dnsmasq.log
```

If the user on Windows tries to browse to facebook.com, the censor will see

![log](/images/bash.png)

## Conclusion of This Section

The goal of all of this is to simulate how a repressive government like China could block and poison DNS. One thing to add: since I am not an expert in networking (although I have a Network+ certification), **I LIBERALLY relied on ChatGPT and Perplexity to help resolve problems and develop testing ideas**. All the writing is mine, but much of the technical stuff would have been difficult without AI help.

### **Introduction: Implementing SNI-Based Censorship Using Suricata and iptables**

In this lab, I implemented a basic deep packet inspection (DPI) censorship mechanism that mirrors techniques used by real-world network censors. The goal was to identify and block access to a specific website—in this case, `www.torproject.org`—based on the Server Name Indication (SNI) field of encrypted TLS traffic.

To accomplish this, I configured Suricata, a powerful open-source intrusion detection system, to inspect network traffic on the gateway (Kali Linux) and generate an alert whenever an outbound TLS handshake contained the SNI `torproject.org`. A custom rule was created in Suricata to match on this domain name, and its alerts were monitored in real time using a Bash script.

Upon detecting the SNI match, the script extracted the source IP address from the Suricata alert and dynamically inserted a `DROP` rule into the system’s `iptables` FORWARD chain. This blocked further traffic from the offending client. Additional safeguards were implemented to ensure IPv6 traffic—commonly used to bypass IPv4-based filtering—was also disabled or explicitly blocked.

This configuration demonstrates a simple but effective censorship model that can:

- Detect access to targeted encrypted services via SNI
    
- Dynamically respond by blocking client traffic at the firewall level
    
- Be expanded to include multiple domains, timed bans, or automated logging/reporting
    

The result is a functioning prototype of content-based network control that highlights both the feasibility and limitations of SNI-based censorship in modern network environments.

* * *

Suricata Setup

```bash
`sudo apt updatesudo apt install suricata`
```

Confirm it is working

```bash
`sudo suricata -i eth0 -v`
```

Be sure config file is set for local.rules

```bash
`sudo nano /etc/suricata/suricata.yaml`
```

and be sure says

```bash
`rule-files:  - local.rules`
```

(It will likely say suricata.rules so change it)

Edit rules

```bash
`sudo nano /var/lib/suricata/rules/local.rules`
```

Then

```bash
`sudo suricata-updatesudo systemctl restart suricata`
```

Now, if you go to te Windows VM and surf to torproject.org, you will get and alert if you check

```bash
`sudo tail -f /var/log/suricata/fast.log`
```

Suricata alert for torproject.org

```bash
`{"timestamp":"2025-06-14T13:41:14.161249-0400","flow_id":609456373043862,"in_iface":"eth0","event_type":"alert","src_ip":"192.168.1.101","src_port":50580,"dest_ip":"204.8.99.146","dest_port":443,"proto":"TCP","pkt_src":"wire/pcap","tx_id":0,"alert":{"action":"allowed","gid":1,"signature_id":100001,"rev":1,"signature":"Blocked SNI contains torproject.org","category":"","severity":3},"tls":{"sni":"www.torproject.org","version":"TLS 1.3"},"app_proto":"tls","direction":"to_server","flow":{"pkts_toserver":5,"pkts_toclient":5,"bytes_toserver":2197,"bytes_toclient":3208,"start":"2025-06-14T13:41:14.076364-0400","src_ip":"192.168.1.101","dest_ip":"204.8.99.146","src_port":50580,"dest_port":443}}`
```

* * *

Now, we can go back to our IP and DNS blocking and add rules to block Tor. We could also set Suricata to trigger a rule blocking torproject.org.  
This is a little more complicated.

First, Kali has to be set as the gateway (IPFire is off)

On Virtualbox, Kali's first interface is NAT, the second in the internal network.

Go to

```bash
`sudo nano /etc/network/interfaces`
```

and add

```bash
`auto eth0iface eth0 inet dhcpauto eth1iface eth1 inet static  address 192.168.56.1  netmask 255.255.255.0`
```

Then enable NAT and FORWARD rules on Kali

```bash
`# Enable IP forwardingecho 1 | sudo tee /proc/sys/net/ipv4/ip_forwardsudo sysctl -w net.ipv4.ip_forward=1# Make it permanentsudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf`
```

Then add the Forwarding Rules

```bash
`# NAT for outbound trafficsudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE# Allow forwardingsudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPTsudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT`
```

Add Suricata TLS rule

```bash
`sudo nano /var/lib/suricata/rules/local.rules`
```

Add the rule (all in one line)

```bash
`alert tls any any -> any any (msg:"Blocked SNI contains torproject.org"; tls_sni; content:"torproject.org"; nocase; sid:100001; rev:1;)`
```

Run Suricata

```bash
`sudo suricata -c /etc/suricata/suricata.yaml -i eth1`
```

Add the IP-Blocking Script to block torproject.org in real time

```bash
`sudo nano /usr/local/bin/suri-block.sh`
```

```bash
`#!/bin/bashLOGFILE="/var/log/suri-blocked.log"EVE_FILE="/var/log/suricata/eve.json"# Log the user running the scriptecho "Running as user: $(whoami)" >> /tmp/suri-script.logtail -Fn0 "$EVE_FILE" | jq -c 'select(.event_type=="alert" and .alert.signature_id==100001)' | while read -r line; do    SRC_IP=$(echo "$line" | jq -r '.src_ip')    MSG=$(echo "$line" | jq -r '.alert.signature')    DATE=$(date +'%Y-%m-%d %H:%M:%S')    # Debug log    echo "[DEBUG] Attempting to block $SRC_IP at $DATE" >> /tmp/suri-debug.log    # Block source IP on FORWARD chain if not already blocked    if ! iptables -C FORWARD -s "$SRC_IP" -j DROP 2>/dev/null; then        iptables -A FORWARD -s "$SRC_IP" -j DROP 2>> /var/log/suri-iptables-errors.log        if [ $? -eq 0 ]; then            echo "$DATE - Blocked $SRC_IP for: $MSG" | tee -a "$LOGFILE"        else            echo "$DATE - Failed to block $SRC_IP" >> /var/log/suri-iptables-errors.log        fi    fidone`
```

Make it executable

```bash
`sudo chmod +x /usr/local/bin/suri-block.sh`
```

Then run it

```bash
`sudo /usr/local/bin/suri-block.sh`
```

When I tried to go to www.torproject.org on Windows, I get the following on Suricata

```bash
`2025-06-14 20:46:05 - Blocked 192.168.56.101 for: Blocked SNI contains torproject.org`
```

Note, to make this work, I disabled ipv6 on Kali

```bash
`sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1`
```

Firefox does not reach torproject.org, and If I check

```bash
`sudo iptables -L FORWARD -n --line-numbers`
```

I get

```bash
`Chain FORWARD (policy ACCEPT)num  target     prot opt source               destination         1    DROP       all  --  192.168.56.101       0.0.0.0/0`
```

So, browsing to torproject.org triggers an alert as seen in the first part, then blocks access to the website by triggering an iptables rule!

If we start Tor Browser and go to www.torproject.org, it does connect and the rule is not triggered. I ran

```bash
sudo tcpdump -i eth1 host 192.168.56.101`
```

and got

```bash
`14:16:16.434242 ARP, Request who-has 192.168.56.101 tell 192.168.56.1, length 2814:16:16.435977 ARP, Reply 192.168.56.101 is-at 08:00:27:7f:00:56 (oui Unknown), length 4614:16:17.388364 IP static.166.233.108.65.clients.your-server.de.9001 > 192.168.56.101.49191: Flags [P.], seq 387115844:387116380, ack 150732934, win 65535, length 53614:16:17.452908 IP 192.168.56.101.49191 > static.166.233.108.65.clients.your-server.de.9001: Flags [.], ack 536, win 64240, length 014:16:19.382150 IP v2202504171896332841.powersrv.de.45785 > 192.168.56.101.49192: Flags [P.], seq 386754002:386754538, ack 948302314, win 65535, length 53614:16:19.468551 IP 192.168.56.101.49192 > v2202504171896332841.powersrv.de.45785: Flags [.], ack 536, win 63704, length 014:16:25.431883 IP static.166.233.108.65.clients.your-server.de.9001 > 192.168.56.101.49191: Flags [P.], seq 536:1072, ack 1, win 65535, length 53614:16:25.480870 IP 192.168.56.101.49191 > static.166.233.108.65.clients.your-server.de.9001: Flags [.], ack 1072, win 63704, length 014:16:26.672183 IP v2202504171896332841.powersrv.de.45785 > 192.168.56.101.49192: Flags [P.], seq 536:1072, ack 1, win 65535, length 53614:16:26.717379 IP 192.168.56.101.49192 > v2202504171896332841.powersrv.de.45785: Flags [.], ack 1072, win 63168, length 014:16:29.469297 IP 192.168.56.101.49192 > v2202504171896332841.powersrv.de.45785: Flags [P.], seq 1:537, ack 1072, win 63168, length 53614:16:29.469907 IP v2202504171896332841.powersrv.de.45785 > 192.168.56.101.49192: Flags [.], ack 537, win 65535, length 014:16:29.707100 IP v2202504171896332841.powersrv.de.45785 > 192.168.56.101.49192: Flags [P.], seq 1072:1608, ack 537, win 65535, length 53614:16:29.710099 IP 192.168.56.101.49192 > v2202504171896332841.powersrv.de.45785: Flags [P.], seq 537:1587, ack 1608, win 64240, length 105014:16:29.710976 IP v2202504171896332841.powersrv.de.45785 > 192.168.56.101.49192: Flags [.], ack 1587, win 65535, length 014:16:29.932352 IP v2202504171896332841.powersrv.de.45785 > 192.168.56.101.49192: Flags [.], seq 1608:3068, ack 1587, win 65535, length 146014:16:29.932408 IP v2202504171896332841.powersrv.de.45785 > 192.168.56.101.49192: Flags [.], seq 3068:4528, ack 1587, win 65535, length 146014:16:29.932410 IP v2202504171896332841.powersrv.de.45785 > 192.168.56.101.49192: Flags [P.], seq 4528:5228, ack 1587, win 65535, length 70014:16:29.933267 IP 192.168.56.101.49192 > v2202504171896332841.powersrv.de.45785: Flags [.], ack 5228, win 64240, length 014:16:30.061351 IP v2202504171896332841.powersrv.de.45785 > 192.168.56.101.49192: Flags [P.], seq 5228:5764, ack 1587, win 65535, length 53614:16:30.063834 IP 192.168.56.101.49192 > v2202504171896332841.powersrv.de.45785: Flags [P.], seq 1587:2637, ack 5764, win 63704, length 105014:16:30.064440 IP v2202504171896332841.powersrv.de.45785 > 192.168.56.101.49192: Flags [.], ack 2637, win 65535, length 014:16:30.074614 IP static.166.233.108.65.clients.your-server.de.9001 > 192.168.56.101.49191: Flags [P.], seq 1072:1608, ack 1, win 65535, length 53614:16:30.148596 IP 192.168.56.101.49191 > static.166.233.108.65.clients.your-server.de.9001: Flags [.], ack 1608, win 63168, length 014:16:30.205620 IP 192.168.56.101.49191 > static.166.233.108.65.clients.your-server.de.9001: Flags [.], seq 1:1461, ack 1608, win 63168, length 146014:16:30.205635 IP 192.168.56.101.49191 > static.166.233.108.65.clients.your-server.de.9001: Flags [P.], seq 1461:1565, ack 1608, win 63168, length 10414:16:30.205636 IP 192.168.56.101.49192 > v2202504171896332841.powersrv.de.45785: Flags [P.], seq 2637:3173, ack 5764, win 63704, length 53614:16:30.206004 IP static.166.233.108.65.clients.your-server.de.9001 > 192.168.56.101.49191: Flags [.], ack 1461, win 65535, length 014:16:30.206061 IP static.166.233.108.65.clients.your-server.de.9001 > 192.168.56.101.49191: Flags [.], ack 1565, win 65535, length 014:16:30.206379 IP v2202504171896332841.powersrv.de.45785 > 192.168.56.101.49192: Flags [.], ack 3173, win 65535, length 014:16:30.269164 IP v2202504171896332841.powersrv.de.45785 > 192.168.56.101.49192: Flags [P.], seq 5764:6300, ack 3173, win 65535, length 53614:16:30.273408 IP v2202504171896332841.powersrv.de.45785 > 192.168.56.101.49192: Flags [.], seq 6300:7760, ack 3173, win 65535, length 146014:16:30.273481 IP v2202504171896332841.powersrv.de.45785 > 192.168.56.101.49192: Flags [P.], seq 7760:9220, ack 3173, win 65535, length 146014:16:30.274311 IP 192.168.56.101.49192 > v2202504171896332841.powersrv.de.45785: Flags [.], ack 9220, win 64240, length 014:16:30.312728 IP v2202504171896332841.powersrv.de.45785 > 192.168.56.101.49192: Flags [.], seq 9220:10680, ack 3173, win 65535, length 1460`
```

So we captured Windows communicating on non standard ports:

9001 — commonly used by Tor relays

45785 — likely another Tor relay port

We could add a rule to Suricata to trigger an alert on port 9001

```bash
`alert tcp any any -> any 9001 (msg:"Tor ORPort Access Detected"; sid:100005; rev:1;)`
```

And we could look up know Tor relay IPs and block them

https://check.torproject.org/torbulkexitlist

https://metrics.torproject.org/collector.html

Then we could try to access sites using Tor pluggable transports like

- obfs4
    
- Snowflake
    
- Meek

## SNI and Keyword Filtering Continued

The idea behind this section of the lab is to demonstrate filtering via keyword or Server Name Indicator (SNI). The setup once again involves using Windows 10 as our censored VM and Kali (set up to forward traffic) as our censoring VM. Using Telegram as our circumvention tool, we can start with the command on Kali

```bash
tshark -i eth1 -Y "tls.handshake.extensions_server_name contains \"t.me\"" -T fields -e ip.dst -e tls.handshake.extensions_server_name
```

This monitors the eth1 interface for the SNI "t.me" and extracts the destination IP and the server name. With it we detect t.me in the unencrypted part of the TLS handshake.

We can use the same command for "telegram.org"

```bash
tshark -i eth1 -Y "tls.handshake.extensions_server_name contains \"telegram.org\"" -T fields -e ip.dst -e tls.handshake.extensions_server_name
```

Both VMs are started and then t.me and telegram.org are accessed via the browser. When t.me was accessed, we saw clear TLS handshakes containing the SNI, which could be monitored using tshark. The telegram.org script showed 0 packets, though.

Attempting to block t.me and telegram.org using iptables also showed an interesting result. Here are the iptables commands used:

```bash
sudo iptables -A OUTPUT -p tcp --dport 443 -m string --string "t.me" --algo bm -j DROP
sudo iptables -I OUTPUT -p tcp --dport 443 -m string --string "telegram.org" --algo bm -j DROP
sudo iptables -I FORWARD -p tcp --dport 443 -m string --string "t.me" --algo bm -j DROP
sudo iptables -I FORWARD -p tcp --dport 443 -m string --string "telegram.org" --algo bm -j DROP
```

When we go back to Windows, access to t.me is blocked, but telegram.org is reached easily. Why?

The answer lies in the use of QUIC, which telegram uses via HTTP/3. The handshake used by telegram.org used QUIC while t.me used the standard unencrypted TLS Handshake. QUIC uses UDP and encrypts even the equivalent of the SNI during the initial handshake, making it invisible to simple packet inspection tools like iptables. Because the iptables rules were written only for TCP, they had no effect on QUIC traffic, which uses UDP by default. The only way around this is to block QUIC UDP port 443.

```bash
sudo iptables -A OUTPUT -p udp --dport 443 -j DROP
```

This forces the connection to fall back to https, and it is subsequently blocked. An additional issue with trying to block using just an iptables match is that the string must match perfectly, or the connection isn't blocked. It is not a robust censorship method. This demonstrates both the power and the limitations of SNI-based filtering. While it’s effective against TLS over TCP where the SNI is visible, it fails against protocols like QUIC unless UDP is explicitly blocked — and even then, success depends on the browser’s fallback behavior.

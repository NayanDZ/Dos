# DOS/DDOS

DENIAL OF SERVICE ATTACKS

## What is DOS/DDOS Attack?
Denial of Service (DoS) Attack is a fatal attempt by an external agent to cause a situation where the actual resource becomes unavailable to the actual visitors or users. This is usually done by illegitimate traffic in the form of broken/unsolicited page access requests.
Distributed Denial of Service (DDoS) Attack is an advance form of DoS where the attacking agents are distributed over the huge network.

## How DoS Attacks are executed?
DoS Attacks are usually executed by flooding the target servers with unsolicited data packets in unprecedented manner. This may be done by misconfiguring network routers or by performing smurf attack on the victim servers. This results in “Capacity Overflow‟, followed by Max Out of system resources, which makes the target service unavailable, either temporarily or permanently to the intended users. 

DDoS attack the origin of unsolicited data packets (for the purpose of flooding the bandwidth/resource of the victim servers) are distributed over a large network. The overall mechanism of DDoS Attack involves a huge quantity of compromised computers connected to internet, governed by agent handlers, which are further controlled centrally by the actual attacker.

The massive number of compromised computers on the internet is then unknowingly governed by the source attacker to demand access to the targeted victim within a minimal time span, which further causes saturation of limited system resources and results in eventual shutdown of the targeted service.

The most common method employed to compromise massive amount of user agents on the internet is by plaguing as many computers as possible over the internet with malware/trojan. Such trojans can either spread via email attachments or via Peer-to-peer networks. Once the intended Trojan is silently installed on the uninformed computer agent, that user agent has actually been compromised, which is then called as a Zombie or Botnet. source attacker to indirectly command some or all its Zombie agents (or botnets) for demanding access to the target service.

## What are other variants of DoS attacks?
There are many other attacks of similar nature and purpose such as smurf attack, nuke bomb, ping of death, banana attack, phlashing among many others.
### How are they counteracted?
The best way to defend a web service from faltering due to DDoS attack is to keep backup resources of the system intact. As the aim of such attack is to max out system resources, if the system resources are already abundant and well prepared to face that sudden peak of traffic at any moment, most chances are that your web service will survive DoS (or even DDoS) attack.
### Two ways for dos attacks one is the lame way and the other is the elite way
### Lame way:
**Email Bombs:** it s the technique in which a person email A/C is flooded with emails; it’s the lamest form of DOS attack. All a person has to do is go on the net get some email bomber like UNA or KABOOM put the victims address and there ya go , his email address will be flooded with the unwanted emails, there is also another way put his email address into some porn subscription he will get bombed without you doing anything.
**Continuous login:** suppose a server is configured to allow only specified amount login attempts then ,and you know his username you can lock his account, by attempting to connect by his name to the server which will lock his account and there ya go , the legitimate user won’t be able to log in ,the reason, you locked his A/C.
Okay now the neophyte way, it’s not that elite way but somewhat better than the lame way, at least you are doing something technical.

## DDOS Attack Types:-
**1. Ping Of Death:** The ping of death attack sends oversized ICMP datagram’s (encapsulated in IP packets) to the victim. The Ping command makes use of the ICMP echo request and echo reply messages and it's commonly used to determine whether the remote host is alive. In a ping of death attack, however, ping causes the remote system to hang, reboot or crash. To do so the attacker uses, the ping command in conjunction with -l argument (used to specify the size of the packet sent) to ping the target system that exceeds the maximum bytes allowed by TCP/IP (65,536). Example:- c:/>ping -l 65540 hostname Fortunately, nearly all operating systems these days are not vulnerable to the ping of death attack.
**2. Teardrop Attack:** Whenever data is sent over the internet, it is broken into fragments at the source system and reassembled at the destination system. For example you need to send 3,000 bytes of data from one system to another. Rather than sending the entire chunk in a single packet, the data is broken down into smaller packets as given below:
•	packet 1 will carry bytes 1-1000.
•	packet 2 will carry bytes 1001-2000.
•	packet 3 will carry bytes 2001-3000.
In teardrop attack, however, the data packets sent to the target computer contains bytes that overlap with each other.
(bytes 1-1500) (bytes 1001-2000) (bytes 1500-2500)
When the target system receives such a series of packets, it cannot reassemble the data and therefore will crash, hang, or reboot. Old Linux systems, Windows NT/95 are vulnerable.	
**3. SYN Flood Attack:** In SYN flooding attack, several SYN packets are sent to the target host, all with an invalid source IP address. When the target system receives these SYN packets, it tries to respond to each one with a SYN/ACK packet but as all the source IP addresses are invalid the target system goes into wait state for ACK message to receive from source. Eventually, due to large number of connection requests, the target systems' memory is consumed. In a SYN flood, multiple SYN request are send from the spoofed IP address and the attacker not respond the host's SYN-ACK response, which make host system to bind the resources until they get the acknowledgement of each of the requests. These type of binding resources ultimately causing denial of service.
Example:
<table>
  <tr>
    <div width="70%"> 
    Normal way:
1.	Syn-packet is sent to the host by the client who intends to establish a connection
2.	Then in the second step host replies with syn/ack packet to the client
3.	Client replies with ack packet to the host and then the threeway handshake is complete
    </div>
    <div width="30%">
    ![image](https://user-images.githubusercontent.com/65315090/134779876-bac9f826-ad23-4d0e-9d41-00840ac9d621.png)
    </div>
  </tr>
</table>

Now in attack:
Several syn packets is sent to host via spoofed ip address (bad or dead ip addresses) now then what happens the host replies with syn/ack packet and host waits for the ack packet.

But however the ip address don’t exist it keeps waiting, thus it queues up and eats the system resources and thus causes the server to crash or reboot.
![image](https://user-images.githubusercontent.com/65315090/134779886-05d29977-422b-4a23-88ba-fcbea7bd7c31.png)

**4. Land Attack:** A land attack is similar to SYN attack, the only difference being that instead of including an invalid IP address, the SYN packet includes the IP address of the target system itself. As a result an infinite loop is created within the target system, which ultimately hangs and crashes. But almost all systems are configured against this type of attacks.

**5. Smurf Attack:** There are 3 players in the smurf attack–the attacker, the intermediary (which can also be a victim) and the victim. In most scenarios the attacker spoofs the IP source address as the IP of the intended victim to the intermediary network broadcast address. Every host on the intermediary network replies, flooding the victim and the intermediary network with network traffic.
![image](https://user-images.githubusercontent.com/65315090/134779834-25b690ef-9649-476d-9364-8dfb8fb27f6e.png)

**6. UDP Flood Attack:** UDP is a session less networking protocol which leverages the UDP. Several UDP echo packets are sent by the attacker to the victim machine ports randomly which cause repeatedly check for the application listening at that port and after getting no application it reply with an ICMP Destination Unreachable packet. Due to whole process creates an infinite non-stopping loop between the two systems, making them useless for any data exchange or service inaccessibility.
![image](https://user-images.githubusercontent.com/65315090/134779858-741c9d94-6af7-41bb-b2f9-f09c88528769.png)


**7. ICMP (Ping) Flood:** Is a Denial of Service Attack. In this attack, the attacker sends a large number of ICMP Echo Request or ping packets to the targeted victim’s IP address, mostly by using the flood option of ping. As a result, the victim’s machine starts responding to each ICMP packet by sending a ICMP Echo Reply packet.

Now, the victim’s machine takes twice the bandwidth of the attacker – once for receiving the packets and once for sending replies. So, if the attacker already has a much higher bandwidth than the victim, the victim’s machine will get flooded with network traffic. The victim’s machine will consume large number of CPU cycles and notice significant slowdown. This attack is called Ping of Flood.


### DDoS Tools
- LOIC - Open source network stress tool for Windows.
- JS LOIC - JavaScript in-browser version of LOIC.
- SlowLoris - DoS tool that uses low bandwidth on the attacking side.
- HOIC - Updated version of Low Orbit Ion Cannon, has 'boosters' to get around common counter measures.
- T50 - Faster network stress tool.
- UFONet - Abuses OSI layer 7 HTTP to create/manage 'zombies' and to conduct different attacks using; GET/POST, multithreading, proxies, origin spoofing methods, cache evasion techniques, etc.
- Memcrashed - DDoS attack tool for sending forged UDP packets to vulnerable Memcached servers obtained using Shodan API.

### Usefull Refrence Link

- DDos Attack Satics’ (collaboration between Google & Arbor): http://www.digitalattackmap.com
- NORSE (Live attack display): http://map.norsecorp.com

- https://www.imperva.com/learn/application-security/ddos-attacks/


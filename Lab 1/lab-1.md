# Wazuh Lab-1 Notes

The cybersecurity landscape is constantly evolving, so there is need to use **SIEM (Security Information/Incident and Event Management)** to deal with the wide attack surfaces.  
**Wazuh** is open source **SIEM** and **XDR (Extended Detection and Response)** that provides protection for endpoints and monitoring them all the time.  

Wazuh has more benefits — the important one is that it is open source which enables anyone to customize it to adopt his business and it is also flexible and provides quality and security.  
It has big communities of users and developers to connect with them; it also has very good documentation to solve most problems faces any user.  
It is totally free tool. Wazuh enhances threat detection, incident response, and threat hunting and compliance management with any organization.  

Wazuh combines powerful features such as **intrusion detection, log analysis, file integrity monitoring, vulnerability detection**, and **security configuration assessment** into a unified solution.

In this first lab I will discover how to set up **IDS (Intrusion Detection System)** to discover suspicious traffic and also I will discover core components of Wazuh platform.

Due to technology development, the cyber attacks have been increasing also, which make us need to practice solutions to prevent most of those attacks.  
Here the **IDS** comes which is proactive tool that tries to prevent attacks before it happens or during it happens.  
Wazuh is IDS which works on various levels including host level which focuses on endpoints threat detection and collecting its logs and indexing it for analysis to get to discover solutions for security.  
It also has various built-in tools like malware detection and file integrity and others.  

We will use **Wazuh** with **Suricata**, which is **IDS/IPS (Intrusion Detection System/Intrusion Prevention System)** that works on network level, to help us detect any network anomalies.  

---

## IDS Overview

IDS monitors traffic and logs to identify patterns and signatures.  
After detection of identifying suspicious pattern it generates alerts to notify admins.  

There are two types of IDS which vary from each other on scope and types of activities to detect, are:

- **NIDS (Network IDS) (Suricata)** → works at network level, functions on central places on network infrastructure, monitors in/out data from different devices that might indicate intrusion, detects network threats like DoS and others.  
- **HIDS (Host IDS) (Wazuh)** → works at host level, installed on the host to monitor log files, system calls and host specific files, detects unauthorized access and privilege escalation and others.

---

## Suricata Overview

**Suricata** is NIDS/IPS which is also open source tool.  
It monitors network traffic to prevent attacks and detect anomalies and prevent them using rule-based language, but it has problem in IPS which can prevent legitimate incidents also.  
To provide this most people focus much more on detection.  

Suricata has wide range use cases for DDoS and protocol analysis and network monitoring and logging and alerting and analysis known attack signatures to detect them and others.  
In this lab I will use **Suricata ruleset by ET (Emerging Threats) community**, it can help us to detect malware and viruses and web-based attacks.  

It also can be integrated with other tools in our case with **Wazuh**, where Suricata logs and sends alerts to SIEM platforms like Wazuh to link those data from Suricata with other events.

---

## Installing Suricata on Rocky Linux Minimal (RPM Method)

I will use **Rocky Linux minimal** to download Suricata on it, so I will use RPM installation:

1. Go to the official website → [https://suricata.io/download/](https://suricata.io/download/)  
2. Install using RPM packages → [https://docs.suricata.io/en/suricata-8.0.1/install/rpm.html](https://docs.suricata.io/en/suricata-8.0.1/install/rpm.html)  
3. Use **Enterprise Linux and Rebuilds**:

   ```bash
   3.1- sudo dnf install epel-release dnf-plugins-core -y   # Adds the Extra Packages for Enterprise Linux (EPEL) repository
   3.2- sudo dnf copr enable @oisf/suricata-8.0 -y          # Official repository maintained by the OISF for Suricata 8.0 builds
   3.3- sudo dnf install suricata -y                        # Installs the Suricata package and dependencies
   3.4- sudo systemctl start suricata                       # Start Suricata
   3.5- sudo systemctl enable suricata                      # Enable Suricata on boot
   3.6- sudo systemctl stop suricata                        # Stop Suricata

## Suricata Deployment Options

There are several ways to deploy **Suricata** as IDS:

1. **Inline Deployment at Network Perimeter**  
   Suricata sits between external internet and internal network  
   `(internet <----> suricata <----> local network)`  
   It can be added as physical or VM (in our case), to analyze in/out packets.

2. **Internal Network Monitoring**  
   We use Suricata sensors that may be physical or virtual devices to monitor internal network (different departments in the same organization).  
   Sensors capture data, analyze them, and then alert the central server.

3. **Cloud Environment Monitoring**  
   We can use cloud services like **AWS** to deploy Suricata on its environments to monitor resources and virtual networks.

4. **Network Tap Deployment**  
   Suricata is used in conjunction with network taps or port mirroring to capture a copy of network traffic, which is then sent to Suricata for analysis.

---

## Wazuh Platform Components

**Wazuh** provides a centralized platform for monitoring and managing security events.  
We install **Wazuh Agent** on the endpoints that need to be monitored.

The Wazuh solution is made up of **three parts**:

### 1. Wazuh Server
- This is the central component used to manage agents and analyze the data collected from them.  
- Integrates logs from different resources, then collects logs and normalizes them using the Wazuh decoder to make them in uniform state.  
- It also provides an API for interaction.

### 2. Wazuh Indexer
- It stores and indexes alerts generated by Wazuh server (repository).  
- It has different index patterns to store data:
  - `wazuh-alerts-*` → Index pattern for alerts generated by Wazuh server  
  - `wazuharchives-*` → Index pattern for all events sent to Wazuh server  
  - `wazuh-monitoring-*` → Pattern for monitoring status of Wazuh agents  
  - `wazuh-statistics-*` → Used for statistical information about Wazuh server

### 3. Wazuh Dashboard
- Web interface for visualization and analysis.  
- Allows us to create rules, monitor regulatory compliances, and much more.

---

## Wazuh Agents and Deployment

Wazuh agents are installed on different types of endpoints.  
Wazuh utilizes the **OSSEC HIDS** module, which is open source tool used in various things, to collect events from all endpoints.

Wazuh has the ability to fully monitor security — it depends on what is our requirements.  
For **production environment**, we should install Wazuh in **cluster mode** (setting up more than one Wazuh server node) to improve speed and scalability.

There are other deployment options like **dedicated server**, **VM image**, **Docker container**, and **Kubernetes**, each deployment option has its advantages.

 **[Wazuh Virtual Machine Deployment Documentation](https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html)**

---

**Note:**  
Docker and Kubernetes → for **production-level deployment**.

---

# Wazuh Modules and Administration

Wazuh has something is called modules which will help us to find security threats and make sure that we are follow rules, Wazuh has four default modules or sections:

## 1. Security Information Management
Security event and integrity monitoring module, by using security predefined rules for security events and display alerts, and make sure and detect any tampering for system files for integrity.

## 2. Threat Detection and Response
Has two modules vulnerabilities (tracks known vulnerabilities) and MITRE ATT&CK (Adversarial tactics, techniques and common knowledge) (maps detected threats to framework) and we can add other modules like VirusTotal and others.

## 3. Auditing and Policy Monitoring
It monitors policies and configurations, this section about policies, has three modules:
- Policy monitoring (ensure that policies are established)
- System auditing (tracks and audits activities on the endpoints)
- Security configuration assessment (checks system configurations against best practices using CIS framework).

## 4. Regulatory Compliance
For make sure that rules meet those Regulatory Compliance containing most popular regularities like (GDPR, ...more). Wazuh rules are created with some of this regularities.

---

## Wazuh Administration Section
Wazuh administration section has pivotal role in Wazuh for detecting in real world, it has the following:

### 1. Decoders
It pulling out important info from different log entries formats and normalize them into one standard format. It contains of different tags:
1.1 - decoder name.  
1.2 - parent --> this will be processed first then child decoders.  
1.3 - prematch --> condition that must match to apply decoder.  
1.4 - regex --> represents regular expressions to extract data.  
1.5 - order --> indicates list of fields in which the extracted info or values will be stored.  

For more about decoders syntax we will use this page:  
 [Decoders Syntax Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html)

---

### 2. Rules
Rules help the system to detect attacks in early stages, it is one of the most important thing in Wazuh or SIEM solution in general, because it defines how good is your detection system.  
There are predefined rules but we can create our custom rules. Let's divide its content; it has different tags:

2.1 - rule id --> unique id for rule.  
2.2 - level --> range from 0 to 15 each number indicates different severity.  
2.3 - if_sid --> id of another rule which is treated as parent rule which will be checked first.  
2.4 - field name --> name of field extracted from decoder, the value is matched by regular expression.  
2.5 - mitre --> id of mapped mitre or associates the rule with a mitre technique.  
2.6 - options --> options to do when this rule is triggered.  
2.7 - group --> organize Wazuh rules by categorizing them into groups.  

There are more and more options and we will find them here:  
 [Rules Syntax Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)

---

### 3. CDB Lists
Constant database for categorization IPs and Domains based on their characteristics, may include suspicious domains and IPs or trusted IPs.  
For learning more about those lists we will use:  
 [CDB Lists Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html)

---

### 4. Groups
Agents or endpoints grouping operation based on different things, using this may make pushing rules to one similar group rather than one by one.  
To know more about this we will use:  
 [Grouping Agents Documentation](https://documentation.wazuh.com/current/user-manual/agents/grouping-agents.html)

---

### 5. Configuration
Helps to fine-tune Wazuh configurations like cluster configuration, alert management and log data analysis and more, by editing:
Configuration is managed by editing the file in Wazuh manager or Wazuh agent:
```bash
/var/ossec/etc/ossec.conf
```
# Wazuh Server Setup Guide

as we have disscused that the wazuh serever is central component including:

1. wazuh manager --> collects data from wazuh agents then analyze them then trigger alerts

2. Filebeat --> forward alerts to wazuh indexer

we will get into production phase which we will use multi node cluster method:

1. production --> https://documentation.wazuh.com/current/installation-guide/index.html

2. VM OVA --> https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html

each documentation has full steps for installation guide

we will depend on this guide of production **https://documentation.wazuh.com/current/installation-guide/index.html**

## steps to monitor by wazuh:

1. we will go to this link (https://documentation.wazuh.com/current/quickstart.html)

2. we will run this command into our VM(ubuntu) which is Wazuh installation assistant(installs anything wazuh needs--> config files - wazuh indexer - wazuh server - wazuh dashboard)

   ```bash
   curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
   ```

3. after finishing installation it will give me username and password to get into dashboard using them

4. this username and password are stored in filebeat.yml file

5. we can find all password for all wazuh indexers in wazuh-passwords.txt inside wazuh-install-files.tar to print them we use this command

   ```bash
   sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
   ```

6. to go to dashboard we needs our machine ip address using this command

   ```bash
   ip addr
   ```

7. then we will go to https://machine-ip-addr

8. after geting into wazuh dashboard we wiil see different sections

   - ENDPOINT SECURITY --> assessment of configurations, malware and file integrity

   - THREAT INTELLIGENCE --> responsible for threat hunting,vulnerability detection and mapping to mitre att&ck framework

   - SECURITY OPTIONS --> assess system, and regulatories compliance(PCI-DSS,GDPR,HIPAA, and others)

   - CLOUD SECURITY --> cloud services like docker aws and others security monitoring

9. now we will deploy new agent, my agent is kali Linux purple VM

   - we will choose the type of the agent os (Linux,windws,macos) to download suitable packages

   - enter wazuh server ip address(ubuntu)

   - enter name of wazuh agent(kali purple)

   - enter group (if there OSs with same structure we can put them into groups)

   - it will give us command we will copy it and paste it in wazuh agent(purple) this will install packages and services needed into agent

   - if there is any firewall rules it should be deleted

   - if we want to install windows agent it will follow the same steps but choosing type of os windows

10. we wiil go to Agents and we will find kali purple agent, it takes and id and some meta data about machine

## Suricata Installation

Suricata is an NSM tool, which has the potential to work as an IPS/IDS. Its goal is to stop intrusion, malware, and other types of malicious attempts from taking advantage of a network, now the steps of installing Suricata:

1. use those three commands:

   - `sudo add-apt-repository ppa:oisf/suricata-stable`

   - `sudo apt-get update`

   - `sudo apt-get install suricata –y`

2. install et rules which is set of rules and we need to store all rules in /etc/suricata/rules directory

   ```bash
   cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz && sudo tar -xvzf emerging.rules.tar.gz && sudo mv rules/*.rules /etc/suricata/rules/ && sudo chmod 640 /etc/suricata/rules/*.rules
   ```
3. modify suricata configurations to change default settings in file /etc/suricata/suricata.yaml
   - `3.1- we will find some codes are already written, lets break the needed ones until now`
      - `3.1.1- HOME_NET  --> needs the agent IP address`
      - `3.1.2- EXTERNAL_NET --> we will set it as any to monitor all external IP addresses we can specify the external IPs we need to monitor`
      - `3.1.3- default-rule-path --> the set of rules we have installed and is /etc/suricata/rules`
      - `3.1.4- af-packet  --> packet capture method on NIC, NIC by command ip addr`
4. before restarting suricata it will ask for reloading since we change the configuration file by using

```bash
sudo systemctl daemon-reload
sudo systemctl restart suricata
```


5. to integrate suricata with wazuh we should specify suricata log file location under wazuh agent ossec config file at `/var/ossec/etc/ossec.conf` and Suricata stores all the logs at `/var/log/suricata/eve.json`, we will put suricata log file location into location tag in ossec.conf by putting this code :


```xml
<ossec_config>
	<localfile>
	  <log_format>json</log_format>
	  <location>/var/log/suricata/eve.json</location>
	</localfile>
</ossec_config>
```


6. Restart the Wazuh agent service using


```bash
sudo systemctl restart wazuh-agent
```

we have finally integrated wazuh with suricata, we have installed suricata on Ubuntu server with et rules and then our endpoint is ready to trigger alerts for any malicious traffic matched with any et rule.

there are two ways to install suricata on :
   - `1. install suricata on wazuh server --> it works as centeral point , but it has condition that it should sees the traffic between kali and purple`
   - `2. install suricata on wazuh agent --> it works on the endpoint itself to monitor this endpoint only(we will use on our case)`
      - `2.1- sudo apt update && sudo apt install -y suricata suricata-update --> Install Suricata + dependencies`
      - `2.2- sudo suricata-update update-sources , sudo suricata-update --> Update and enable Emerging Threats (ET) rules`
      - `2.3- sudo nano /etc/suricata/suricata.yaml --> edit configuration file`
            - `outputs:`
              - `- eve-log:`
                  - `enabled: yes`
                  - `filetype: regular`
                  - `filename: /var/log/suricata/eve.json`
                  - `community-id: yes`
            - `types:`
              - `- alert:`
                  - `payload: yes`
                  - `metadata: yes`


	 - `2.4- sudo systemctl restart suricata --> restart suricata`
	 - `2.5- sudo nano /etc/default/suricata  --> to edit default interface by putting in it (IFACE=eth0) which will listen on this interface`
	 - `2.6- sudo nano /var/ossec/etc/ossec.conf  -->  to edit wazuh agent config file`


```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
</ossec_config>
```

```
	2.7- sudo systemctl restart wazuh-agent  --> restart wazuh agent
	2.8- test usin nmap -->
```

```bash
nmap -sS -Pn <wazuh agent ip-addess>
```

```
	2.9- seeing result in wazuh dashboard
```

suricata is powerful when rule is powerful, there are many rule templates but we will learn how to create custom suricata rules.

suricata uses rules to detect different network events and when certain conditions are met it may alert or block this event it depends on how we write it, we will break down the rule syntax:
```rules 
action proto src_ip src_port -> dest_ip dest_port (msg:"Alert message"; content:"string"; sid:12345;)
```
   - `1- action --> action will be taken when the rule is true may be alert or drop or any other action`
   - `2- proto  --> shows what kind of traffic is being matched(tcp,udp,icmp and others), type of traffic`
   - `3- src_ip --> specify range of IPs where traffic comes from`
   - `4- src_port --> specify range of ports where traffic comes form`
   - `5- dest_ip --> specify range of IPs where traffic is going`
   - `6- dest_port --> specify range of ports where traffic is going`
   - `7- msg --> message that will be shown as alert when rule is true`
   - `8- content --> optional field that checks the packet payload for certain content`
   - `9- flow --> this defines the direction of the traffic that initiates the rule, prevents initial connection attempts from generating alerts.`
   - `10- sid --> rule id should be unique`

```rules
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH connction detected";flow:to_server,established;content:"SSH-2.0-OpenSSH"; sid:100001;)
```
  -   `1- alert: The rule specifies that an alert should be generated if the specified conditions are met.`
  -   `2- tcp: This refers to Transmission Communication Protocol (TCP) based traffic.`
  -   `3- $EXTERNAL_NET any -> $HOME_NET 22: The traffic flow is defined by directing traffic from any external network IP address ($EXTERNAL_NET) to any home or local network IP ($HOME_NET) on port 22 (SSH).`
  -   `4- (msg:"SSH connection detected";): This specifies a detailed message to be added to the alert. It indicates that the rule has identified an SSH connection in this instance.`
  -   `5- flow:to_server,established: This defines the direction of the traffic that initiates the rule. It is looking for established connections between the server (home network) and the server (external                network). This portion of the rule prevents initial connection attempts from generating alerts.`
  -   `6- content:"SSH-2.0-OpenSSH": This part looks at the payload of the packet for a particular string ("SSH-2.0-OpenSSH"). It searches the traffic payload for this specific string, which signifies the                  utilization of the OpenSSH protocol and the SSH protocol in general.`
  -   `7- sid:100001: It is a unique identifier for a particular rule.`


now we will start to test this by using network scanning probe attack, Network scanning is initial stage of most hacking exercises, and most powerful tool for this is Nmap scanner, Nmap is a free open source tool, helps us to scan any host to discover any opened ports, sw versions , OSs and so on.it is used for security testing and vulnerability detection, and threat agents use it also to discover opened ports or vulnerability packages. we will now initiate network scanning using Nmap against our wazuh agent(purple --> running suricata services). ET rule set already contains rules to detect Nmap scanning.
   - `1- to test the Nmap scenario we neet three parts`
      - `1.1- attacker --> kali Linux`
      - `1.2- wazuh agent --> purple (our defendable endpoint)`
      - `1.3- wazuh server --> ubuntu`
   we can install Nmap using this command

   ```bash
      sudo apt-get install nmap
   ```

   ,the flow is ( attacker  --port scanning--> endpoint(wazuh agent) <-- wazuh server)
   - `2- now we will simulate the attack , here is the steps:`
      - `2.1- opens kali`
      - `2.2- opens terminal`
      - `2.3- enter nmap command using (-sS) keyword for SYN scan and (-Pn) to skip host discovery, here how it works`
         - `2.3.1- The Nmap SYN scan is a half open scan that works by sending a TCP SYN packet to the target machine (the Wazuh agent)`
         - `2.3.2- If the port is open, the target device responds with a SYN-ACK (synchronize-acknowledgment) packet`
         - `2.3.3-  However, if the port is closed, the device may respond with an RST (reset) packet`
         - `2.3.4- (-sS) --> to check for open ports -->`

            ```bash
               nmap -sS -Pn 192.168.133.128
            ```

```
			Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-31 09:37 EET
			Nmap scan report for 192.168.133.128 (192.168.133.128)
			Host is up (0.00026s latency).
			Not shown: 999 closed tcp ports (reset)
			PORT   STATE SERVICE
			22/tcp open  ssh
			MAC Address: 00:0C:29:4F:22:28 (VMware)

		2.3.5- (-sV) --> to check for software version -->
```

         ```bash
            nmap -sV -Pn 192.168.133.128
         ```

```
			Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-31 09:39 EET
			Nmap scan report for 192.168.133.128 (192.168.133.128)
			Host is up (0.00022s latency).
			Not shown: 999 closed tcp ports (reset)
			PORT   STATE SERVICE VERSION
			22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
			MAC Address: 00:0C:29:4F:22:28 (VMware)
			Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
			Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```
  after run the two commands we will learn what all the ports are open and second, what version of the package is installed on the target machine
   - `3- in wazuh dashboard we will see alerts like (Suricata: Alert - ET SCAN Suspicious inbound to PostgreSQL port 5432) we can expand this alert to see more information like :`
	    - `3.1- data.alert.signature --> this filed talks about the ruricata rule applied and detected this abnormal traffic(ET for rule set)`
	    - `3.2- data.dest_ip  --> this field gives us victim machine`
	    - `3.3- data.src_ip --> this field gives us attacker machine`
	    - `3.4- data.alert.action --> this field indicates the actions taken by wazuh in response to the detected event`
	    - `3.5- alerts.severity  --> this field shows severity level to the event by wazuh`
  there are more and more fields

this is how the wazuh can detect network scanning probes via suricata and wazuh visualizes it on the dashboard.


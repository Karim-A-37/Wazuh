# Wazuh and Suricata Lab Notes

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
# Wazuh Server Installation and Configuration Guide

As we have discussed that the Wazuh server is central component including:  
1- Wazuh manager --> collects data from Wazuh agents then analyze them then trigger alerts  
2- Filebeat --> forward alerts to Wazuh indexer  

We will get into production phase which we will use multi node cluster method:  
1- production --> https://documentation.wazuh.com/current/installation-guide/index.html  
2- VM OVA --> https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html  

Each documentation has full steps for installation guide we will depend on this guide of production  
**https://documentation.wazuh.com/current/installation-guide/index.html**  

## Steps to monitor by Wazuh:  

1- we will go to this link[](https://documentation.wazuh.com/current/quickstart.html)  

2- we will run this command into our VM (ubuntu) which is Wazuh installation assistant (installs anything Wazuh needs --> config files - Wazuh indexer - Wazuh server - Wazuh dashboard)  
```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

3- after finishing installation it will give me username and password to get into dashboard using them  

4- this username and password are stored in filebeat.yml file  

5- we can find all password for all Wazuh indexers in wazuh-passwords.txt inside wazuh-install-files.tar to print them we use this command  
```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

6- to go to dashboard we needs our machine ip address using this command  
```bash
ip addr
```

7- then we will go to https://machine-ip-addr  

8- after getting into Wazuh dashboard we will see different sections  
8.1- ENDPOINT SECURITY --> assessment of configurations, malware and file integrity  
8.2- THREAT INTELLIGENCE --> responsible for threat hunting, vulnerability detection and mapping to mitre att&ck framework  
8.3- SECURITY OPTIONS --> assess system, and regulatories compliance (PCI-DSS, GDPR, HIPAA, and others)  
8.4- CLOUD SECURITY --> cloud services like docker aws and others security monitoring  

9- now we will deploy new agent, my agent is kali Linux purple VM  
9.1- we will choose the type of the agent os (Linux, windows, macos) to download suitable packages  
9.2- enter Wazuh server ip address (ubuntu)  
9.3- enter name of Wazuh agent (kali purple)  
9.4- enter group (if there OSs with same structure we can put them into groups)  
9.5- it will give us command we will copy it and paste it in Wazuh agent (purple) this will install packages and services needed into agent  
9.6- if there is any firewall rules it should be deleted  
9.7- if we want to install windows agent it will follow the same steps but choosing type of os windows  

10- we will go to Agents and we will find kali purple agent, it takes an id and some meta data about machine  

## Suricata Installation

Suricata is an NSM tool, which has the potential to work as an IPS/IDS. Its goal is to stop intrusion, malware, and other types of malicious attempts from taking advantage of a network. Now the steps of installing Suricata:  

1- use those three commands:  
1.1-
```bash
sudo add-apt-repository ppa:oisf/suricata-stable
```
1.2-
```bash
sudo apt-get update
```
1.3-
```bash
sudo apt-get install suricata -y
```

2- install ET rules which is set of rules and we need to store all rules in /etc/suricata/rules directory  
2.1-
```bash
cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz && sudo tar -xvzf emerging.rules.tar.gz && sudo mv rules/*.rules /etc/suricata/rules/ && sudo chmod 640 /etc/suricata/rules/*.rules
```

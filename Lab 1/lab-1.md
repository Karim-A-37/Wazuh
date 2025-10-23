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

In our lab we will use **OVA (Open Virtual Appliance)** to use it in **VirtualBox** to test our labs.  
There are other deployment options like **dedicated server**, **VM image**, **Docker container**, and **Kubernetes**, each deployment option has its advantages.

 **[Wazuh Virtual Machine Deployment Documentation](https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html)**

---

**Note:**  
Docker and Kubernetes → for **production-level deployment**.


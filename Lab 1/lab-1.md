The cybersecurity landscape is constantly evolving, so there is need to use SIEM(Securiy Information/Incident and Event Management) to deal with the wide attack surfaces.
Wazuh is open source siem and xdr(Extended Detection and Respoonse) that provides protection for endpoints and montoring them all the time. wazuh has more benefits the important one is that it is 
open source which enables anyone to customize it to adopt his busniss and it is also flexible and provides quality and security, it has big communties of users 
and developers to connect with them it also has very good documentation to solve most problems faces any user. it is totaly free tool.wazuh enhance threat detection, incident response
and threat hunting and compliance management with any orgnization. Wazuh combines powerful features such as intrusion detection, log analysis, file integrity monitoring, 
vulnerability detection, and security configuration assessment into a unified solution.
in this first lab i will discover how to set up IDS(Intrusion Detection System) to discover suspsious traffic and also i will discover core components of wazuh platform.
Due to technology developement the cyber attacks have been increases also which make us to neet to practive solution to prevent most of those attacks, here the IDS comes which is proactive 
tool that tries to prevent attacks before it happens or during it happens, wazuh is IDS which works on various levels including host level which focuses on endpoints threat detection and collecting its logs and
indexing it for analysis to get to discover solutions for security, it also has various built in tools like malware detection and file integrity and others.
we will use wazuh with suricata, which is IDS/IPS(Intrustion Detection System/Intrusion Previntion System) that works on network level, to help us detect any network anomalias.
IDS monitors trrafic and logs to identify  patterns and signatures, after detection of identyfiying suspsious pattern it generates alerts to notify admins, there are two types of IDS which variours from each other
on scope and types of activites to detect, are:
  NIDS(Network IDS)(suricata) ---> works at network level, function on central places on network infrastructure montiors in/out data from different devices that migt indicate intrusion, detects network threats like DoS and others.
  HIDS(Host IDS)(wazuh) ---> works at host level, installed on the host to monitors log files, system calls and host specific files, detects unauthoriazed access and privilage esclation and others.
suricat is NIDS/IPS which is also open source tool, it monitors network traffic to prevent attacks and detect anomalias and prevent them using rule based language, but it has problem in IPS which can prevent 
legitimate incidents also, to provide this most people focus much more on detection, suricat has wide range use cases for DDos and protocol analysis and network montoring and logging and alerting and
analysis known attack signatures to detect them and others in this lab i will use suricata ruleset by ET(Emerging Threats) comuunity  it can help us to detect malware and virsues and web based attacks,
it also can be integrated wih other tools in our case wiht wazuh which suricata logs and sends alerts to siem platforms like wazuh to link those data from suricata with other events.
i will use rocky linux minimal to download suricate on it so i will use rpm installation:
  1- we will go to official website which is https://suricata.io/download/
  2- i will install using RPM packages which is https://docs.suricata.io/en/suricata-8.0.1/install/rpm.html
  3- i will use Enterprise Linux and Rebuilds which is 
    3.1- sudo dnf install epel-release dnf-plugins-core -y  --> Adds the Extra Packages for Enterprise Linux (EPEL) repository
    3.2- sudo dnf copr enable @oisf/suricata-8.0 -y  --> official repository maintained by the OISF for Suricata 8.0 builds
    3.3- sudo dnf install suricata -y  --> Installs the Suricata package and dependencies
    3.4- sudo systemctl start suricata --> to start suricata
    3.5- sudo systemctl enable suricata --> to have suricata start on booting
    3.6- sudo systemctl stop suricata --> to stop suricata
there are several ways to deploy suricata as IDS here they are :
  1- Inline Deployment at network parameter --> suricat sets between external internet and internal network ( internet  <---> suricata <---> local network ) 
  it can be added as pyhsical or vm(in our case), analyze in/out packets.
  2- Internal Network Montoring --> we use suricata sensors that my be physica or virtual devices to monitor internal nework, different department in the same
  orgnization, sensors captures data and anlyze them and then alerts them to central server.
  3- Cloud Environment monitoring --> we can use cloud services like (AWS) to deploy suricata on its environments to monitor resources and virtual networks.
  4- Network Tap deployment --> suricat is used in conjunction with network taps or port mirroring to capture copy of network traffic then it is send to 
  suricata to analyze it.
Wazuh provides a centralized platform for monitoring and managing security events, we install wazuh agent on the endpoints that need to be monitored, wazuh solution is made up of three parts : 
  1- wazuh server     ---> this is central component that is used to manage agents and analyze the data collected from them,integrate logs from different resources   then collects logs then normalize logs using wazuh decoder to make it in uniform state, it also provides api for interaction.
  2- wazuh indexer    ---> it stored and indexing alerts generated by wazuh server (repository), it has differnt intdex patterns to store data :
     2.1- wazuh-alerts-*: This is the index pattern for alerts generated by the Wazuh server
     2.2- wazuharchives-*: This is the index pattern for all events sent to the Wazuh server
     2.3- wazuh-monitoring-*: This pattern is for monitoring the status of Wazuh agents
     2.4- wazuh-statistics-*: This is used for statistical information about the Wazuh server

  3- wazuh dashboard  ---> web interface for visualization and analysis, it allows us to create rule monitor regulatory compliances and much more.
wazuh agents are installed on differnt types of endpoints, wazuh utilizes the OSSEC HIDS module, which is open source tool uses in various things, to collect 
events from all endpoints. wazuh has the ability to fully monitor security, it depends on what is our requirements, for production environment we should install
wazuh in cluster mode (setting up more than one wazuh server nodes) aims to improve speed and scalablity, in our lab we will use OVA(Open Virtual Appliance) to use
it in virtual box to test our labs, there are other deployment options like dedicatied server,VM image (i will use)
(https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html) , Docker container and Kubernetes each deployment option has
its advantages(Docker - Kubernetes -->>  for production level deployment)

  


 

    

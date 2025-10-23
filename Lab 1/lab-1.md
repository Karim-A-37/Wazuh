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

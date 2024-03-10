# SOC-Automation-Lab

### Lab objective:
In this lab, I integrated Wazuh and TheHive using the Shuffle feature. This integration allows for the automatic creation of alerts in TheHive whenever Wazuh detects a security event. The goal of this project is to enhance my proficiency in Security Orchestration, Automation, and Response (SOAR) by configuring Shuffle to automate the transmission of Wazuh alerts to TheHive.

### Wazuh Setup:
- Downloaded Wazuh server on an Ubuntu machine on the cloud (DigitalOcean)
- Configured Wazuh to analyze Sysmon logs.
- Logged into Wazuh and created a rule to detect Mimikatz usage.

(Wazuh server running in cloud)
<img src="https://i.imgur.com/BsiEYvp.png">

(Custom rule to alert for Mimikatz)
<img src="https://i.imgur.com/cA6d8No.png">

(The Rule in action)
<img src="https://i.imgur.com/eFmjh00.png">

### TheHive Setup:
- Downloaded the hive on an Ubuntu machine on the cloud (along with elastic-search and cassandra).
- Logged in and created an analyst to receive alerts.

(TheHive Server)
<img src="https://i.imgur.com/aTeskvJ.png">

### Shuffler Setup:
- When the custom rule is detected it will get hashed and run through VirusTotal and then an alert will be sent to TheHIve

(Workflow)
<img src="https://i.imgur.com/0iqz6yr.png">

(VirusTotal searches up the hash)
<img src="https://i.imgur.com/ENhycIs.png">

(Alert shows up in TheHive)
<img src="https://i.imgur.com/8u0BldS.png">

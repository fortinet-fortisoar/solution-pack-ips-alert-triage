# solution-pack-ips-alert-triage
 alerts to showcase vulnerability correlation capabilities

# SIEM IPS Alert Triage through CVE correlation

In this scenario a SIEM system (FortiSIEM) triggers an Incident every time the IPS (FortiGate) logs a Permitted Inbound IPS packet. FortiSIEM then opens an alert in FortiSOAR which is maps all the incident artifacts and proceeds to validate if the target of the attack is vulnerable to the CVE reported by the FortiGate.

The vulnerability information is sourced from Nessus and mapped in the Vulnerability Management module, it would work the same way with any supported vulnerability scanner.

The aim of the scenario is to showcase the speed at which such Incidents can be closed, by correlating information from multiple sources to determine that even though a packet passed through the FortiGate, the alert may be a false positive because the target asset is not vulnerable to that specific CVE ID.

### 1) Prerequisites

- SMTP Connector configured 
- SLA Connector configured
- MITRE ATT&CK Connector configured with scheduled ingestion
- FortiSOAR SOC Simulator

### 2) Simulation Steps:
**- Alert1:**
- IPS detects a remote exploit attack against Asset 10.222.248.67 exploiting vulnerability CVE-2020-1350
- FortiSOAR checks the list of Asset 10.222.248.67 vulnerabilities where CVE-2020-1350 is included.
- FortiSOAR then escalates this Alert to an Incident as **True Positive** creating a Task to Assign the resulting Incident to an Analyst so he can Assign, Investigate and Remediate the Incident by blocking the IP on a FortiGate, due to the high risk of compromise.

#### Things to show in the Alert
- Open the alert, show the Workspace / Comments section. This is populated by playbooks and serves to show the process of automatically analysing each inbound alert.
- On the bottom panel, click on Indicators, Correlations and Tasks. There is a lot of contextual information an analyst can derive by clicking on any malicious indicator and also correlations. For this specific use case, click on the affected Asset in Correlations/Assets to showcase all the information we know about that asset. This can also position FortiSOAR as a CMDB.
- Click on Correlations/Technique and on the Technique ID, to show MITRE information.
- Click on Correlations/Incident to move on to the Incident.

#### Things to show in the Incident
- Show the Incident Graph where all the related artifacts are tied together. We can clearly paint a picture of the Incident by looking at the link graph.
- Remember the task you now have, remediate the incident by clicking on Indicators, Selecting the Malicious IP and Execute one of the Block IP playbooks. An alternative to this, to showcase the flexibility one can give to analysts, is to click on the Actions / chose a Connector (such as a FortiGate) and then pass on the Malicious IP as an attribute. This will show how one can leverage all the security technologies in their arsenal with the information at hand in FortiSOAR, without having to resort to multiple applications and consoles to do incident management.


**- Alert2:**
- IPS detects a remote exploit attack against Asset 10.222.248.67  exploiting vulnerability CVE-2008-4250
- FortiSOAR checks the list of Asset 10.222.248.67 vulnerabilities and determines CVE-2008-4250 is not one of them
- FortiSOAR then Closes the alert as **False Positive** because the risk of successful compromise is null
- FortiSOAR asks the analyst to confirm the automated closure of the alert on the FortiSIEM side (this can be applied to any SIEM / Ticketing Platform). It could also be automated so as to not even require human input.
- The point is to showcase how much analyst time one can save by automating these 'low hanging fruit' kind of alerts that require simple validations which consume a lot of human time.
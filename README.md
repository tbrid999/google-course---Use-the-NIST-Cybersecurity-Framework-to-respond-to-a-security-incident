# google-course---Use-the-NIST-Cybersecurity-Framework-to-respond-to-a-security-incident
Identify
Summary of the Event:
The company experienced a Distributed Denial of Service (DDoS) attack targeting its internal network, causing all network services to stop responding for two hours. The attack was conducted using a flood of ICMP packets that overwhelmed the company’s network. A lack of proper firewall configuration allowed the attack to pass through without restriction, resulting in widespread network downtime.

Cause:
The primary cause was a misconfigured firewall that failed to filter incoming ICMP packets. The attacker exploited this vulnerability to overwhelm the network with a high volume of pings.

Impact:

Duration: The attack disrupted the network for two hours.
Systems Affected: All internal network systems and services were rendered inaccessible.
Response: The incident management team mitigated the attack by blocking ICMP packets and temporarily taking non-critical network services offline. Critical services were restored.
Attack Type:
This was a DDoS attack, specifically an ICMP flood, leveraging multiple sources to send a high volume of ping requests to the target network.

Protect
Immediate Action Plan:
To prevent similar incidents in the future, the following steps must be implemented:

Strengthen Firewall Rules:

Configure the firewall to limit the rate of incoming ICMP packets to prevent flooding.
Block unauthorized ICMP packets by enabling source IP verification to filter spoofed addresses.
Implement Network Access Controls:

Restrict access to the internal network from untrusted IPs and external sources.
Use geo-restrictions to block traffic from high-risk regions.
Employee Training:

Conduct regular training on identifying security threats and the importance of reporting suspicious activity.
Update Incident Response Policies:

Define clear protocols for responding to DDoS attacks, including pre-approved steps for mitigation and escalation.
Detect
Monitoring and Detection Strategies:

Network Monitoring Tools:

Deploy network monitoring software to track incoming and outgoing traffic for abnormal patterns.
Use anomaly-based intrusion detection systems (IDS) to identify unusual traffic behavior, such as large ICMP floods.
Traffic Analysis:

Implement packet analysis tools (e.g., Wireshark) to identify suspicious traffic in real-time.
Regularly review logs for spikes in ICMP traffic and other irregularities.
User Behavior Monitoring:

Track account activity to detect unauthorized access or unusual patterns.
Monitor failed login attempts and unusual IP logins to identify potential threats.
Automated Alerts:

Configure automated alerts for abnormal traffic or unauthorized access attempts.
Respond
Response Plan for Future Incidents:

Containment:

Immediately block suspicious traffic using firewall rules or rate-limiting policies.
Take affected systems offline to prevent further damage while mitigating the attack.
Neutralization:

Use intrusion prevention systems (IPS) to filter and block malicious traffic automatically.
Isolate compromised devices and inspect logs to identify the source of the attack.
Incident Analysis:

Analyze logs and data collected during the attack to determine its origin, scope, and techniques used.
Share findings with the team to improve future response strategies.
Improvement Procedures:

Refine firewall configurations, IDS/IPS policies, and monitoring rules based on lessons learned from the incident.
Conduct tabletop exercises to simulate similar attacks and improve team preparedness.
Recover
Steps to Recovery:

Restore Network Services:

Restart critical network services in a phased manner, ensuring each service is fully operational before moving to the next.
Reconfigure Devices:

Reconfigure firewalls, routers, and switches with updated rules to mitigate vulnerabilities discovered during the attack.
Validate System Integrity:

Perform a full scan of all systems to ensure no malware or backdoors remain from the attack.
Verify that data integrity has not been compromised.
Incident Documentation:

Document the incident, including the timeline, attack methods, mitigation steps, and lessons learned.
Share the report with relevant stakeholders and regulatory authorities if required.
Post-Incident Review:

Conduct a review with the cybersecurity team to evaluate the effectiveness of the response and identify areas for improvement.
By addressing the vulnerabilities that allowed this DDoS attack, the organization can strengthen its network security posture. Implementing these steps across the NIST CSF categories will reduce the likelihood of future attacks and ensure faster, more effective mitigation and recovery.

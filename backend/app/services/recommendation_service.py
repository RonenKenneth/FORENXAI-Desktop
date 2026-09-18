from typing import Dict, List


RECOMMENDATIONS: Dict[str, Dict] = {
    "API": {
        "summary": "Review API-related activity for unusual request patterns, unauthorized access attempts, or abuse.",
        "actions": [
            "Review the source and destination involved in the detected API traffic.",
            "Check application and API gateway logs for matching timestamps.",
            "Verify whether the observed API requests were authorized.",
            "Inspect authentication failures, unusual request volume, and suspicious endpoints.",
            "Preserve relevant logs and network evidence for further investigation."
        ]
    },

    "Bruteforce": {
        "summary": "Repeated authentication attempts may indicate a brute-force attack.",
        "actions": [
            "Identify the source system generating repeated authentication attempts.",
            "Review authentication logs for repeated failures.",
            "Check whether any account was successfully accessed after repeated failures.",
            "Temporarily restrict or block the suspicious source if appropriate.",
            "Preserve authentication and network logs for correlation."
        ]
    },

    "BufferOverflow": {
        "summary": "The detected traffic may be associated with buffer overflow exploitation attempts.",
        "actions": [
            "Identify the targeted host and service.",
            "Review application and operating system logs for crashes or abnormal behavior.",
            "Check the affected service version for known vulnerabilities.",
            "Inspect related traffic around the detected flow.",
            "Preserve system memory, logs, and network evidence if compromise is suspected."
        ]
    },

    "C2Beaconing": {
        "summary": "Repeated communication patterns may indicate command-and-control beaconing.",
        "actions": [
            "Identify the internal system involved in the repeated communication.",
            "Review destination IP addresses and domains.",
            "Check for periodic or repeated outbound connections.",
            "Correlate the activity with endpoint and DNS logs.",
            "Consider isolating the affected host if compromise is confirmed."
        ]
    },

    "DDoS": {
        "summary": "The traffic pattern may represent distributed denial-of-service activity.",
        "actions": [
            "Identify the targeted host or service.",
            "Review traffic volume and source distribution.",
            "Check firewall and network device logs.",
            "Identify whether multiple source addresses participated in the activity.",
            "Preserve traffic evidence for timeline reconstruction."
        ]
    },

    "DNS": {
        "summary": "The detected traffic contains suspicious DNS-related behavior.",
        "actions": [
            "Review the queried domains and responding DNS servers.",
            "Check for unusually frequent or abnormal DNS requests.",
            "Correlate suspicious domains with endpoint activity.",
            "Inspect DNS logs for related systems.",
            "Preserve DNS and network logs for further analysis."
        ]
    },

    "DoS": {
        "summary": "The traffic pattern may indicate denial-of-service activity against a host or service.",
        "actions": [
            "Identify the targeted host and service.",
            "Review connection rate and packet volume.",
            "Check firewall and server logs for service disruption.",
            "Identify the source of the traffic.",
            "Preserve relevant PCAP and system logs for investigation."
        ]
    },

    "Evasion": {
        "summary": "The detected traffic may contain behavior intended to avoid normal security inspection.",
        "actions": [
            "Review unusual packet and flow characteristics.",
            "Compare the activity with firewall and IDS alerts.",
            "Inspect related sessions from the same source.",
            "Check for fragmentation, unusual ports, or protocol anomalies.",
            "Preserve the original traffic capture for deeper inspection."
        ]
    },

    "Exfiltration": {
        "summary": "The detected traffic may indicate unauthorized data transfer.",
        "actions": [
            "Identify the source and destination systems.",
            "Review the amount and direction of transferred data.",
            "Check whether the destination is approved or expected.",
            "Correlate the activity with endpoint and user logs.",
            "Preserve network and host evidence before containment actions."
        ]
    },

    "Exploitation": {
        "summary": "The detected traffic may represent an attempt to exploit a vulnerable service.",
        "actions": [
            "Identify the targeted host, port, and service.",
            "Review vulnerability information for the affected service.",
            "Check system and application logs for exploitation indicators.",
            "Inspect surrounding network flows for follow-up activity.",
            "Preserve relevant host and network evidence."
        ]
    },

    "MITM": {
        "summary": "The traffic may indicate man-in-the-middle behavior.",
        "actions": [
            "Review the affected source and destination systems.",
            "Inspect ARP, DNS, and certificate-related anomalies.",
            "Check for unexpected gateway or routing changes.",
            "Compare traffic with trusted network configuration.",
            "Preserve network evidence for further validation."
        ]
    },

    "PortScan": {
        "summary": "The detected flow may indicate systematic scanning of network ports.",
        "actions": [
            "Identify the system performing the scan.",
            "Review the destination hosts and ports contacted.",
            "Determine whether the scanning activity was authorized.",
            "Check firewall and IDS logs for additional scanning activity.",
            "Preserve the related network flows for timeline analysis."
        ]
    },

    "Slowloris": {
        "summary": "The detected behavior may indicate a Slowloris-style denial-of-service attempt.",
        "actions": [
            "Identify the targeted web server or service.",
            "Review long-lived or incomplete connections.",
            "Check server logs for connection exhaustion.",
            "Review connection limits and timeout settings.",
            "Preserve the relevant network and server logs."
        ]
    },

    "TLSSSL": {
        "summary": "The traffic contains TLS/SSL behavior that requires additional review.",
        "actions": [
            "Review the systems involved in the encrypted connection.",
            "Check certificate information and destination reputation.",
            "Inspect metadata such as connection frequency and destination ports.",
            "Correlate the activity with endpoint and application logs.",
            "Preserve the encrypted traffic metadata for investigation."
        ]
    },

    "WebBased": {
        "summary": "The detected traffic may indicate a web-based attack.",
        "actions": [
            "Identify the targeted web application and endpoint.",
            "Review web server and application logs.",
            "Inspect request patterns associated with the detected flow.",
            "Check whether the activity resulted in unauthorized access or application errors.",
            "Preserve network and application evidence."
        ]
    },

    "Benign": {
        "summary": "The flow was classified as benign and does not currently require threat-response action.",
        "actions": [
            "Retain the flow as part of the forensic case record.",
            "Correlate with surrounding flows if it is relevant to the incident timeline.",
            "Do not treat the classification alone as proof that the activity is harmless."
        ]
    }
}


def get_recommendation(predicted_class: str) -> Dict:
    if predicted_class not in RECOMMENDATIONS:
        raise KeyError(
            f"No recommendation is defined for class: {predicted_class}"
        )

    recommendation = RECOMMENDATIONS[predicted_class]

    return {
        "predicted_class": predicted_class,
        "summary": recommendation["summary"],
        "actions": recommendation["actions"]
    }
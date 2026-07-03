# SIEM-Based Cyber Attack Detection & Threat Simulation Lab  
**Cybersecurity Operations and Threat Intelligence Academic Assignment**

> ⚠️ **Disclaimer**  
> This project was conducted in a fully isolated virtual lab environment for academic purposes.  
> All IP addresses, systems, users, and attack scenarios are simulated and authorised.  
> No real-world infrastructure or production systems were targeted.

---

## 📘 Project Overview

This repository documents a full end-to-end **Security Information and Event Management (SIEM)** implementation and detection engineering project.

A simulated e-commerce company (BrightMart) was experiencing:

- Abnormal login activity  
- Suspicious network traffic spikes  
- Web application errors  
- Unusual endpoint behaviour  

The objective was to:

- Simulate realistic cyber attacks in a controlled lab  
- Ingest multi-source logs into a SIEM  
- Develop detection logic using measurable Indicators of Compromise (IoCs)  
- Configure real-time alerts  
- Propose structured mitigation strategies  

This project emphasises **blue team operations, detection engineering, log analysis, and incident response workflow design**.

---

## 🎯 Objectives

- Build a virtual SOC-style lab environment  
- Configure Splunk Enterprise for centralised log ingestion  
- Simulate common enterprise attack scenarios  
- Develop behaviour-based detection queries  
- Tune alerts to reduce false positives  
- Map technical findings to business impact  

---

## 🖥️ Lab Environment

### Virtual Architecture

| IP Address      | System                                  | Role |
|---------------|------------------------------------------|------|
| 192.168.8.130 | Windows 10 + OWASP Juice Shop           | Target Web Application |
| 192.168.8.131 | Windows Server 2012 + Splunk Enterprise | SIEM Indexer |
| 192.168.8.132 | Kali Linux                              | Attack Simulation Machine |

### Components

- Splunk Enterprise (SIEM)
- Splunk Universal Forwarder
- OWASP Juice Shop (vulnerable web application)
- Kali Linux (attack simulation)
- Snort IDS (network-level detection)
- Windows Defender (endpoint protection)

All systems were deployed within a private virtual network.

---

## 🔍 Simulated Attack Scenarios

The following attacks were executed in a controlled lab and detected through Splunk correlation rules:

### 1️. SQL Injection (SQLi)
### 2️. Cross-Site Scripting (XSS)
### 3️. Network Scanning
### 4️. Directory Enumeration
### 5️. Insecure Direct Object Reference (IDOR)
### 6️. Unauthorised Admin Endpoint Access
### 7️. Brute Force Authentication
### 8️. Denial of Service (DoS)
### 9️. Malware Infection Simulation
### 10. Business Logic Abuse
### 11. Cross-Site Request Forgery (CSRF)


## 📊 Key Outcomes

- Built a full SIEM detection pipeline
- Correlated network, system, and application logs
- Reduced detection time through automation
- Converted attack behaviour into measurable IoCs
- Demonstrated structured incident response workflow

---

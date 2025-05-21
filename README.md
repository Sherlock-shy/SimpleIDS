<h1>Python based SimpleIDS with port scan</h1> 

This repository contains a simple Python-based simulation of an Intrusion Detection System (IDS) designed to detect port scanning activities.

About the Project
The port scan simulation here is a basic brute-force approach where a socket client attempts to connect to every port on a target machine sequentially. This mimics how attackers try to discover open ports by trying to connect to many ports one by one.

The IDS component listens for these connection attempts and flags potential port scanning based on the pattern of rapid connection attempts to multiple ports.

Important Note
This code was originally written a few years ago for educational purposes and may not follow the latest best practices or include advanced detection techniques. It provides a straightforward example to help understand how port scanning can be detected with basic methods.

<h2>Environment setup</h2>

Create envrionment and install requirements

```bash
pip install -r requirements.txt
```
or just install scapy

```bash
pip install scapy
```



Feel free to explore, modify, and build upon this project.
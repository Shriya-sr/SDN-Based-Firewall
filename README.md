## ⚙️ Installation & Setup

1. Install dependencies:
   sudo apt update
   sudo apt install mininet openvswitch-switch python3-ryu -y

2. Start controller:
   ryu-manager firewall.py

3. Start Mininet:
   sudo mn --topo single,4 --controller remote --switch ovsk,protocols=OpenFlow13 --mac

## 1. Problem Understanding & Objective
The objective of this project is to implement a Software-Defined Networking (SDN) based firewall using Mininet and the Ryu OpenFlow controller. The primary goal is to develop controller logic that acts as a learning switch for standard traffic while explicitly blocking specific IPv4 communication (e.g., between Host 1 and Host 2) through dynamic OpenFlow match-action rules. 

### 🔑 Key Features
- 🔐 IP-based traffic filtering
- ⚡ Dynamic flow rule installation
- 🔁 Learning switch behavior
- 📊 Performance analysis using iperf

## 2. Topology Design & Justification
For this simulation, a single-switch, 4-host star topology was chosen.
* **Justification:** A single OpenFlow switch (s1) directly connected to four hosts (h1, h2, h3, h4) is the most effective and isolated environment to demonstrate access control. It removes the complexities of multi-hop routing, allowing for a clear demonstration of Layer 2/Layer 3 filtering. 
* Hosts 1 and 2 act as the "restricted" zone (blocked from each other), while Hosts 3 and 4 act as the "allowed" zone (unrestricted communication), perfectly satisfying the requirement to test allowed vs. blocked traffic scenarios.

## 3. Mininet & Controller Setup
The environment was set up using an Open vSwitch (OVS) and a remote Ryu controller running OpenFlow 1.3.

**Commands to initialize the environment:**
1. Start the Ryu Controller:
   `ryu-manager firewall.py`
   
   <img width="940" height="138" alt="image" src="https://github.com/user-attachments/assets/a0225147-5beb-4b15-94d7-9a58fc988d57" />

3. Start the Mininet Topology:
   `sudo mn --topo single,4 --controller remote --switch ovsk,protocols=OpenFlow13 --mac`
   
   <img width="940" height="262" alt="image" src="https://github.com/user-attachments/assets/6f4c0fb2-ee19-437e-a7d1-98714c5f91d9" />


## 4. SDN Logic & Flow Rule Implementation

The core logic of this firewall resides in the `StaticFirewall` class within `firewall.py`, which acts as a dynamic learning switch with integrated access control.

### Handling `packet_in` Events
A Table-Miss flow entry is installed when the switch connects (priority `0`), which routes all unmatched packets to the Ryu controller via `EventOFPPacketIn`. The controller then parses the packet payload (Ethernet and IPv4 headers) to determine the appropriate action. 

## 🔐 Firewall Logic & Rule Implementation

### 🚫 Rule Definition

The SDN firewall enforces the following policy:

- ❌ **Blocked:** 10.0.0.1 → 10.0.0.2  
- ✅ **Allowed:** All other traffic  

---

### ⚙️ Working Principle

The controller follows a **match-action mechanism**:

1. The switch forwards unknown packets to the controller (`PacketIn`)
2. The controller parses the packet (Ethernet + IPv4)
3. Based on source and destination IP, it decides:
   - **Drop** → for blocked traffic  
   - **Forward** → for allowed traffic  

---

### 🔥 Flow Rule Design (Priority-Based)

To ensure the firewall cannot be bypassed, rules are installed with strict priorities:

#### 🔴 Firewall Rule (Priority 100)

- Matches:
  - IPv4 packets  
  - Source: `10.0.0.1`  
  - Destination: `10.0.0.2`  

- Action:
  - `[]` (No action → DROP)

- Behavior:
  - Blocks the packet  
  - Installs a **high-priority flow rule** in the switch  
  - Future packets are dropped directly at the switch  

---

#### 🟢 Forwarding Rules (Priority 10)

- Applies to:
  - All allowed traffic (ARP, normal IP communication)

- Behavior:
  - Learns MAC → port mapping  
  - Determines correct output port  
  - Installs forwarding rules  

- Matching:
  - **IP packets:** matched using IP addresses (to avoid firewall bypass)  
  - **Non-IP packets:** matched using MAC addresses  

- Result:
  - Future packets are forwarded directly by the switch  
  - Reduces controller involvement  

---

### 🧠 Key Concept

- **High-priority rules (100)** → enforce firewall (DROP)  
- **Lower-priority rules (10)** → handle normal forwarding  
- Ensures **security rules always override forwarding rules**

---

### ⚡ Summary

- First packet → handled by controller  
- Rule installed → switch handles future packets  
- Firewall rule guarantees blocked traffic is never forwarded  
- Learning switch ensures efficient communication for allowed traffic

## 5. Functional Correctness & Validation

The project successfully demonstrates the intended SDN functionalities:

* **Forwarding (Learning Switch):** Standard traffic is permitted. Hosts in the "allowed" zone (e.g., h3 and h4) can communicate without restriction.
* **Blocking/Filtering (Firewall):** The controller successfully intercepts and blocks specific unauthorized traffic (IPv4 packets from h1 to h2) while still allowing ARP resolution.
* **Monitoring/Logging:** The Ryu controller actively monitors `packet_in` events and maintains a console log of all blocked packets.

### 🧪 Validation Scenario 1: Allowed vs. Blocked Traffic

<img width="598" height="197" alt="image" src="https://github.com/user-attachments/assets/00a1e2ac-d818-45bd-bb12-b54d357120db" />


- ❌ **h1 → h2** communication is successfully blocked (100% packet loss)  
- ✅ **h3 ↔ h4** and other host pairs maintain full connectivity  

📌 *This confirms that the firewall rule is correctly enforced without affecting normal traffic.*

---

### 📋 Validation Scenario 2: Controller Logging

<img width="841" height="77" alt="image" src="https://github.com/user-attachments/assets/9ad486b3-593e-4c38-9dd1-4993d1d1fd4e" />


- 🚫 Detects forbidden communication (10.0.0.1 → 10.0.0.2)  
- 📝 Logs source and destination IP addresses  
- ⛔ Drops the packet before forwarding  

📌 *This verifies correct packet inspection and real-time firewall enforcement.*

## 6. 📈 Performance Observation & Analysis

To analyze the performance and behavior of the SDN network, both throughput and flow table statistics were measured.

---

### 🚀 Throughput Analysis (iperf)

<img width="731" height="89" alt="image" src="https://github.com/user-attachments/assets/6b2b89b3-7f3a-46ed-af20-efe2020959fb" />


*An `iperf` test was conducted between two unblocked hosts (h3 and h4) to measure network throughput.*

- 📡 Communication between allowed hosts shows **high throughput**
- ⚡ No noticeable bottleneck introduced by the controller
- 🔁 Learning switch ensures packets are forwarded efficiently after initial setup  

📌 *This demonstrates that the SDN controller does not impact performance for permitted traffic.*

---

### Flow Table Changes & Packet Counts
<img width="1124" height="238" alt="image" src="https://github.com/user-attachments/assets/e28ff6bb-04f9-432b-a358-8bd82622bd2f" />

*The flow table dump from OVS (`s1`) clearly illustrates the dynamic changes pushed by the controller:*


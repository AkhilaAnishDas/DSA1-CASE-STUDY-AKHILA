# 🛡️ FireGuard - Cloud Security Packet Filtering System

## 👨‍💻 Author

**Akhila Anish**
* 📝 ROLL NO: 150096725016 
*📍COHORT: LARRY PAGE (2025-2029)
* 🎓 B.Tech Computer Science & Engineering
* 🏫 ITM Skills University

🔗 **GitHub Repository:**
https://github.com/AkhilaAnishDas/DSA1-CASE-STUDY-AKHILA.git

---

# 📌 Project Title

**FireGuard: Cloud Security Packet Filtering System Using Data Structures and Algorithms in C++**

---

# 📝 Problem Statement

Modern cloud infrastructures receive thousands of network packets every second. Firewalls are responsible for monitoring, filtering, and securing network traffic entering an organization's cloud environment.

Traditional systems face several challenges:

* ⚠️ Slow attack signature detection.
* ⚠️ Inefficient storage of malicious patterns.
* ⚠️ Lack of a proper audit trail.
* ⚠️ Difficulty processing packets fairly.
* ⚠️ Slow identification of active connections.
* ⚠️ Challenges in detecting suspiciously large data transfers.
* ⚠️ Absence of a structured firewall architecture map.
* ⚠️ Difficulty tracing the shortest route taken by suspicious traffic.
* ⚠️ Uneven workload distribution across security servers.

To solve these issues, FireGuard was developed using efficient Data Structures and Algorithms (DSA) to provide fast, scalable, and reliable firewall management.

---

# 🎯 Objectives

The primary objectives of FireGuard are:

✅ Detect malicious payloads efficiently.

✅ Store and retrieve attack signatures quickly.

✅ Maintain a complete firewall inspection history.

✅ Process packets strictly in arrival order.

✅ Provide instant socket status lookup.

✅ Sort network flows based on traffic volume.

✅ Represent firewall architecture using graph structures.

✅ Find shortest paths for security validation.

✅ Balance packet inspection workload among servers.

✅ Demonstrate practical applications of DSA in cybersecurity.

---

# 🌐 System Overview

FireGuard simulates a cloud firewall monitoring system.

The system continuously monitors incoming network traffic, checks for malicious signatures, records inspection logs, manages active connections, analyzes network flows, maps firewall infrastructure, traces suspicious routes, and distributes workload among security servers.

---

# 🏗️ System Architecture

```text
                    INTERNET TRAFFIC
                            │
                            ▼
                🔍 Pattern Detection (Trie)
                            │
                            ▼
               📥 Packet Verification Queue
                            │
                            ▼
                 🔥 Firewall Inspection
                            │
                            ▼
                    📜 Audit Logging
                            │
                            ▼
                 🔌 Socket Monitoring
                            │
                            ▼
                  🌊 Flow Analysis
                            │
                            ▼
               🕸️ Firewall Architecture
                            │
                            ▼
             🛣️ Validation Path Analysis
                            │
                            ▼
              ⚖️ Traffic Load Allocation
```

---

# 🧠 Data Structures and Algorithms Used

| Feature                 | Data Structure / Algorithm | Purpose                         |
| ----------------------- | -------------------------- | ------------------------------- |
| 🔍 Pattern List         | Trie                       | Fast attack signature matching  |
| 📜 Logging Trail        | Stack                      | Audit trail management          |
| 📥 Verification Line    | Queue                      | FIFO packet inspection          |
| 🔌 Socket Identity      | Hash Map (unordered_map)   | Instant socket lookup           |
| 🌊 Flow Sorter          | Max Heap (Priority Queue)  | Sort flows by volume            |
| 🕸️ Firewall Interfaces | Graph (Adjacency List)     | Represent firewall architecture |
| 🛣️ Validation Path     | Breadth First Search (BFS) | Find shortest route             |
| ⚖️ Traffic Allocator    | Min Heap                   | Load balancing                  |

---

# ⚙️ Implementation Approach

## 🔍 Pattern List Module

### Data Structure Used:

Trie

### Purpose:

Stores thousands of attack signatures and malicious keywords.

### Example:

```text
virus
trojan
malware
ransomware
```

Incoming traffic:

```text
This file contains malware code
```

Output:

```text
ALERT: Malicious Pattern Detected
```

### Advantage:

Fast pattern matching even with large datasets.

---

## 📜 Logging Trail Module

### Data Structure Used:

Stack

### Purpose:

Stores firewall inspection history.

### Example:

```text
Packet Received
Virus Scan
Port Scan
Rule Applied
```

### Advantage:

Latest action is always accessible first.

---

## 📥 Verification Line Module

### Data Structure Used:

Queue

### Purpose:

Processes packets in arrival order.

### Example:

```text
Packet A
Packet B
Packet C
```

Inspection Order:

```text
Packet A
Packet B
Packet C
```

### Advantage:

Ensures fairness using FIFO.

---

## 🔌 Socket Identity Module

### Data Structure Used:

Hash Map

### Purpose:

Stores active socket IDs and statuses.

### Example:

```text
101 -> Active
102 -> Blocked
103 -> Suspicious
```

### Advantage:

Near O(1) lookup time.

---

## 🌊 Flow Sorter Module

### Data Structure Used:

Max Heap

### Purpose:

Displays highest-volume network flows first.

### Example:

```text
5000 MB
3000 MB
1200 MB
500 MB
```

### Advantage:

Quick identification of suspicious transfers.

---

## 🕸️ Firewall Interfaces Module

### Data Structure Used:

Graph

### Purpose:

Represents firewall architecture.

### Example:

```text
FW0 ---- FW1
 |        |
FW2 ---- FW3
```

### Advantage:

Models real-world network infrastructure efficiently.

---

## 🛣️ Validation Path Module

### Algorithm Used:

Breadth First Search (BFS)

### Purpose:

Finds the shortest route between firewalls.

### Example:

```text
FW0 → FW2 → FW4
```

### Advantage:

Efficient shortest-path discovery in unweighted networks.

---

## ⚖️ Traffic Allocator Module

### Data Structure Used:

Min Heap

### Purpose:

Balances workload among inspection servers.

### Example:

```text
Task 1 → Server 1
Task 2 → Server 2
Task 3 → Server 3
```

### Advantage:

Prevents server overload and bottlenecks.

---

# 📊 Time and Space Complexity Analysis

## 🔍 Trie

| Operation | Complexity |
| --------- | ---------- |
| Insert    | O(L)       |
| Search    | O(L)       |
| Space     | O(N × L)   |

Where:

* N = Number of attack signatures
* L = Length of signature

---

## 📜 Stack

| Operation | Complexity |
| --------- | ---------- |
| Push      | O(1)       |
| Pop       | O(1)       |
| Space     | O(N)       |

---

## 📥 Queue

| Operation | Complexity |
| --------- | ---------- |
| Enqueue   | O(1)       |
| Dequeue   | O(1)       |
| Space     | O(N)       |

---

## 🔌 Hash Map

| Operation | Complexity |
| --------- | ---------- |
| Insert    | O(1)       |
| Search    | O(1)       |
| Space     | O(N)       |

---

## 🌊 Max Heap

| Operation | Complexity |
| --------- | ---------- |
| Insert    | O(log N)   |
| Delete    | O(log N)   |
| Space     | O(N)       |

---

## 🕸️ Graph

| Operation | Complexity |
| --------- | ---------- |
| Storage   | O(V + E)   |

Where:

* V = Number of Firewalls
* E = Number of Connections

---

## 🛣️ BFS

| Operation | Complexity |
| --------- | ---------- |
| Time      | O(V + E)   |
| Space     | O(V)       |

---

## ⚖️ Min Heap

| Operation | Complexity |
| --------- | ---------- |
| Insert    | O(log N)   |
| Remove    | O(log N)   |
| Space     | O(N)       |

---

# 🚀 How to Run the Project

## 📥 Clone Repository

```bash
git clone https://github.com/AkhilaAnishDas/DSA1-CASE-STUDY-AKHILA.git
cd DSA1-CASE-STUDY-AKHILA
```

---

# 💻 Compile Using GNU G++

```bash
g++ FireGuard_Menu_Driven.cpp -o FireGuard
```

### Run

```bash
./FireGuard
```

---

# 🍎 Compile Using Clang++

```bash
clang++ FireGuard_Menu_Driven.cpp -std=c++17 -o FireGuard
```

### Run

```bash
./FireGuard
```

---

# 🪟 Windows Users

Compile:

```bash
g++ FireGuard_Menu_Driven.cpp -o FireGuard.exe
```

Run:

```bash
FireGuard.exe
```

---

# 📋 Menu Options

```text
1. Add Attack Signatures
2. Scan Traffic Payload
3. Add Firewall Log
4. View Audit Trail
5. Add Packets
6. Process Packets
7. Add Socket Status
8. Search Socket
9. Add Network Flows
10. View Sorted Flows
11. Build Firewall Architecture
12. Find Validation Path
13. Allocate Traffic Load
14. Exit
```

---

# 🧪 Sample Input and Output

## Example 1: Pattern Detection

Input:

```text
1
3
virus
trojan
malware

2
This file contains malware code
```

Output:

```text
ALERT: Malicious Pattern Detected
```

---

## Example 2: Socket Lookup

Input:

```text
7
101 active

8
101
```

Output:

```text
Status = active
```

---

## Example 3: Validation Path

Input:

```text
11

5
4

0 1
1 2
2 3
3 4

12

0
4
```

Output:

```text
Shortest Path:
0 1 2 3 4
```

---

# 📸 Screenshots

Add screenshots of:

📍 Main Menu

📍 Pattern Detection Module

📍 Audit Trail Module

📍 Packet Verification Queue

📍 Socket Lookup Module

📍 Flow Sorter Module

📍 Firewall Architecture Module

📍 Validation Path Result

📍 Traffic Allocation Module

📍 Program Exit Screen

---

# 📈 Results and Observations

### 🔍 Observations

* Trie enables fast attack signature matching.
* Queue ensures fair packet processing.
* Stack maintains reliable audit history.
* Hash Map provides instant socket lookup.
* Heap structures efficiently prioritize flows and balance workloads.
* Graph and BFS accurately model firewall networks.
* The menu-driven interface improves usability and testing.

### ✅ Results

The FireGuard system successfully satisfies all requirements specified in the problem statement and demonstrates how Data Structures and Algorithms can be applied to real-world cybersecurity and cloud infrastructure management.

---

# 🎓 Conclusion

FireGuard is a DSA-based cloud security monitoring system implemented in C++.

The project integrates multiple data structures and algorithms to solve practical firewall management challenges, including:

✅ Attack signature detection

✅ Audit trail management

✅ Packet verification

✅ Socket monitoring

✅ Flow analysis

✅ Firewall architecture mapping

✅ Shortest path tracing

✅ Traffic load balancing

The project demonstrates efficient problem-solving using DSA while providing a strong foundation for future enhancements in cybersecurity and cloud networking systems.

---

# ⭐ Key Learning Outcomes

* Practical application of Data Structures and Algorithms.
* Understanding of firewall and network security concepts.
* Efficient implementation of Trie, Stack, Queue, Hash Map, Heap, Graph, and BFS.
* Experience in designing menu-driven console applications.
* Exposure to real-world cloud security scenarios.

---

# 🙏 Thank You

Happy Coding! 🚀

/**
 * FireGuard - Cloud Security Packet Filtering System
 * ====================================================
 * Real-time packet inspection inspired by Palo Alto & Fortinet architectures.
 *
 * Data Structures Used:
 *  1. Trie          → Pattern List (attack signature matching, O(m) lookup)
 *  2. Stack         → Logging Trail (audit trail, reversible breach analysis)
 *  3. Queue         → Verification Line (FIFO packet inspection)
 *  4. Hash Map      → Socket Identity (O(1) socket status lookup)
 *  5. Priority Queue→ Flow Sorter (max-heap by data volume, detect exfiltration)
 *  6. Graph (adj list)→ Firewall Interfaces (zone topology map)
 *  7. BFS/Dijkstra  → Validation Path (shortest bypass route)
 *  8. Round-Robin   → Traffic Allocator (load balancing across servers)
 */

#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <stack>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <climits>
#include <iomanip>
#include <ctime>
#include <stdexcept>

using namespace std;

// ─────────────────────────────────────────────
// 1. TRIE – Attack Pattern Matching (Palo Alto App-ID style)
// ─────────────────────────────────────────────
struct TrieNode {
    unordered_map<char, TrieNode*> children;
    bool isEnd = false;
    string pattern;
};

class PatternTrie {
    TrieNode* root;
public:
    PatternTrie() : root(new TrieNode()) {}

    void insert(const string& word) {
        TrieNode* cur = root;
        for (char c : word) {
            c = tolower(c);
            if (!cur->children.count(c))
                cur->children[c] = new TrieNode();
            cur = cur->children[c];
        }
        cur->isEnd = true;
        cur->pattern = word;
    }

    // Returns matched pattern or "" if clean
    string search(const string& payload) {
        string lower = payload;
        transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        for (int i = 0; i < (int)lower.size(); i++) {
            TrieNode* cur = root;
            for (int j = i; j < (int)lower.size(); j++) {
                if (!cur->children.count(lower[j])) break;
                cur = cur->children[lower[j]];
                if (cur->isEnd) return cur->pattern;
            }
        }
        return "";
    }

    bool isEmpty() { return root->children.empty(); }
};

// ─────────────────────────────────────────────
// 2. STACK – Audit Log Trail (Fortinet FortiAnalyzer style)
// ─────────────────────────────────────────────
struct LogEntry {
    string timestamp, packetID, rule, result;
};

class AuditLog {
    stack<LogEntry> log;
public:
    string getTimestamp() {
        time_t t = time(nullptr);
        char buf[20];
        strftime(buf, sizeof(buf), "%H:%M:%S", localtime(&t));
        return string(buf);
    }

    void record(const string& pktID, const string& rule, const string& result) {
        log.push({getTimestamp(), pktID, rule, result});
        cout << "  [LOG] " << pktID << " | Rule: " << rule << " | Result: " << result << "\n";
    }

    void retrace(int n) {
        if (log.empty()) { cout << "  [AUDIT] No logs available.\n"; return; }
        stack<LogEntry> tmp = log;
        cout << "\n  ══ AUDIT TRAIL (last " << n << " entries, newest first) ══\n";
        cout << "  " << left << setw(10) << "Time" << setw(16) << "Packet ID"
             << setw(24) << "Rule Applied" << "Result\n";
        cout << "  " << string(60, '-') << "\n";
        int shown = 0;
        while (!tmp.empty() && shown < n) {
            auto& e = tmp.top();
            cout << "  " << setw(10) << e.timestamp << setw(16) << e.packetID
                 << setw(24) << e.rule << e.result << "\n";
            tmp.pop(); shown++;
        }
    }
};

// ─────────────────────────────────────────────
// 3. QUEUE – Packet Inspection Line (Strict FIFO)
// ─────────────────────────────────────────────
struct Packet {
    string id, srcIP, dstIP, payload;
    int size;
};

class InspectionQueue {
    queue<Packet> q;
public:
    void enqueue(const Packet& p) {
        q.push(p);
        cout << "  [QUEUE] Packet " << p.id << " from " << p.srcIP
             << " → " << p.dstIP << " enqueued (size=" << p.size << "B)\n";
    }

    bool inspect(PatternTrie& trie, AuditLog& log) {
        if (q.empty()) { cout << "  [QUEUE] No packets pending.\n"; return false; }
        Packet p = q.front(); q.pop();
        cout << "\n  ── Inspecting Packet " << p.id << " ──\n";
        string hit = trie.search(p.payload);
        if (!hit.empty()) {
            log.record(p.id, "PATTERN_MATCH:" + hit, "BLOCKED");
            cout << "  [ALERT] Malicious payload detected: \"" << hit << "\" → BLOCKED\n";
            return false;
        }
        log.record(p.id, "DEEP_INSPECTION", "ALLOWED");
        cout << "  [PASS] Packet " << p.id << " is clean → ALLOWED\n";
        return true;
    }

    int size() { return (int)q.size(); }
    bool empty() { return q.empty(); }
};

// ─────────────────────────────────────────────
// 4. HASH MAP – Socket Identity Registry (O(1) lookup)
// ─────────────────────────────────────────────
struct SocketInfo {
    string srcIP, dstIP, status; // ACTIVE / BLOCKED / SUSPICIOUS
    int port;
};

class SocketRegistry {
    unordered_map<string, SocketInfo> table;
public:
    void add(const string& id, const SocketInfo& info) {
        table[id] = info;
        cout << "  [SOCKET] Registered " << id << " | " << info.srcIP
             << ":" << info.port << " → " << info.dstIP
             << " | Status: " << info.status << "\n";
    }

    void query(const string& id) {
        if (!table.count(id)) {
            cout << "  [SOCKET] ID '" << id << "' not found.\n"; return;
        }
        auto& s = table[id];
        cout << "  ── Socket " << id << " ──\n"
             << "  Source : " << s.srcIP << ":" << s.port << "\n"
             << "  Dest   : " << s.dstIP << "\n"
             << "  Status : " << s.status << "\n";
    }

    void updateStatus(const string& id, const string& status) {
        if (!table.count(id)) { cout << "  [SOCKET] ID not found.\n"; return; }
        table[id].status = status;
        cout << "  [SOCKET] " << id << " status updated to " << status << "\n";
    }

    void listAll() {
        if (table.empty()) { cout << "  [SOCKET] Registry empty.\n"; return; }
        cout << "  " << left << setw(14) << "Socket ID" << setw(18) << "Source"
             << setw(16) << "Destination" << "Status\n";
        cout << "  " << string(58, '-') << "\n";
        for (auto& [id, s] : table)
            cout << "  " << setw(14) << id << setw(18) << (s.srcIP+":"+to_string(s.port))
                 << setw(16) << s.dstIP << s.status << "\n";
    }
};

// ─────────────────────────────────────────────
// 5. PRIORITY QUEUE – Flow Sorter (max-heap, detect data exfiltration)
// ─────────────────────────────────────────────
struct Flow {
    string id, srcIP, dstIP;
    long long bytes;
    bool operator<(const Flow& o) const { return bytes < o.bytes; } // max-heap
};

class FlowSorter {
    priority_queue<Flow> pq;
public:
    void addFlow(const Flow& f) {
        pq.push(f);
        cout << "  [FLOW] Added flow " << f.id << " | " << f.bytes << " bytes\n";
    }

    void showTopFlows(int n) {
        if (pq.empty()) { cout << "  [FLOW] No flows tracked.\n"; return; }
        priority_queue<Flow> tmp = pq;
        cout << "\n  ══ TOP " << n << " DATA FLOWS (by volume) ══\n";
        cout << "  " << left << setw(12) << "Flow ID" << setw(16) << "Source"
             << setw(16) << "Destination" << "Volume\n";
        cout << "  " << string(56, '-') << "\n";
        int shown = 0;
        while (!tmp.empty() && shown < n) {
            auto f = tmp.top(); tmp.pop();
            string flag = (f.bytes > 100000000LL) ? " ⚠ EXFIL RISK" : "";
            cout << "  " << setw(12) << f.id << setw(16) << f.srcIP
                 << setw(16) << f.dstIP << f.bytes << " B" << flag << "\n";
            shown++;
        }
    }
};

// ─────────────────────────────────────────────
// 6 & 7. GRAPH + BFS – Firewall Topology & Shortest Bypass Path
// ─────────────────────────────────────────────
class FirewallGraph {
    unordered_map<string, vector<pair<string,int>>> adj;
    unordered_set<string> nodes;
public:
    void addZone(const string& zone) {
        nodes.insert(zone);
        cout << "  [TOPO] Zone '" << zone << "' added.\n";
    }

    void addLink(const string& a, const string& b, int cost = 1) {
        if (!nodes.count(a) || !nodes.count(b)) {
            cout << "  [TOPO] Error: One or both zones not found. Add zones first.\n";
            return;
        }
        adj[a].push_back({b, cost});
        adj[b].push_back({a, cost});
        cout << "  [TOPO] Link: " << a << " ↔ " << b << " (cost=" << cost << ")\n";
    }

    void showTopology() {
        if (nodes.empty()) { cout << "  [TOPO] No zones defined.\n"; return; }
        cout << "\n  ══ FIREWALL TOPOLOGY MAP ══\n";
        for (auto& z : nodes) {
            cout << "  [" << z << "] → ";
            if (!adj.count(z) || adj[z].empty()) { cout << "(isolated)\n"; continue; }
            for (auto& [nb, c] : adj[z])
                cout << nb << "(c=" << c << ") ";
            cout << "\n";
        }
    }

    // BFS shortest hop path
    void shortestPath(const string& src, const string& dst) {
        if (!nodes.count(src) || !nodes.count(dst)) {
            cout << "  [PATH] Zone(s) not found.\n"; return;
        }
        unordered_map<string, string> parent;
        unordered_map<string, int> dist;
        queue<string> bfsQ;
        for (auto& n : nodes) dist[n] = INT_MAX;
        dist[src] = 0;
        bfsQ.push(src);
        parent[src] = "";
        while (!bfsQ.empty()) {
            string cur = bfsQ.front(); bfsQ.pop();
            for (auto& [nb, _] : adj[cur]) {
                if (dist[nb] == INT_MAX) {
                    dist[nb] = dist[cur] + 1;
                    parent[nb] = cur;
                    bfsQ.push(nb);
                }
            }
        }
        if (dist[dst] == INT_MAX) {
            cout << "  [PATH] No path from " << src << " to " << dst << ".\n"; return;
        }
        vector<string> path;
        for (string cur = dst; cur != ""; cur = parent[cur])
            path.push_back(cur);
        reverse(path.begin(), path.end());
        cout << "\n  ══ SHORTEST BYPASS ROUTE: " << src << " → " << dst << " ══\n";
        cout << "  Hops: " << dist[dst] << "\n  Route: ";
        for (int i = 0; i < (int)path.size(); i++) {
            cout << path[i];
            if (i + 1 < (int)path.size()) cout << " → ";
        }
        cout << "\n  [TRACE] Vulnerability path identified. Audit these zones.\n";
    }
};

// ─────────────────────────────────────────────
// 8. ROUND-ROBIN – Traffic Allocator
// ─────────────────────────────────────────────
class TrafficAllocator {
    vector<string> servers;
    int idx = 0;
public:
    void addServer(const string& s) {
        servers.push_back(s);
        cout << "  [ALLOC] Server '" << s << "' registered.\n";
    }

    void dispatch(const string& packetID) {
        if (servers.empty()) { cout << "  [ALLOC] No servers configured.\n"; return; }
        cout << "  [ALLOC] Packet " << packetID << " → Server: "
             << servers[idx] << "\n";
        idx = (idx + 1) % (int)servers.size();
    }

    void status() {
        if (servers.empty()) { cout << "  [ALLOC] No servers.\n"; return; }
        cout << "  Configured servers (" << servers.size() << "): ";
        for (auto& s : servers) cout << s << " ";
        cout << "\n  Next dispatch index: " << idx << "\n";
    }
};

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────
string trim(const string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    return (a == string::npos) ? "" : s.substr(a, b - a + 1);
}

bool validIP(const string& ip) {
    int dots = 0, num = 0, digits = 0;
    for (char c : ip) {
        if (c == '.') { if (num > 255 || digits == 0) return false; dots++; num = 0; digits = 0; }
        else if (isdigit(c)) { num = num * 10 + (c - '0'); digits++; }
        else return false;
    }
    return dots == 3 && num <= 255 && digits > 0;
}

// ─────────────────────────────────────────────
// MAIN MENU
// ─────────────────────────────────────────────
void printBanner() {
    cout << R"(
  ╔══════════════════════════════════════════════════════════╗
  ║          FireGuard - Cloud Security Firewall v2.0        ║
  ║     Real-time Packet Inspection & Threat Prevention      ║
  ╚══════════════════════════════════════════════════════════╝
)";
}

void printMenu() {
    cout << R"(
  ┌─────────────────────────────────────────────────┐
  │  MAIN MENU                                      │
  ├────┬────────────────────────────────────────────┤
  │ 1  │ Pattern List    – Manage attack signatures │
  │ 2  │ Logging Trail   – Audit log & retrace      │
  │ 3  │ Verification Line – Packet queue & inspect │
  │ 4  │ Socket Identity – Socket registry          │
  │ 5  │ Flow Sorter     – Data volume analysis     │
  │ 6  │ Firewall Interfaces – Topology map         │
  │ 7  │ Validation Path – Shortest bypass route    │
  │ 8  │ Traffic Allocator – Load balancing         │
  │ 0  │ Exit                                       │
  └────┴────────────────────────────────────────────┘
  Choice: )";
}

int main() {
    PatternTrie trie;
    AuditLog audit;
    InspectionQueue iq;
    SocketRegistry sockets;
    FlowSorter flows;
    FirewallGraph graph;
    TrafficAllocator alloc;

    // Seed defaults
    for (auto& p : {"sqlinjection","dropdatabase","exec(","<script>","xss",
                    "union select","eval(","passwd","rootkit","malware",
                    "exploit","shellcode","cmd.exe","wget http","curl http"})
        trie.insert(p);

    printBanner();
    cout << "  [INIT] Default attack signatures loaded.\n";
    cout << "  [INIT] FireGuard is ACTIVE. All traffic will be monitored.\n";

    string line;
    while (true) {
        printMenu();
        getline(cin, line);
        line = trim(line);
        if (line.empty()) continue;

        int choice = -1;
        try { choice = stoi(line); } catch (...) {
            cout << "  [ERROR] Invalid input. Enter a number 0-8.\n"; continue;
        }

        // ── 1. PATTERN LIST ──
        if (choice == 1) {
            cout << "\n  [1] Pattern List\n"
                 << "  a) Add pattern   b) Test payload   c) Show info\n  > ";
            string sub; getline(cin, sub); sub = trim(sub);
            if (sub == "a") {
                cout << "  Enter attack keyword/pattern: ";
                getline(cin, sub); sub = trim(sub);
                if (sub.empty()) { cout << "  [ERROR] Pattern cannot be empty.\n"; continue; }
                trie.insert(sub);
                cout << "  [PATTERN] \"" << sub << "\" added to signature database.\n";
            } else if (sub == "b") {
                cout << "  Enter payload to test: ";
                getline(cin, sub); sub = trim(sub);
                if (sub.empty()) { cout << "  [ERROR] Payload cannot be empty.\n"; continue; }
                string hit = trie.search(sub);
                if (!hit.empty())
                    cout << "  [ALERT] ⚠ THREAT DETECTED: matched pattern \"" << hit << "\"\n";
                else
                    cout << "  [CLEAN] No known threats detected in payload.\n";
            } else if (sub == "c") {
                cout << "  Trie-based multi-pattern engine active.\n"
                     << "  Matching is O(m) per payload where m = payload length.\n"
                     << "  Similar to Palo Alto App-ID & Content-ID engines.\n";
            } else cout << "  [ERROR] Unknown sub-command.\n";

        // ── 2. LOGGING TRAIL ──
        } else if (choice == 2) {
            cout << "\n  [2] Logging Trail\n"
                 << "  a) Retrace last N entries   b) Manual log entry\n  > ";
            string sub; getline(cin, sub); sub = trim(sub);
            if (sub == "a") {
                cout << "  How many entries to retrace? ";
                getline(cin, sub); sub = trim(sub);
                int n = 10;
                try { n = stoi(sub); if (n <= 0) throw invalid_argument(""); }
                catch (...) { cout << "  [WARN] Invalid N, showing last 10.\n"; n = 10; }
                audit.retrace(n);
            } else if (sub == "b") {
                cout << "  Packet ID: "; string pid; getline(cin, pid); pid = trim(pid);
                cout << "  Rule: ";      string rule; getline(cin, rule); rule = trim(rule);
                cout << "  Result (ALLOWED/BLOCKED/SUSPICIOUS): ";
                string res; getline(cin, res); res = trim(res);
                if (pid.empty() || rule.empty() || res.empty())
                    cout << "  [ERROR] All fields required.\n";
                else audit.record(pid, rule, res);
            } else cout << "  [ERROR] Unknown sub-command.\n";

        // ── 3. VERIFICATION LINE ──
        } else if (choice == 3) {
            cout << "\n  [3] Verification Line (Packet Queue)\n"
                 << "  a) Enqueue packet   b) Inspect next   c) Inspect all   d) Queue size\n  > ";
            string sub; getline(cin, sub); sub = trim(sub);
            if (sub == "a") {
                Packet p;
                cout << "  Packet ID (e.g. PKT-001): "; getline(cin, p.id); p.id = trim(p.id);
                if (p.id.empty()) { cout << "  [ERROR] Packet ID required.\n"; continue; }
                cout << "  Source IP (e.g. 192.168.1.10): "; getline(cin, p.srcIP); p.srcIP = trim(p.srcIP);
                if (!validIP(p.srcIP)) { cout << "  [ERROR] Invalid source IP.\n"; continue; }
                cout << "  Dest IP (e.g. 10.0.0.1): "; getline(cin, p.dstIP); p.dstIP = trim(p.dstIP);
                if (!validIP(p.dstIP)) { cout << "  [ERROR] Invalid destination IP.\n"; continue; }
                cout << "  Payload (the data content): "; getline(cin, p.payload); p.payload = trim(p.payload);
                cout << "  Packet size in bytes: ";
                string sz; getline(cin, sz);
                try { p.size = stoi(trim(sz)); if (p.size <= 0) throw invalid_argument(""); }
                catch (...) { cout << "  [ERROR] Invalid size. Using 64.\n"; p.size = 64; }
                iq.enqueue(p);
            } else if (sub == "b") {
                iq.inspect(trie, audit);
            } else if (sub == "c") {
                if (iq.empty()) { cout << "  [QUEUE] No packets.\n"; continue; }
                cout << "  Inspecting all " << iq.size() << " packet(s)...\n";
                while (!iq.empty()) iq.inspect(trie, audit);
            } else if (sub == "d") {
                cout << "  Packets pending inspection: " << iq.size() << "\n";
            } else cout << "  [ERROR] Unknown sub-command.\n";

        // ── 4. SOCKET IDENTITY ──
        } else if (choice == 4) {
            cout << "\n  [4] Socket Identity Registry\n"
                 << "  a) Register socket   b) Query socket   c) Update status   d) List all\n  > ";
            string sub; getline(cin, sub); sub = trim(sub);
            if (sub == "a") {
                string id, src, dst, st; int port;
                cout << "  Socket ID (e.g. SOCK-001): "; getline(cin, id); id = trim(id);
                if (id.empty()) { cout << "  [ERROR] Socket ID required.\n"; continue; }
                cout << "  Source IP: "; getline(cin, src); src = trim(src);
                if (!validIP(src)) { cout << "  [ERROR] Invalid source IP.\n"; continue; }
                cout << "  Dest IP: "; getline(cin, dst); dst = trim(dst);
                if (!validIP(dst)) { cout << "  [ERROR] Invalid dest IP.\n"; continue; }
                cout << "  Port (1-65535): ";
                string ps; getline(cin, ps);
                try { port = stoi(trim(ps)); if (port < 1 || port > 65535) throw invalid_argument(""); }
                catch (...) { cout << "  [ERROR] Invalid port. Using 80.\n"; port = 80; }
                cout << "  Status (ACTIVE/BLOCKED/SUSPICIOUS): "; getline(cin, st); st = trim(st);
                if (st != "ACTIVE" && st != "BLOCKED" && st != "SUSPICIOUS") {
                    cout << "  [WARN] Unknown status, defaulting to ACTIVE.\n"; st = "ACTIVE";
                }
                sockets.add(id, {src, dst, st, port});
            } else if (sub == "b") {
                cout << "  Socket ID to query: ";
                string id; getline(cin, id); sockets.query(trim(id));
            } else if (sub == "c") {
                cout << "  Socket ID: "; string id; getline(cin, id); id = trim(id);
                cout << "  New status (ACTIVE/BLOCKED/SUSPICIOUS): ";
                string st; getline(cin, st); st = trim(st);
                if (st != "ACTIVE" && st != "BLOCKED" && st != "SUSPICIOUS") {
                    cout << "  [ERROR] Invalid status.\n"; continue;
                }
                sockets.updateStatus(id, st);
            } else if (sub == "d") {
                sockets.listAll();
            } else cout << "  [ERROR] Unknown sub-command.\n";

        // ── 5. FLOW SORTER ──
        } else if (choice == 5) {
            cout << "\n  [5] Flow Sorter (Data Volume Analysis)\n"
                 << "  a) Add flow   b) Show top N flows\n  > ";
            string sub; getline(cin, sub); sub = trim(sub);
            if (sub == "a") {
                Flow f;
                cout << "  Flow ID (e.g. FLOW-001): "; getline(cin, f.id); f.id = trim(f.id);
                if (f.id.empty()) { cout << "  [ERROR] Flow ID required.\n"; continue; }
                cout << "  Source IP: "; getline(cin, f.srcIP); f.srcIP = trim(f.srcIP);
                if (!validIP(f.srcIP)) { cout << "  [ERROR] Invalid source IP.\n"; continue; }
                cout << "  Dest IP: "; getline(cin, f.dstIP); f.dstIP = trim(f.dstIP);
                if (!validIP(f.dstIP)) { cout << "  [ERROR] Invalid dest IP.\n"; continue; }
                cout << "  Data volume in bytes: ";
                string bstr; getline(cin, bstr);
                try { f.bytes = stoll(trim(bstr)); if (f.bytes < 0) throw invalid_argument(""); }
                catch (...) { cout << "  [ERROR] Invalid byte count. Using 1000.\n"; f.bytes = 1000; }
                flows.addFlow(f);
            } else if (sub == "b") {
                cout << "  Show top N flows (e.g. 5): ";
                string ns; getline(cin, ns);
                int n = 5;
                try { n = stoi(trim(ns)); if (n <= 0) throw invalid_argument(""); }
                catch (...) { cout << "  [WARN] Invalid N. Using 5.\n"; n = 5; }
                flows.showTopFlows(n);
            } else cout << "  [ERROR] Unknown sub-command.\n";

        // ── 6. FIREWALL INTERFACES ──
        } else if (choice == 6) {
            cout << "\n  [6] Firewall Interfaces (Topology)\n"
                 << "  a) Add zone   b) Add link   c) Show topology\n  > ";
            string sub; getline(cin, sub); sub = trim(sub);
            if (sub == "a") {
                cout << "  Zone name (e.g. DMZ, INTERNAL, WAN, DB-ZONE): ";
                string z; getline(cin, z); z = trim(z);
                if (z.empty()) { cout << "  [ERROR] Zone name required.\n"; continue; }
                graph.addZone(z);
            } else if (sub == "b") {
                string a, b, cs;
                cout << "  Zone A: "; getline(cin, a); a = trim(a);
                cout << "  Zone B: "; getline(cin, b); b = trim(b);
                cout << "  Link cost (default 1): "; getline(cin, cs); cs = trim(cs);
                int cost = 1;
                try { if (!cs.empty()) cost = stoi(cs); if (cost <= 0) throw invalid_argument(""); }
                catch (...) { cout << "  [WARN] Invalid cost. Using 1.\n"; cost = 1; }
                graph.addLink(a, b, cost);
            } else if (sub == "c") {
                graph.showTopology();
            } else cout << "  [ERROR] Unknown sub-command.\n";

        // ── 7. VALIDATION PATH ──
        } else if (choice == 7) {
            cout << "\n  [7] Validation Path (Shortest Bypass Route)\n";
            string src, dst;
            cout << "  From zone: "; getline(cin, src); src = trim(src);
            cout << "  To zone  : "; getline(cin, dst); dst = trim(dst);
            if (src.empty() || dst.empty())
                cout << "  [ERROR] Both zones required.\n";
            else graph.shortestPath(src, dst);

        // ── 8. TRAFFIC ALLOCATOR ──
        } else if (choice == 8) {
            cout << "\n  [8] Traffic Allocator (Round-Robin Load Balancing)\n"
                 << "  a) Add server   b) Dispatch packet   c) Server status\n  > ";
            string sub; getline(cin, sub); sub = trim(sub);
            if (sub == "a") {
                cout << "  Server name (e.g. SEC-SERVER-01): ";
                string s; getline(cin, s); s = trim(s);
                if (s.empty()) { cout << "  [ERROR] Server name required.\n"; continue; }
                alloc.addServer(s);
            } else if (sub == "b") {
                cout << "  Packet ID to dispatch: ";
                string pid; getline(cin, pid); pid = trim(pid);
                if (pid.empty()) { cout << "  [ERROR] Packet ID required.\n"; continue; }
                alloc.dispatch(pid);
            } else if (sub == "c") {
                alloc.status();
            } else cout << "  [ERROR] Unknown sub-command.\n";

        // ── 0. EXIT ──
        } else if (choice == 0) {
            cout << "\n  [FireGuard] Shutting down. All logs preserved. Stay secure.\n\n";
            break;
        } else {
            cout << "  [ERROR] Invalid choice. Enter 0-8.\n";
        }
    }
    return 0;
}

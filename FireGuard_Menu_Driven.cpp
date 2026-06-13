
#include <iostream>
#include <vector>
#include <queue>
#include <stack>
#include <unordered_map>
#include <algorithm>
#include <string>
using namespace std;

class TrieNode {
public:
    TrieNode* child[26];
    bool isEnd;
    TrieNode() {
        isEnd = false;
        for(int i=0;i<26;i++) child[i]=NULL;
    }
};

class Trie {
    TrieNode* root;
public:
    Trie(){ root=new TrieNode(); }

    void insert(string word){
        TrieNode* cur=root;
        for(char c:word){
            if(!isalpha(c)) continue;
            c=tolower(c);
            int idx=c-'a';
            if(cur->child[idx]==NULL) cur->child[idx]=new TrieNode();
            cur=cur->child[idx];
        }
        cur->isEnd=true;
    }

    bool searchPattern(string text){
        transform(text.begin(),text.end(),text.begin(),::tolower);
        for(int i=0;i<(int)text.size();i++){
            TrieNode* cur=root;
            for(int j=i;j<(int)text.size();j++){
                if(!isalpha(text[j])) break;
                int idx=text[j]-'a';
                if(idx<0 || idx>=26 || cur->child[idx]==NULL) break;
                cur=cur->child[idx];
                if(cur->isEnd) return true;
            }
        }
        return false;
    }
};

int main() {
    Trie attackPatterns;
    stack<string> logs;
    queue<string> packetQueue;
    unordered_map<int,string> socketStatus;
    priority_queue<pair<int,string>> flowHeap;

    vector<vector<int>> graph;
    int V=0;

    int choice;

    do{
        cout<<"\n========== FIREGUARD ==========\n";
        cout<<"1. Add Attack Signatures\n";
        cout<<"2. Scan Traffic Payload\n";
        cout<<"3. Add Firewall Log\n";
        cout<<"4. View Audit Trail\n";
        cout<<"5. Add Packets\n";
        cout<<"6. Process Packets\n";
        cout<<"7. Add Socket Status\n";
        cout<<"8. Search Socket\n";
        cout<<"9. Add Network Flows\n";
        cout<<"10. View Sorted Flows\n";
        cout<<"11. Build Firewall Architecture\n";
        cout<<"12. Find Validation Path\n";
        cout<<"13. Allocate Traffic Load\n";
        cout<<"14. Exit\n";
        cout<<"Enter Choice: ";

        if(!(cin>>choice)){
            cin.clear();
            cin.ignore(1000,'\n');
            cout<<"Invalid input!\n";
            continue;
        }

        switch(choice){

        case 1:{
            int n;
            cout<<"Number of signatures: ";
            cin>>n;
            for(int i=0;i<n;i++){
                string s;
                cin>>s;
                attackPatterns.insert(s);
            }
            cout<<"Signatures added.\n";
            break;
        }

        case 2:{
            cin.ignore();
            string payload;
            cout<<"Enter payload: ";
            getline(cin,payload);

            if(attackPatterns.searchPattern(payload))
                cout<<"ALERT: Malicious Pattern Detected\n";
            else
                cout<<"Traffic Safe\n";
            break;
        }

        case 3:{
            cin.ignore();
            string log;
            cout<<"Enter firewall log: ";
            getline(cin,log);
            logs.push(log);
            cout<<"Log added.\n";
            break;
        }

        case 4:{
            if(logs.empty()){
                cout<<"No logs available.\n";
                break;
            }

            stack<string> temp=logs;
            cout<<"Audit Trail:\n";

            while(!temp.empty()){
                cout<<temp.top()<<endl;
                temp.pop();
            }
            break;
        }

        case 5:{
            int n;
            cout<<"Number of packets: ";
            cin>>n;

            for(int i=0;i<n;i++){
                string p;
                cin>>p;
                packetQueue.push(p);
            }
            cout<<"Packets added.\n";
            break;
        }

        case 6:{
            if(packetQueue.empty()){
                cout<<"No packets to inspect.\n";
                break;
            }

            cout<<"Inspection Order:\n";

            while(!packetQueue.empty()){
                cout<<packetQueue.front()<<endl;
                packetQueue.pop();
            }
            break;
        }

        case 7:{
            int id;
            string status;

            cout<<"Socket ID: ";
            cin>>id;

            cout<<"Status(active/blocked/suspicious): ";
            cin>>status;

            socketStatus[id]=status;

            cout<<"Socket stored.\n";
            break;
        }

        case 8:{
            int id;
            cout<<"Enter Socket ID: ";
            cin>>id;

            if(socketStatus.find(id)!=socketStatus.end())
                cout<<"Status = "<<socketStatus[id]<<endl;
            else
                cout<<"Socket Not Found\n";

            break;
        }

        case 9:{
            int n;
            cout<<"Number of flows: ";
            cin>>n;

            for(int i=0;i<n;i++){
                string name;
                int volume;

                cin>>name>>volume;

                flowHeap.push({volume,name});
            }

            cout<<"Flows added.\n";
            break;
        }

        case 10:{
            if(flowHeap.empty()){
                cout<<"No flows available.\n";
                break;
            }

            priority_queue<pair<int,string>> temp=flowHeap;

            cout<<"Flows By Volume:\n";

            while(!temp.empty()){
                cout<<temp.top().second<<" -> "
                    <<temp.top().first<<" MB\n";
                temp.pop();
            }
            break;
        }

        case 11:{
            int E;

            cout<<"Number of Firewalls: ";
            cin>>V;

            graph.assign(V,vector<int>());

            cout<<"Number of Connections: ";
            cin>>E;

            for(int i=0;i<E;i++){
                int u,v;
                cin>>u>>v;

                if(u>=0 && u<V && v>=0 && v<V){
                    graph[u].push_back(v);
                    graph[v].push_back(u);
                }
            }

            cout<<"Architecture Built.\n";
            break;
        }

        case 12:{
            if(V==0){
                cout<<"Build graph first.\n";
                break;
            }

            int source,destination;

            cout<<"Source: ";
            cin>>source;

            cout<<"Destination: ";
            cin>>destination;

            vector<int> parent(V,-1);
            vector<bool> visited(V,false);

            queue<int> q;

            q.push(source);
            visited[source]=true;

            while(!q.empty()){
                int node=q.front();
                q.pop();

                for(int nxt:graph[node]){
                    if(!visited[nxt]){
                        visited[nxt]=true;
                        parent[nxt]=node;
                        q.push(nxt);
                    }
                }
            }

            if(!visited[destination]){
                cout<<"No Path Found\n";
            }else{
                vector<int> path;

                for(int cur=destination;cur!=-1;cur=parent[cur])
                    path.push_back(cur);

                reverse(path.begin(),path.end());

                cout<<"Shortest Path: ";

                for(int x:path)
                    cout<<x<<" ";

                cout<<endl;
            }

            break;
        }

        case 13:{
            int servers,tasks;

            cout<<"Number of Servers: ";
            cin>>servers;

            priority_queue<pair<int,int>,
            vector<pair<int,int>>,
            greater<pair<int,int>>> allocator;

            for(int i=1;i<=servers;i++)
                allocator.push({0,i});

            cout<<"Number of Tasks: ";
            cin>>tasks;

            for(int i=1;i<=tasks;i++){
                int load;
                cin>>load;

                auto cur=allocator.top();
                allocator.pop();

                cout<<"Task "<<i
                    <<" -> Server "
                    <<cur.second<<endl;

                cur.first+=load;

                allocator.push(cur);
            }

            break;
        }

        case 14:
            cout<<"Thank You For Using FireGuard\n";
            break;

        default:
            cout<<"Invalid Choice\n";
        }

    }while(choice!=14);

    return 0;
}

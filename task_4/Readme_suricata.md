
### Step-by-Step Guide to Set Up a Network-Based Intrusion Detection System Using Suricata

---

### **Step 1: Installation of Suricata**

1. **Update Your System:**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```
   
2. **Install Suricata:**
   - For Ubuntu:
     ```bash
     sudo apt install suricata -y
     ```
   - For CentOS:
     ```bash
     sudo yum install epel-release -y
     sudo yum install suricata -y
     ```

3. **Verify Installation:**
   ```bash
   suricata --version
   ```

### **Step 2: Basic Configuration of Suricata**

1. **Configure Network Interfaces:**
   - Edit the Suricata configuration file (typically `/etc/suricata/suricata.yaml`):
     ```yaml
     af-packet:
       - interface: eth0
         cluster-id: 99
         cluster-type: cluster_flow
         defrag: yes
     ```
   Replace `eth0` with the network interface that Suricata should monitor.

2. **Test the Configuration:**
   ```bash
   suricata -T -c /etc/suricata/suricata.yaml
   ```

3. **Start Suricata:**
   ```bash
   sudo systemctl start suricata
   sudo systemctl enable suricata
   ```

### **Step 3: Setting Up Rules and Alerts**

1. **Download Rules:**
   - Suricata can use rules from Emerging Threats (ET) or other sources. Download ET rules:
     ```bash
     sudo suricata-update
     ```

2. **Edit Rules:**
   - Add custom rules by editing the `.rules` files in `/var/lib/suricata/rules/`.
   - Example rule to detect ping sweeps:
     ```
     alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Sweep"; itype:8; sid:1000001; rev:1;)
     ```
   
3. **Reload Rules:**
   ```bash
   sudo suricata -c /etc/suricata/suricata.yaml -r /var/log/suricata/eve.json
   ```

### **Step 4: Setting Up Alerts**

1. **Configure Alert Output:**
   - In the configuration file (`/etc/suricata/suricata.yaml`), configure Suricata to log alerts to `eve.json` in JSON format for easy parsing and integration with visualization tools:
     ```yaml
     outputs:
       - eve-log:
           enabled: yes
           filetype: json
           filename: eve.json
           types:
             - alert
     ```

2. **Test the Alerts:**
   - Generate traffic (e.g., ping sweep or simple nmap scan) to test the rules and see the alerts logged in `/var/log/suricata/eve.json`.

### **Step 5: Visualizing Detected Attacks**

1. **Set Up ELK Stack (Elasticsearch, Logstash, Kibana):**
   - **Install Elasticsearch:**
     ```bash
     sudo apt install elasticsearch -y
     ```
   - **Install Logstash:**
     ```bash
     sudo apt install logstash -y
     ```
   - **Install Kibana:**
     ```bash
     sudo apt install kibana -y
     ```

2. **Configure Logstash:**
   - Create a configuration file for Logstash (e.g., `/etc/logstash/conf.d/suricata.conf`):
     ```plaintext
     input {
       file {
         path => "/var/log/suricata/eve.json"
         codec => json
       }
     }
     filter {
       if [event_type] == "alert" {
         mutate {
           add_field => { "event_type" => "alert" }
         }
       }
     }
     output {
       elasticsearch {
         hosts => ["localhost:9200"]
         index => "suricata-%{+YYYY.MM.dd}"
       }
     }
     ```
   - Start Logstash:
     ```bash
     sudo systemctl start logstash
     sudo systemctl enable logstash
     ```

3. **Configure Kibana:**
   - Access Kibana at `http://localhost:5601` and set up the index pattern to match `suricata-*`.
   - Create visualizations and dashboards to view alerts, such as pie charts of alert types, time-series graphs of alerts over time, and geo-maps of source IPs.

### **Step 6: Responding to Alerts**

- **Automated Responses:** Set up automated responses based on specific alerts, such as blocking IP addresses using firewall rules or sending notifications via email or Slack.
- **Monitoring and Fine-Tuning:** Regularly monitor the NIDS dashboard, review alerts, and fine-tune rules to reduce false positives and enhance detection accuracy.

---


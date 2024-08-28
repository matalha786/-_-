
### Step-by-Step Guide to Set Up a Network-Based Intrusion Detection System Using Snort

---

### **Step 1: Installation of Snort**

1. **Update Your System:**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Install Dependencies:**
   ```bash
   sudo apt install -y build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev
   ```

3. **Download and Install Snort:**
   - Download the latest Snort version from the [official website](https://www.snort.org/downloads).
   - Extract and install:
     ```bash
     tar -xvzf snort-<version>.tar.gz
     cd snort-<version>
     ./configure --enable-sourcefire
     make
     sudo make install
     ```

4. **Verify Installation:**
   ```bash
   snort -V
   ```

### **Step 2: Basic Configuration of Snort**

1. **Configure Network Interface:**
   - Identify the network interface you want to monitor:
     ```bash
     ifconfig  # or ip a
     ```
   - Edit `/etc/snort/snort.conf` and set the correct interface and home network:
     ```plaintext
     var HOME_NET any
     ```

2. **Set Up Directories for Snort:**
   ```bash
   sudo mkdir /etc/snort/rules
   sudo mkdir /var/log/snort
   sudo touch /etc/snort/rules/local.rules
   sudo touch /etc/snort/snort.conf
   ```

3. **Download and Add Rule Sets:**
   - Download community rules from [Snort’s website](https://www.snort.org/downloads/#rule-downloads).
   - Extract and copy the rules into `/etc/snort/rules/`.

### **Step 3: Configuring Rules and Alerts**

1. **Edit Snort Configuration File:**
   - Open `/etc/snort/snort.conf` and set up the basic settings, including paths to rule files:
     ```plaintext
     include $RULE_PATH/local.rules
     ```
   - Customize or add additional rule files as needed.

2. **Add Custom Rules:**
   - Edit `/etc/snort/rules/local.rules` to include specific detection rules.
   - Example rule to detect ping sweeps:
     ```plaintext
     alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Sweep Detected"; itype:8; sid:1000001; rev:1;)
     ```

3. **Run Snort in Test Mode:**
   ```bash
   sudo snort -T -c /etc/snort/snort.conf -i eth0
   ```

### **Step 4: Running Snort and Logging Alerts**

1. **Run Snort in NIDS Mode:**
   - Run Snort with logging enabled:
     ```bash
     sudo snort -c /etc/snort/snort.conf -i eth0 -A console
     ```
   - Alternatively, log to a file:
     ```bash
     sudo snort -c /etc/snort/snort.conf -i eth0 -l /var/log/snort/
     ```

2. **Generate Test Traffic:**
   - Generate traffic such as a ping sweep or an nmap scan to trigger the rules and verify Snort’s alerting.

### **Step 5: Visualizing Detected Attacks**

To visualize Snort alerts, you can use a variety of tools like **Snorby**, **Kibana**, or **BASE (Basic Analysis and Security Engine)**. Below is a guide to set up visualization with Kibana.

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

2. **Configure Logstash for Snort:**
   - Create a configuration file for Logstash (e.g., `/etc/logstash/conf.d/snort.conf`):
     ```plaintext
     input {
       file {
         path => "/var/log/snort/alert"
         start_position => "beginning"
         sincedb_path => "/dev/null"
       }
     }
     filter {
       grok {
         match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} \[%{DATA:classification}\] %{WORD:priority}: %{GREEDYDATA:description}" }
       }
       date {
         match => [ "timestamp", "MMM dd HH:mm:ss" ]
       }
     }
     output {
       elasticsearch {
         hosts => ["localhost:9200"]
         index => "snort-%{+YYYY.MM.dd}"
       }
       stdout { codec => rubydebug }
     }
     ```

   - **Start Logstash:**
     ```bash
     sudo systemctl start logstash
     sudo systemctl enable logstash
     ```

3. **Configure Kibana:**
   - Access Kibana at `http://localhost:5601` and set up the index pattern to match `snort-*`.
   - Create visualizations and dashboards to monitor alerts, such as time-series graphs, pie charts, and data tables showing detected threats.

### **Step 6: Responding to Detected Threats**

- **Automated Responses:** Set up response mechanisms such as blocking IPs via firewall rules or sending real-time alerts via email or messaging services.
- **Regular Monitoring:** Regularly monitor the dashboard, update rules, and refine configurations to enhance detection and reduce false positives.

---


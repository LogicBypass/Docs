# Self-Hosted Wazuh ELK IDS / IPS

[Visual Paradigm Online](https://online.visual-paradigm.com/w/wdpkjheg/diagrams/#diagram:workspace=wdpkjheg&proj=0&id=1)

- ****Wazuh single-node cluster****
    
    **Servername: 300(wazuh)**
    
    Cent OS LXC Privileged
    
    [https://documentation.wazuh.com/current/deployment-options/elastic-stack/distributed-deployment/wazuh-cluster/wazuh-single-node-cluster.html](https://documentation.wazuh.com/current/deployment-options/elastic-stack/distributed-deployment/wazuh-cluster/wazuh-single-node-cluster.html)
    
    ```bash
    cd /etc/yum.repos.d/
    sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
    yum update -y
    --
    yum install zip unzip curl openssh openssh-server bash-completion nano net-tools -y
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    
    cat > /etc/yum.repos.d/wazuh.repo << EOF
    [wazuh]
    gpgcheck=1
    gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
    enabled=1
    name=EL-\$releasever - Wazuh
    baseurl=https://packages.wazuh.com/4.x/yum/
    protect=1
    EOF
    
    yum install wazuh-manager
    
    systemctl status wazuh-manager
    
    ----Chech-----
    systemctl stop firewalld
    systemctl disable firewalld
    netstat -ltpnd
    
    1514
    1515
    55000
    ```
    
    - Install Filebeat (After ELK is configured)
        
        [https://documentation.wazuh.com/current/deployment-options/elastic-stack/distributed-deployment/wazuh-cluster/wazuh-single-node-cluster.html#installing-filebeat](https://documentation.wazuh.com/current/deployment-options/elastic-stack/distributed-deployment/wazuh-cluster/wazuh-single-node-cluster.html#installing-filebeat)
        
        ```bash
        [from site]
        rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
        
        cat > /etc/yum.repos.d/elastic.repo << EOF
        [elasticsearch-7.x]
        name=Elasticsearch repository for 7.x packages
        baseurl=https://artifacts.elastic.co/packages/7.x/yum
        gpgcheck=1
        gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
        enabled=1
        autorefresh=1
        type=rpm-md
        EOF
        
        yum install filebeat-7.17.6
        curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.3/tpl/elastic-basic/filebeat.yml
        ```
        
        ```bash
        [custom]
        #edit config file to disable https to elk
        nano /etc/filebeat/filebeat.yml
        
        output.elasticsearch.hosts: <elasticsearch_ip>:9200
        #output.elasticsearch.password: <elasticsearch_password>
        output.elasticsearch.protocol: http
        #output.elasticsearch.ssl.certificate: /etc/filebeat/certs/filebeat.crt
        #output.elasticsearch.ssl.key: /etc/filebeat/certs/filebeat.key
        #output.elasticsearch.ssl.certificate_authorities: /etc/filebeat/certs/ca/ca.crt
        #output.elasticsearch.ssl.verification_mode: strict
        #output.elasticsearch.username: elastic
        
        filebeat test output
        >>>
        elasticsearch: http://192.168.18.87:9200...
          parse url... OK
          connection...
            parse host... OK
            dns lookup... OK
            addresses: 192.168.18.87
            dial up... OK
          TLS... WARN secure connection disabled
          talk to server... OK
          version: 7.17.6
        >>>
        ```
        
        ```bash
        [from site]
        curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.3/extensions/elasticsearch/7.x/wazuh-template.json
        chmod go+r /etc/filebeat/wazuh-template.json
        
        curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.2.tar.gz | tar -xvz -C /usr/share/filebeat/module
        
        #skip all to 
        systemctl daemon-reload
        systemctl enable filebeat
        systemctl start filebeat
        systemctl status filebeat
        			>>>Connection to backoff(elasticsearch(http://192.168.18.87:9200)) established>>>
        ```
        
        [Now Install Kibana on [ELK] Stack](Self-Hosted%20Wazuh%20ELK%20IDS%20IPS%20fac1c11977a443b4871db4e58ef0c1f1.md)
        
        Set SSL connection
        
        ```bash
        output.elasticsearch.protocol: https
        ```
        
- **ELK**
    
    ****Wazuh with Elastic Stack basic license - All-in-one deployment****
    
    **Servername: 301(ELK)**
    
    up to 64Gb then another node
    
    Cent OS LXC Privileged [elkstack]
    
    [https://documentation.wazuh.com/current/deployment-options/elastic-stack/all-in-one-deployment/index.html](https://documentation.wazuh.com/current/deployment-options/elastic-stack/all-in-one-deployment/index.html)
    
    ```bash
    cd /etc/yum.repos.d/
    sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
    yum update -y
    --
    yum install zip unzip curl nano openssh openssh-server bash-completion net-tools -y
    
    rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
    
    cat > /etc/yum.repos.d/elastic.repo << EOF
    [elasticsearch-7.x]
    name=Elasticsearch repository for 7.x packages
    baseurl=https://artifacts.elastic.co/packages/7.x/yum
    gpgcheck=1
    gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
    enabled=1
    autorefresh=1
    type=rpm-md
    EOF
    
    yum install elasticsearch-7.17.6
    ```
    
    Configuration file
    
    We’ll modify our own default file for now
    
    ```bash
    nano /etc/elasticsearch/elasticsearch.yml
    
    cluster.name: wazuhcluster
    node.name: node-1
    bootstrap.memory_lock: true #Alocate static amount of memory
    network.host: 192.168.0.1   #IP of this server or loopback
    http.port: 9200
    cluster.initial_master_nodes: ["node-1"] #need to match node name and set which cluster are mains ["node-1", "node-2"]
    
    #alocate half of memory to elastic search 
    #check:
    free -mh
    #I have 6gb
    nano /etc/elasticsearch/jvm.options
    
    -Xms3g #3gb
    -Xmx3g #3gb
    
    nano /usr/lib/systemd/system/elasticsearch.service
    LimitMEMLOCK=infinity
    
    systemctl daemon-reload
    systemctl enable elasticsearch
    systemctl start elasticsearch
    systemctl status elasticsearch
    netstat -ltpnd
    ```
    
    - Additional to test
        
        1) **/etc/sysconfig/elasticsearch**
        
        On sysconfig: `/etc/sysconfig/elasticsearch` you should have:
        
        ```
        ES_JAVA_OPTS="-Xms4g -Xmx4g"
        MAX_LOCKED_MEMORY=unlimited
        
        ```
        
        (replace 4g with HALF your available RAM as recommended [here](https://www.elastic.co/guide/en/elasticsearch/guide/current/heap-sizing.html))
        
        2) **/etc/security/limits.conf**
        
        On security limits config: `/etc/security/limits.conf` you should have
        
        ```
        elasticsearch soft memlock unlimited
        elasticsearch hard memlock unlimited
        
        ```
        
        3) **/usr/lib/systemd/system/elasticsearch.service**
        
        On the service script: `/usr/lib/systemd/system/elasticsearch.service` you should uncomment:
        
        ```
        LimitMEMLOCK=infinity
        
        ```
        
        you should do `systemctl daemon-reload` after changing the service script
        
        4) **/etc/elasticsearch/elasticsearch.yml**
        
        On elasticsearch config finally: `/etc/elasticsearch/elasticsearch.yml` you should add:
        
        ```
        bootstrap.memory_lock: true
        
        ```
        
        Thats it, restart your node and the RAM will be locked, you should notice a major performance improvement.
        
    
    **[Return to Wazuh Manager and install Filebeat](Self-Hosted%20Wazuh%20ELK%20IDS%20IPS%20fac1c11977a443b4871db4e58ef0c1f1.md)**
    
    Set SSL
    
    ```bash
    cat > /usr/share/elasticsearch/instances.yml <<\EOF
    instances:
    - name: "elasticsearch"
      ip:
      - "10.0.0.2"      #our ip
    - name: "filebeat"
      ip:
      - "10.0.0.3"     #our ip
    - name: "wazuh-manager"
      ip:
      - "10.0.0.3"     #our ip
    - name: "kibana"
      ip:
      - "10.0.0.4"     #our ip
    EOF
    ```
    
    ```bash
    /usr/share/elasticsearch/bin/elasticsearch-certutil cert ca --pem --in instances.yml --keep-ca-key --out ~/certs.zip
    
    unzip ~/certs.zip -d ~/certs
    mkdir /etc/elasticsearch/certs/ca -p
    cp -R ~/certs/ca/ ~/certs/elasticsearch/* /etc/elasticsearch/certs/
    chown -R elasticsearch: /etc/elasticsearch/certs
    chmod -R 500 /etc/elasticsearch/certs
    chmod 400 /etc/elasticsearch/certs/ca/ca.* /etc/elasticsearch/certs/elasticsearch.*
    rm -rf ~/certs/
    ```
    
    from 
    `https://packages.wazuh.com/4.3/tpl/elastic-basic/elasticsearch_all_in_one.yml`
    
    ```bash
    nano /etc/elasticsearch/elasticsearch.yml
    
    # Transport layer
    xpack.security.transport.ssl.enabled: true
    xpack.security.transport.ssl.verification_mode: certificate
    xpack.security.transport.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
    xpack.security.transport.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt
    xpack.security.transport.ssl.certificate_authorities: /etc/elasticsearch/certs/ca/ca.crt
    
    # HTTP layer
    xpack.security.http.ssl.enabled: true
    xpack.security.http.ssl.verification_mode: certificate
    xpack.security.http.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
    xpack.security.http.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt
    xpack.security.http.ssl.certificate_authorities: /etc/elasticsearch/certs/ca/ca.crt
    
    # Elasticsearch authentication
    xpack.security.enabled: true
    
    systemctl daemon-reload
    systemctl restart elasticsearch
    ```
    
    [Edit filebeat settings](Self-Hosted%20Wazuh%20ELK%20IDS%20IPS%20fac1c11977a443b4871db4e58ef0c1f1.md)
    
    [Install certs Kibana](Self-Hosted%20Wazuh%20ELK%20IDS%20IPS%20fac1c11977a443b4871db4e58ef0c1f1.md)
    
    - Install Kibana
        
        [https://documentation.wazuh.com/current/deployment-options/elastic-stack/all-in-one-deployment/index.html#kibana-installation-and-configuration](https://documentation.wazuh.com/current/deployment-options/elastic-stack/all-in-one-deployment/index.html#kibana-installation-and-configuration)
        
        ```bash
        yum install kibana-7.17.6
        
        #skip certs
        
        curl -so /etc/kibana/kibana.yml https://packages.wazuh.com/4.3/tpl/elastic-basic/kibana_all_in_one.yml
        
        mkdir /usr/share/kibana/data
        chown -R kibana:kibana /usr/share/kibana
        
        cd /usr/share/kibana
        sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.3.9_7.17.6-1.zip
        #no sudo - yum install sudo #and repeat
        ```
        
        ```bash
        IP a #get the ip
        nano /etc/kibana/kibana.yml
        
        server.host: 192.168.18.87      #kibana host not from internet
        server.port: 8080     #will change to 443 when connect certs
        elasticsearch.hosts: http://192.168.18.87:9200       #it's on this host
        #elasticsearch.password: <elasticsearch_password> #not yet
        # Elasticsearch from/to Kibana
        
        #elasticsearch.ssl.certificateAuthorities: /etc/kibana/certs/ca/ca.crt
        #elasticsearch.ssl.certificate: /etc/kibana/certs/kibana.crt
        #elasticsearch.ssl.key: /etc/kibana/certs/kibana.key
        
        # Browser from/to Kibana
        #server.ssl.enabled: true
        #server.ssl.certificate: /etc/kibana/certs/kibana.crt
        #server.ssl.key: /etc/kibana/certs/kibana.key
        
        # Elasticsearch authentication
        #xpack.security.enabled: true
        #elasticsearch.username: elastic
        #uiSettings.overrides.defaultRoute: "/app/wazuh"
        #elasticsearch.ssl.verificationMode: certificate
        #telemetry.banner: false
        
        nano /usr/share/kibana/data/wazuh/config/wazuh.yml
        hosts:
          - default:
              url: http://localhost  #change to wazuh manager ip
              port: 55000
              username: wazuh-wui
              password: wazuh-wui
              run_as: false
        
        systemctl daemon-reload
        systemctl enable kibana
        systemctl start kibana
        systemctl status kibana
        ```
        
    
    set SSL for elasticsearch
    
    set SSL for Kibana
    
    ```bash
    unzip ~/certs.zip -d ~/certs
    rm -f ~/certs/ca/ca.key
    mkdir /etc/kibana/certs/ca -p
    cp ~/certs/ca/ca.crt /etc/kibana/certs/ca
    cp ~/certs/kibana/* /etc/kibana/certs/
    chown -R kibana: /etc/kibana/certs
    chmod -R 500 /etc/kibana/certs
    chmod 400 /etc/kibana/certs/ca/ca.* /etc/kibana/certs/kibana.*
    rm -rf ~/certs ~/certs.zip
    ```
    
    ```bash
    nano /etc/kibana/kibana.yml
    
    server.host: 192.168.18.87
    server.port: 8080
    elasticsearch.hosts: https://192.168.18.87:9200
    #elasticsearch.password: <elasticsearch_password>
    
    # Elasticsearch from/to Kibana
    
    elasticsearch.ssl.certificateAuthorities: /etc/kibana/certs/ca/ca.crt
    elasticsearch.ssl.certificate: /etc/kibana/certs/kibana.crt
    elasticsearch.ssl.key: /etc/kibana/certs/kibana.key
    
    # Browser from/to Kibana
    server.ssl.enabled: true
    server.ssl.certificate: /etc/kibana/certs/kibana.crt
    server.ssl.key: /etc/kibana/certs/kibana.key
    
    # Elasticsearch authentication
    xpack.security.enabled: true
    elasticsearch.username: elastic
    uiSettings.overrides.defaultRoute: "/app/wazuh"
    elasticsearch.ssl.verificationMode: certificate
    telemetry.banner: false
    ```
    

# ****Unattended installation****

[Unattended installation - Distributed deployment · Wazuh documentation](https://documentation.wazuh.com/4.2/installation-guide/open-distro/distributed-deployment/unattended/index.html)

```bash
cd /etc/yum.repos.d/
sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
yum update -y
yum install zip unzip curl nano openssh sudo tar openssh-server bash-completion net-tools -y
```

![Untitled](Self-Hosted%20Wazuh%20ELK%20IDS%20IPS%20fac1c11977a443b4871db4e58ef0c1f1/Untitled.png)

### ELK & Kibana

[Elasticsearch & Kibana unattended installation](https://documentation.wazuh.com/4.2/installation-guide/open-distro/distributed-deployment/unattended/unattended-elasticsearch-cluster-installation.html)

```bash
curl -so ~/elastic-stack-installation.sh https://packages.wazuh.com/resources/4.2/open-distro/unattended-installation/distributed/elastic-stack-installation.sh
curl -so ~/config.yml https://packages.wazuh.com/resources/4.2/open-distro/unattended-installation/distributed/templates/config.yml
```

### Install ElasticSearch

```bash
nano config.yml

>>>>>
## Single-node configuration

## Elasticsearch configuration

**network.host: <elasticsearch_ip>**

# Clients certificates
clients:
  - name: admin
    dn: CN=admin,OU=Docu,O=Wazuh,L=California,C=US
    admin: true
  - name: filebeat
    dn: CN=filebeat,OU=Docu,O=Wazuh,L=California,C=US

# Kibana-instance
**- <kibana_ip>**

# Wazuh-master-configuration
**- <wazuh_master_server_IP>
>>>>**
```

```bash
bash ~/elastic-stack-installation.sh -e -n elasticsearch-1
```

### Install Kibana

```bash
bash ~/elastic-stack-installation.sh -k -n <same_node_name_as_previous>

Check for connection
```

Change Password:

```bash
curl -so wazuh-passwords-tool.sh https://packages.wazuh.com/resources/4.2/open-distro/tools/wazuh-passwords-tool.sh
bash wazuh-passwords-tool.sh -u admin -p mynewpassword
```

Copy certs to wazuh

```bash
scp certs.tar root@ip:/root/
```

Perform wazuh+filebeat install

### Wazuh + Filebeat

[Wazuh server unattended installation - Unattended installation](https://documentation.wazuh.com/4.2/installation-guide/open-distro/distributed-deployment/unattended/unattended-wazuh-cluster-installation.html)

**********Be sure that you copied certs**********

```bash
curl -so ~/wazuh-server-installation.sh https://packages.wazuh.com/resources/4.2/open-distro/unattended-installation/distributed/wazuh-server-installation.sh
bash ~/wazuh-server-installation.sh -n <any_node_name>
cd /etc/filebeat/certs/
tar -xvf certs.tar
nano /etc/filebeat/filebeat.yml
	#insert a changed password for elk 

filebeat test output
systemctl status wazuh-manager
```

- Connect a wazuh agent
    - Linux
        
        Install Agent
        
        [https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html)
        
        ```bash
        yum install wazuh-agent  #without address registration
        
        nano /var/ossec/etc/ossec.conf
            #Here we can find and add log files to be sent to Wazuh MANAGER
          
            
            Add Manager IP
        
        systemctl daemon-reload
        systemctl enable wazuh-agent
        systemctl start wazuh-agent
        
        tail /var/log/messages
        tail /var/ossec/logs/ossec.log
        
        [Go to **Wazuh Manager Server** and check for connection>>>](Self-Hosted%20Wazuh%20ELK%20IDS%20IPS%20fac1c11977a443b4871db4e58ef0c1f1.md)
        ```
        
    - Windows
        
        Install the agent then goto (Wazuh Manager) machine and generate key
        
        ```bash
        (Wazuh Manager)
        
        /var/ossec/bin/manage_agents
        
        A
        #Add Name
        #IP - any
        #y
        
        E
        #ID of the recently added machine
        #Copy the key to the Windows machine
        
        Check for connection (Wazuh Manager)
        /var/ossec/bin/manage_agents -l
        /var/ossec/bin/agent_control -lc #-h for help
        ```
        
        It’s also run as a Windows service
        
- Check for connection (Wazuh Manager)
    
    ```bash
    (Wazuh Manager)
    cd /var/ossec/bin/ #Wazuh debugging scripts folder
    ./manage_agents -l
    
    OR 
    
    /var/ossec/bin/manage_agents -l
    
    Available agents: 
       ID: 001, Name: wazuh-agent, IP: any
        #IP: any is good for migration 
    
    #check for messages that's coming from machines and if it's working
    tail -f /var/ossec/logs/alerts/alerts.json
    #try to fail logins to agent machines, they need to appear into logs
    
    ```
    
- VirusTotal integration
    
    ```bash
    [Wazuh-Manager]
    nano /var/ossec/etc/ossec.conf
    
    <integration>
      <name>virustotal</name>
      <api_key>API_KEY</api_key> <!-- Replace with your VirusTotal API key -->
      <group>syscheck</group>
      <alert_format>json</alert_format>
    </integration>
    
    #to not populate the virustotal change <**syscheck>** with <rule.id> of  "file added to the system" and it will check just new files
    #or can create a rule for checking just *.exe and use this rule.id 
    
    <integration>
      <name>virustotal</name>
      <api_key>API_KEY</api_key> <!-- Replace with your VirusTotal API key -->
      <group>**554**</group>
      <alert_format>json</alert_format>
    </integration>
    ```
    
    View the integrations logs
    
    ```bash
    
    tail -f /var/ossec/logs/integrations.log
    #on server add a infected file and we'll see an API call in log
    ```
    
- SysMon integration
    
    [**Download Sysmon**](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
    
    - **Download config file:**
        
        [https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml](https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml)
        
        OR
        
        [https://github.com/olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)
        
    - **Sysmon Install**:
        
        ```powershell
        [PC]
        cd "to sysmon64.exe dir"
        
        .\Sysmon64.exe -accepteula -i C:\Users\sysmonconfig.xml
        ```
        
        Check
        
        Open “Event Viewer” `> Applications.. > Microsoft > Windows > Sysmon > Operational`
        
        Need to see events
        
    - **Edit the Wazuh agent  file**
        
        From the ELK:
        
        ELK > Wazuh > management > groups
        
        ![Untitled](Self-Hosted%20Wazuh%20ELK%20IDS%20IPS%20fac1c11977a443b4871db4e58ef0c1f1/Untitled%201.png)
        
        ```xml
        <agent_config>
        	<!-- Shared agent configuration here -->
        	<localfile>
                <location>Microsoft-Windows-Sysmon/Operational</location>
                <log_format>eventchannel</log_format>
            </localfile>
        </agent_config>
        ```
        
        Inside the Windows Wazuh config:
        
        Open “wazuh manager” > edit config
        
        ```xml
        --add this--
        <localfile>
            <location>Microsoft-Windows-Sysmon/Operational</location>
            <log_format>eventchannel</log_format>
        </localfile>
        --
        ```
        
    - **Implement Wazuh rules**
        
        ELK> Wazuh > Management > Rules > Sysmon - turn on one by one
        
        OR
        
        ELK> Wazuh > Management > Rules > Manage rules > Custom rules > Add new rules file
        
        Name: sysmon.xml
        
        Content: insert from: [https://github.com/OpenSecureCo/Wazuh/blob/main/sysmon.xml](https://github.com/OpenSecureCo/Wazuh/blob/main/sysmon.xml)
        
    
- Add Ip to Geomap
    
    SSH into a server with “filebeat” usually “wazuh manager”
    
    `nano /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json`
    
    copy and edit one geoip and careful with the punctuation
    
    ```xml
        {
          "geoip": {
            "field": "data.win.eventdata.ipAddress",
            "target_field": "GeoLocation",
            "properties": ["city_name", "country_name", "region_name", "location"],
            "ignore_missing": true,
            "ignore_failure": true
          }
        },
    
    #i want to change it to 
    data.win.eventdata.destinationIp
    #and one more for
    data.win.eventdata.sourceIp
    ```
    
    `nano /etc/filebeat/filebeat.yml`
    
    ```xml
    filebeat.overwrite_pipelines: true
    setup.template.overwrite: true
    ```
    
    `systemctl restart filebeat`
    

### Useful Folders:

- Wazuh-Host
    - Linux
        - `/var/ossec/` - Logs, Configs, Active-Responses
        - `/var/ossec/etc/ossec.conf` - Config file (server, local logs location)
        - 
- Wazuh-Manager Filebeat
    - Wazuh
        - `/var/ossec/bin` - scripts for managing or debug
        - `/var/ossec/ruleset` - Decoders, Rules
        - `/var/ossec/logs` - Logs
            - `/var/ossec/logs/alerts/alerts.json` - Alerts
    - Filebeat
        - `/etc/filebeat/filebeat.yml` - Filebeat config
        - `/usr/share/filebeat/module/` - Modules
        - `/usr/share/filebeat/module/wazuh/alerts/manifest.yml` - Where to forward the **alerts.json**
- Elastic Kibana
    - Elastic
        - `/var/lib/elasticsearch/` - store data
        - `/var/log/elasticsearch/` - store debuging logs
        - `/etc/elasticsearch/elasticsearch.yml` - config file
    - Kibana
        - `/etc/kibana/kibana.yml` - Kibana config file
        - `/usr/share/kibana/data/wazuh/config/wazuh.yml` - Kibana wazuh connection
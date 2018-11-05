import paramiko, socket, os, boto3, json, requests,base64,pysnow,logging,inspect,warnings,substring,sys
from paramiko import SSHException
from BeautifulSoup import BeautifulSoup
from base64 import b64decode
from requests.auth import HTTPBasicAuth


def Credentials():
    try:
        ENCRYPTED = os.environ['ssurl']
        ssurl = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED))['Plaintext']
        ENCRYPTED = os.environ['ssgetsec']
        ssgetsec = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED))['Plaintext']
        ENCRYPTED = os.environ['suser']
        suser = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED))['Plaintext']
        ENCRYPTED = os.environ['spass']
        spass = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED))['Plaintext']
        ENCRYPTED = os.environ['Snowinstance']
        Snowinstance = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED))['Plaintext']
        ENCRYPTED = os.environ['sid']
        sid = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED))['Plaintext']
        ENCRYPTED = os.environ['snsid']
        snsid = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED))['Plaintext']
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        creds = {
            "username": suser,
            "password": spass,
            "organization": "",
            "domain": "ads"
        }
        
        resp = requests.post(ssurl, data=creds, headers=headers, verify=False)
        sresp = resp.content
        Soup = BeautifulSoup
        soup = Soup(sresp)
        token = soup.find('token').string
        secret = {
            "secretId": sid,
            "token": token
        }
        s = requests.post(ssgetsec, data=secret, headers=headers, verify=False)
        strs = s.content
        soup = Soup(strs)
        username = soup.findAll("value")
        i = 0
        for user in username:
            if i == 0:
                i = i + 1
            elif i <= 2:
                strval = user.string
                if "svc" in strval:
                    cuser = strval
                else:
                    cpwd = strval
                i = i + 1
        snowresp = requests.post(ssurl, data=creds, headers=headers, verify=False)
        ssnowresp = snowresp.content
        Soup1 = BeautifulSoup
        soup1 = Soup1(ssnowresp)
        snowtoken = soup1.find('token').string
        snowsecret = {
            "secretId": snsid,
            "token": snowtoken
        }
        snowurl = requests.post(ssgetsec, data=snowsecret, headers=headers, verify=False)
        strsnowurl = snowurl.content
        soup1 = Soup(strsnowurl)
        SnowUsername = soup1.findAll("value")
        i = 0
        for u in SnowUsername:
            if i == 0:
                i = i + 1
            elif i <= 2:
                SnowString = u.string
                if "svc" in SnowString:
                    snowuser = SnowString
                else:
                    snowpwd = SnowString
                i = i + 1
        
        return cuser,cpwd,snowuser,snowpwd,Snowinstance
        
    except Exception as e:
        logging.warning("Warning at Credentials()...!" + str(e))



def SSHSession(IpAddress):
    cuser,cpwd,snowuser,snowpwd,Snowinstance =  Credentials()
    try:
        LinuxInstance = paramiko.SSHClient()
        LinuxInstance.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        LinuxInstance.connect(hostname = IpAddress, username = cuser, password = cpwd)
        return LinuxInstance
        LinuxInstance.close()
    except paramiko.ssh_exception.NoValidConnectionsError:
        print "IP does not belong to linux"
        print "Message: Bot execution failed"
    except paramiko.ssh_exception.AuthenticationException:
        print "Authentication Error! Invalid username/password..."
        print "Message: Bot execution failed"
    except paramiko.ssh_exception.SSHException:
        print "Unable to SSH! ..."
        print "Message: Unable to initiate SSH"


def MainMethod(IpAddress, cmd ):
    '''   Status of the Method is to get the top five process names   '''
    try:
        stdin, stdout, stderr = SSHSession(IpAddress).exec_command(cmd)
        Output = stdout.read().decode('ascii').strip("\n")
        return Output
    except AttributeError:
        print "Unable to execute commands..!"
        print "Message: Bot execution failed"
    except SSHException:
        print "SSH session is not active..!"
        print "Message: Bot execution failed"
           
def lambda_handler(event, context):
    '''Method to run commands'''
    cuser,cpwd,snowuser,snowpwd,Snowinstance = Credentials()
    print event

    for alert in (event.get("incident")).get("alerts"):
        for tag in (alert.get("tags")):
            if tag.get("name") == "ip":
               EventIpAddress = tag.get("value").encode("utf-8")
               print "The ip is:", EventIpAddress

    for alert in (event.get("incident")).get("alerts"):
        for tag in (alert.get("tags")):
            if tag.get("name") == "host":
               HostName = tag.get("value").encode("utf-8")
               print "The hostname is:", HostName

    for alert in (event.get("incident")).get("alerts"):
        for tag in (alert.get("tags")):
            if tag.get("name") == "short_description":
               ShortDescription = tag.get("value").encode("utf-8")
               print "The description is:", ShortDescription
               
    for alert in (event.get("incident")).get("alerts"):
        for tag in (alert.get("tags")):
            if tag.get("name") == "u_collector":
               collectorName = tag.get("value").encode("utf-8")
               print("The collector name is:", collectorName)


    if (event.get("incident")["changedOn"]) == (event.get("incident")["startedOn"]):
        SnowSysId = event.get("shareResults").get("servicenowSysId")
        print "The sysid is:", SnowSysId
        
        
    else:
        for result in (((event.get("shareResults")).get("result"))):
            SnowSysId = (result).get("sys_id").encode("utf-8")
            print "The sysid is:",SnowSysId
            
    Disk = []; File = [];WorkState = [];CollectorOutput = [];SNMP = []; ReadOnlyStatusInfo = [] ;TroubleshootSteps = []; colIP = []

    '''   Status of the Method is to get the Linux Version   '''
    LinuxVersion = MainMethod(EventIpAddress, "cat /etc/redhat-release")
    
    SNMP_State = MainMethod(EventIpAddress, "ps -e | grep snmp")
    if "snmpd" in SNMP_State:
        SnmpStatus = "SNMP Service Running"
        SNMP.append(SnmpStatus)
        print SNMP
    else:
        SnmpStatus = "SNMP Service not running"
        SNMP.append(SnmpStatus)
        print SNMP
        if "Red Hat Enterprise Linux Server release 7.5" in LinuxVersion:
            stdin, stdout, stderr = SSHSession(EventIpAddress).exec_command("sudo /bin/systemctl restart snmpd")
            restart = stdout.readlines()
            print "SNMP start status:", restart
            stdin, stdout, stderr = SSHSession(EventIpAddress).exec_command("sudo /bin/systemctl status snmpd")
            lines  = stdout.readlines()
            for i in lines:
                if " active (running)" in i:
                    print "SNMP started successfully"
        else:
            stdin, stdout, stderr = SSHSession(EventIpAddress).exec_command("sudo /sbin/service snmpd restart")
            restart = stdout.readlines()
            print "SNMP start status:", restart
            stdin, stdout, stderr = SSHSession(IpAddress).exec_command("sudo /sbin/service snmpd status")
            lines  = stdout.readlines()
            for i in lines:
                if " active (running)" in i:
                    print "SNMP started successfully"
                    
    nslookup = MainMethod(EventIpAddress, "nslookup " + collectorName)
    for line in nslookup.splitlines():
        if "Address" in line:
            colIP.append(line)
            print(colIP)
    IP = (colIP[1]).split()
    ColIPToConnect = IP[1]
    print "The IP of the collector is:", ColIPToConnect
    

    
    SNMP_Result = MainMethod(EventIpAddress, "/bin/snmpwalk -v3  -l authPriv -u zenoss -a SHA -A 2oN6aKWriVgKL6aBPIoX -x AES -X 9NuRRr4V2OTUqB8TKjMQ localhost:161 sysName.0;echo $?")
    
    try:
        if "0" in SNMP_Result:
        
            WorkingState = "SNMP working successfully"
            WorkState.append(WorkingState)
            
            LogicCollectorOutput  = MainMethod(ColIPToConnect, "/bin/snmpwalk -v3  -l authPriv -u zenoss -a SHA -A 2oN6aKWriVgKL6aBPIoX -x AES -X 9NuRRr4V2OTUqB8TKjMQ localhost:161 sysName.0;echo $?")
            print LogicCollectorOutput
            if "0" in LogicCollectorOutput:
                LogicCollectorState = "SNMP working successfully on" +  ColIPToConnect
                CollectorOutput.append(LogicCollectorState)
                connect_to_snow = pysnow.Client(instance = Snowinstance, user = snowuser, password = snowpwd)
                incident = connect_to_snow.resource(api_path='/table/incident')
                response = incident.get(query={'sys_id': SnowSysId})
                update = response.update({'comments': "SNMP working successfully both on client and collector, hence resolving the ticket"})
                update = response.update({'assignment_group': 'DES Unix Operations'})
                update = response.update({'assigned_to': 'Autobots'})
                update = response.update({'incident_state': 'Resolved'})
                update = response.update({'assigned_to': 'Autobots'})
                if True:
                    print "Update on SNOW successful!"
                    print "Message: Bot executed successfully"
                else:
                    print "Update on SNOW not succesful!"
                    print "Message: Bot execution failed"
                sys.exit()
            else:
                LogicCollectorState = "SNMP error on " + ColIPToConnect
                CollectorOutput.append(LogicCollectorState)
        else:
            WorkingState = "SNMP Error!!"
            WorkState.append(WorkingState)
    except Exception as e:
        print e
        
    Steps = """'For, RHEL 5
                    GO TO 
                    /var/net-snmp/
                    grep -i usmUser /var/net-snmp/snmpd.conf
                    if,above command output is empty perform the below:
                    cd /var/net-snmp/.puppet
                    rm db.*
                    run puppet agent -t
                    if the issue is still not fixed, please check if iptables rule is blocking the snmp or not
                     
                    For, RHEL 6 and RHEL 7
                    /var/lib/net-snmp
                    grep -i usmUser snmpd.conf
                    If,above command output is empty perform the below:
                    cd /var/lib/net-snmp/.puppet
                    rm db.*
                    run puppet agent -t
                    if the issue is still not fixed, please check if iptables rule is blocking the snmp or not'"""
    TroubleshootSteps.append(Steps)
        
    
        
    '''   Status of the UDP port   '''
    UDPCheck = MainMethod(EventIpAddress,"netstat -anp | grep 161")
    UDPStatus = "The status for " + EventIpAddress + " on port 161 is: " + '\r\n' +  UDPCheck


    '''*********************HEALTHCHECK**********************'''

    RoutingTable = MainMethod(EventIpAddress, "netstat -r")
    TcpConnection = MainMethod(EventIpAddress, "netstat -t --listening")
    stdin, stdout, stderr = SSHSession(EventIpAddress).exec_command("awk '$4 ~ " + "^ro" + "&& $3 !~ " + "(squashfs|iso9660|nfs|cifs|tmpfs|sysfs)" + "{print $0}' /proc/mounts")
    ReadOnlylines  = stdout.readlines()
    if ReadOnlylines == []:
        ReadOnlyStatus = "No read-only file information"
        ReadOnlyStatusInfo.append(ReadOnlyStatus)
    else:
        ReadOnlyStatusInfo.append(FileInfo)
        
    DiskInfo = MainMethod(EventIpAddress, "df -H")
    ZombieProcessList = MainMethod(EventIpAddress, 'ps aux | grep Z | grep -vE "grep|ps aux"' )
    InodeInfo = MainMethod(EventIpAddress, "df -i")
    MemInfo = MainMethod(EventIpAddress, "free -m")
    SwapInfo = MainMethod(EventIpAddress, "/sbin/swapon  --summary")
    RebootInfo = MainMethod(EventIpAddress, "last reboot | head -3")
    ShutdownInfo = MainMethod(EventIpAddress, "last -x | grep shutdown | head -3")
    CpuInfo = MainMethod(EventIpAddress, "ps -eo pcpu,pid,user,args | sort -k 1 -r | head -6")
    MemInfo = MainMethod(EventIpAddress, "ps aux --sort -rss | head -n 6")

    '''Comments to be printed'''
    LinuxVer = "The linux version is : " + LinuxVersion
    SnmpServiceInfo = "The SNMP service information is: " + '\r\n' + ("\n".join(SNMP))
    SnmpSuccessInfo = "The SNMP run state is: " + '\r\n' +  ("\n".join(WorkState))
    CollectorRunInfo = "The SNMP run state on " + ColIPToConnect + " is:" + '\r\n' + ("\n".join(CollectorOutput))
    Troubleshoot = "SNMP Error, execute the steps given below: " + '\r\n' + ("\n".join(TroubleshootSteps))
    RoutingTableInfo = "The routing table information is:" + '\r\n' +  RoutingTable
    TcpConnectionInfo = "The active tcp connections are :" + '\r\n' +  TcpConnection
    FileInformation = "The read-only file information is:" + '\r\n' + ("\n".join(ReadOnlyStatusInfo))
    DiskInformation = "The disk information is:" + '\r\n' +  DiskInfo
    ZombieInformation = "The zombie process information is:" + '\r\n' + ZombieProcessList
    InodeInforation = "The inode information is :" + '\r\n' +  InodeInfo
    MemoryInformation = "The memory information is :" + '\r\n' +  MemInfo
    SwapInformation = "The swap information is :" + '\r\n' +  SwapInfo
    RebootInformation = "The last reboot information is :" + '\r\n' +  RebootInfo
    ShutdownInformation = "The shutdown information is :" + '\r\n' +  ShutdownInfo
    Top5Cpu =  "The top 5 processes consuming memory is :" + '\r\n' +  CpuInfo

    comments = LinuxVer + '\r\n'*2 + SnmpServiceInfo + '\r\n'*2 + SnmpSuccessInfo + '\r\n'*2 + CollectorRunInfo + '\r\n'*2 + Troubleshoot + '\r\n'*2 + UDPStatus  + '\r\n'*4 + "HEALTHCHECK" + '\r\n'*2 + RoutingTableInfo + '\r\n'*2 + TcpConnectionInfo + '\r\n'*2 +  FileInformation + '\r\n'*2  +  DiskInformation + '\r\n'*2 +  ZombieInformation + '\r\n'*2 +InodeInforation + '\r\n'*2 + MemoryInformation + '\r\n'*2 + SwapInformation + '\r\n'*2 + RebootInformation + '\r\n'*2 +  ShutdownInformation + '\r\n'*2 + Top5Cpu
    print comments


    
    connect_to_snow = pysnow.Client(instance = Snowinstance, user = snowuser, password = snowpwd)
    incident = connect_to_snow.resource(api_path='/table/incident')
    response = incident.get(query={'sys_id': SnowSysId})
    update = response.update({'comments': comments})
    update = response.update({'assignment_group': 'DES Unix Operations'})
    update = response.update({'assigned_to': 'Autobots'})
    update = response.update({'incident_state': 'Awaiting Assignment'})
    update = response.update({'assigned_to': 'Open'})
    if True:
        print "Update on SNOW successful!"
        print "Message: Bot executed successfully"
    else:
        print "Update on SNOW not succesful!"
        print "Message: Bot execution failed"
   
    


        

        




        






















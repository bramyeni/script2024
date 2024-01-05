#!/bin/env python3
import sys
import os
import json
import re
import jmespath
import subprocess
import socket
import argparse
try:
    from azure.cli.core import get_default_cli
except (ImportError,ModuleNotFoundError):
    print("Missing dependency azure.cli, use pip install azure.cli")
    sys.exit(2)

PLATFORM=sys.platform

LOCATION="australiaeast"
RESOURCEGROUP="RG-EMEA-Brampahlawanto-DBeam"
DNSSERVER="192.168.0.153"

if (PLATFORM=="win32"):
    try:
        import dns.resolver
    except (ImportError,ModuleNotFoundError):
         print("Missing dependency dns.resolver, use pip install dnspython")
         sys.exit(2)

    tempdir="c:\\users\\public\\"
    rsclist=tempdir+"allrsclist.out"
    SHELL=True
else:
    tempdir="/tmp/"
    rsclist=tempdir+'allrsclist.out'
    SHELL=False

def install_extension(extensions):
    data=run_azcli("extension list")
    for extension in extensions:
        azext=jmespath.search("[?contains(name,'"+extension+"')].{name:name}",data)
        if (azext==[] or azext==None):
            print("installing extension "+extension)
            out=run_azcli("extension add --name "+extension)
            if (out!=None):
               print("Error in installing extension "+extension)
               sys.exit()
        else:
            print("Extension "+azext[0]['name']+" has been installed")


def run_az(argsstr):
   args=("az "+argsstr).split() 
   process = subprocess.Popen(args, stdout=subprocess.PIPE, shell=SHELL)
   out, err = process.communicate()
   if (err==None):
      return(err)
   else:
      return(json.loads(out))

def run_azcli(argsstr):
   global azcli
   args=argsstr.split() 
   azcli=get_default_cli()
   fout=open(rsclist,'w')
   code=azcli.invoke(args,None,fout)
   fout.close()
   if azcli.result.result:
      return(azcli.result.result)
   else:
      return(azcli.result.error)

def print_value(pkey,obj,keysearch,valsearch):
    if (keysearch!=None):
       if (re.findall(keysearch,pkey)!=[]):
          if (valsearch!=None):
             if (re.findall(valsearch,obj)!=[]):
                print(pkey+" = "+obj)
          else:
             print(pkey+" = "+obj)
    elif (valsearch!=None):
       if (re.findall(valsearch,obj)!=[]):
          print(pkey+" = "+obj)
    else:
       print(pkey+" = "+obj)

def print_key_val(pkey,obj,keysearch=None,valsearch=None):
    if (isinstance(obj,list)):
       for proplist in obj:
           print_key_val(pkey+" [ ",proplist,keysearch,valsearch)
    elif isinstance(obj,str):
       print_value(pkey,obj,keysearch,valsearch)
    elif (isinstance(obj,dict)):
       for key,value in obj.items():
           if (keysearch!=None):
              if (re.findall(keysearch,key)!=[]):
                 print_key_val(pkey+" -> "+key,value,keysearch,valsearch)
           else:
              print_key_val(pkey+" -> "+key,value,keysearch,valsearch)
    elif (obj==None):
       if (keysearch==None and valsearch==None):
          print(pkey+" = None")
    elif (isinstance(obj,int)):
       print_value(pkey,str(obj),keysearch,valsearch)
    elif (isinstance(obj,float)):
       print_value(pkey,str(obj),keysearch,valsearch)
    else:
       print_value(pkey,obj,keysearch,valsearch)

def check_output(output,skip=0):
    if (output==[] or output=="" or output==None):
        print("No output..")
        if (skip==0):
           sys.exit()
        else:
           return(1)
    else:
        return(0)

def check_port(host,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)                                      #2 Second Timeout
    result = sock.connect_ex((host,port))
    if (result==0):
       return(0)
    else:
       print('Port '+str(port)+' returned: '+str(result))
       return(1)


msg = "Parameter descriptions"
parser = argparse.ArgumentParser(description = msg)
parser.add_argument("-d","--dns-server",help="On-premises DNS Server")
parser.add_argument("-g","--resource-group", help="Azure Resource Group")
parser.add_argument("-l","--location",help = "Azure Location",default="australiaeast")
parser.parse_args()
args = parser.parse_args()

if args.dns_server: DNSSERVER=args.dns_server;DNSMSG=DNSSERVER
else: DNSSERVER="";DNSMSG="Current"
if args.resource_group: RESOURCEGROUP=args.resource_group
else: RESOURCEGROUP="";print("Resource group must be specified");sys.exit()
if args.location: LOCATION=args.location

print("Using Azure Resource Group : "+RESOURCEGROUP)
print("Using Azure Location       : "+LOCATION)
print("Using DNS Server           : "+DNSMSG)

extensions=['dns-resolver','offazure']
install_extension(extensions)

maindata=run_azcli("resource list -g "+RESOURCEGROUP)
data=maindata
azmig=jmespath.search("[?contains(id,'migrate')&&contains(type,'Microsoft.Migrate/migrateprojects')&&provisioningState=='Succeeded'].{id:id,name:name}",data)
check_output(azmig)

azmigid=azmig[0]['id']
azmigname=azmig[0]['name']
print("\nAzure Migrate Information :\n")
print("Azure Migrate name    : %s" % azmigname)
print("Azure Migrate id      : %s" % azmigid)

data=run_azcli("resource show -g "+RESOURCEGROUP+" --ids "+azmigid)
azprivepconn=jmespath.search("properties.privateEndpointConnections[].{id:id}",data)
check_output(azprivepconn)

print("\nAzure Private connection and endpoint Information :\n")

print("Azure Private Conn ID : %s" % azprivepconn[0]['id'])

azprivepid=jmespath.search("properties.privateEndpointConnections[].properties.privateEndpoint.id",data)
check_output(azprivepid)

print("Private endpoint ID   : %s" % azprivepid[0])
data=run_azcli("resource show -g "+RESOURCEGROUP+" --ids "+azprivepid[0])
subnetid=jmespath.search("properties.subnet.id",data)
check_output(subnetid)
print("Private SUBNET ID     : %s" % subnetid)

data=run_azcli("resource show -g "+RESOURCEGROUP+" --ids "+subnetid)
addpref=jmespath.search("properties.addressPrefix",data)
check_output(addpref)

print("Address Prefix        : %s" % addpref)
print("\nList of all Private link Zones : ")
data=maindata
privdnsall=jmespath.search("[?contains(id,'privateDnsZones')&&(contains(id,'sitereco')||contains(id,'migration')||contains(id,'vaultcore')||contains(id,'blob'))&&!contains(id,'virtualNetworkLinks')].{id:id,name:name}",data)
check_output(privdnsall)

allentries=[]
for privdns in privdnsall:
    print("- %s" % privdns['name'])
    print("  %s" % privdns['id'])
    TMPFILE=tempdir+privdns['name']+".tmp"
    out=run_az("network private-dns zone export --name "+privdns['name']+" -g "+RESOURCEGROUP+" -o none -f "+TMPFILE)
    flines=open(TMPFILE,'rt')
    for fline in flines:
        out=re.findall('.*IN A.*',fline)
        if (out!=[] and out!=""):
            allentries.append(out[0]+" "+privdns['name'])
    if flines: flines.close()

print("\nThe following is the list of private domain name and its IP address")

if (os.getenv('AZUREPS_HOST_ENVIRONMENT')==None):
    import dns.resolver
    res = dns.resolver.Resolver()
    if (DNSSERVER!=""):
       res.nameservers = [ DNSSERVER ]
    else:
       DNSSERVER=res.nameservers[0]
    CSHELL=0
else:
    CSHELL=1
    dnsfromfile=open('/etc/resolv.conf','rt')
    dnsline=re.findall('(?<=nameserver ).*',dnsfromfile.read())
    if (dnsline!=[]): DNSSERVER=dnsline[0]
    dnsfromfile.close()


for dnsentry in allentries:
    domainname=dnsentry.split()[0]+"."+dnsentry.split()[-1]
    ipaddr=dnsentry.split()[-2]
    try:
        if (CSHELL==1):    
           realaddr=socket.gethostbyname(domainname)
        else:
           r = res.resolve(domainname,"A")
           if (r!=[]):
              realaddr=r[0]
        print("%-100s %s => %s (DNS=%s)" % (domainname,ipaddr,realaddr,DNSSERVER))
    except Exception as e:
        print("%-100s %s => %s (DNS=%s)" % (domainname,ipaddr,'None',DNSSERVER))
        print(e)

       
print("\nNOTE: \n- A => B must match, otherwise dns resolver or conditional forwarder setup was wrong")
print("- run nslookup, the result must also match the above aaddresses")
print("- Ensure DNS on premise can forward DNS query to DNS private resolver on Azure:")
print("\nE.g: nslookup "+domainname+" should resolve "+ipaddr)

privnetlnkall=jmespath.search("[?contains(id,'privateDnsZones')&&(contains(id,'sitereco')||contains(id,'migration')||contains(id,'vaultcore')||contains(id,'blob'))&&contains(id,'virtualNetworkLinks')].{id:id,name:name}",data)
check_output(privnetlnkall)
print("\nList of all Private Virtual Net links : ")
for privnetlnk in privnetlnkall:
    print("- %s" % privnetlnk['name'])
    print("  %s" % privnetlnk['id'])

data=maindata
dnsresolver=jmespath.search("[?contains(id,'resolver')&&!contains(id,'inbound')&&!contains(id,'outbound')].{id:id,name:name}",data)
check_output(dnsresolver)

inbound=jmespath.search("[?contains(id,'resolver')&&contains(id,'inbound')].{id:id,name:name}",data)
check_output(inbound)


print("\nDNS Private Resolver information :")
print("ID                    : %s" % dnsresolver[0]['id'])
print("Name                  : %s" % dnsresolver[0]['name'])

data=run_azcli("resource show -g "+RESOURCEGROUP+" --ids "+inbound[0]['id'])
inboundinfo=jmespath.search("properties.ipConfigurations[].{subnetid:subnet.id,IpAddr:privateIpAddress}",data)
check_output(inboundinfo)
inboundinfox=jmespath.search("{id:id}",data)
check_output(inboundinfox)

print("\nDNS Private Resolver Inbound Information : (DNS Query from on-premises to Azure) ")

print("Inbound ID            : %s" % inboundinfox['id'])
print("Inbound Subnet        : %s" % inboundinfo[0]['subnetid'])
print("Inbound IP Address    : %s" % inboundinfo[0]['IpAddr'])

print("NOTE: All private link Zones (listed above) must be registered into conditional forwarders in on-premise DNS server\nit must be pointed to the IP address : %s\n" % inboundinfo[0]['IpAddr'])

print("Checking DNS server "+inboundinfo[0]['IpAddr']+" on Port 53")
ret=check_port(inboundinfo[0]['IpAddr'],53)

if (ret==0):
   print("DNS server is running...") 
else:
   print("NOTE: DNS Private resolver must be contactable from On-premise DNS through port 53")
   print("This will allow all domains listed under conditional forwarders are redirected to DNS private resolver on IP: "+inboundinfo[0]['IpAddr'])

data=maindata
outbound=jmespath.search("[?contains(id,'resolver')&&contains(id,'outbound')].{id:id,name:name}",data)
check_output(outbound)

data=run_azcli("resource show -g "+RESOURCEGROUP+" --ids "+outbound[0]['id'])
outboundinfo=jmespath.search("{id:id,subnetid:properties.subnet.id}",data)
check_output(outboundinfo)

print("Outbound ID           : %s" % outboundinfo['id'])
print("Outound Subnet        : %s" % outboundinfo['subnetid'])


data=maindata
rulesets=jmespath.search("[?contains(id,'dnsForwardingRulesets')].{id:id}",data)
check_output(rulesets)

print("\nDNS Private Resolver Outbound Information : (DNS Query from Azure back to on-premises)")

for ruleset in rulesets:
    data=run_azcli("resource show -g "+RESOURCEGROUP+" --ids "+ruleset['id'])
    rulesetinfo=jmespath.search("{id:id,name:name}",data)
    check_output(rulesetinfo)
    print("Outbound Ruleset ID  : %s" % rulesetinfo['id'])
    print("Outbound Ruleset Name: %s" % rulesetinfo['name'])
    data=run_azcli("dns-resolver forwarding-rule list --ruleset-name "+rulesetinfo['name']+" -g "+RESOURCEGROUP)  
    forwardrules=jmespath.search("[].{domainName:domainName,rulestate:forwardingRuleState,id:id,name:name}",data)
    check_output(forwardrules)
    for forwardrule in forwardrules:
        print("Forward to domain    : %s" % forwardrule['domainName'])
        print("Forward rule state   : %s" % forwardrule['rulestate'])
        print("Forward rule ID      : %s" % forwardrule['id'])
        print("Forward rule Name    : %s" % forwardrule['name'])

        targetdnses=jmespath.search("[].targetDnsServers[].{ipAddress:ipAddress,port:port}",data)
        check_output(targetdnses)
        for targetdns in targetdnses:
            print("Target DNS IP        : %s" % targetdns['ipAddress'])
            print("Target Port          : %s" % targetdns['port'])


print("\nList of the storage accoutn that is used by this "+azmigname+" Project")
data=run_azcli("storage account list -g "+RESOURCEGROUP)
azstorids=jmespath.search("[?tags.\"Migrate Project\"=='"+azmigname+"'].id",data)
check_output(azstorids)

for azstorid in azstorids:
    data=run_azcli("resource show -g "+RESOURCEGROUP+" --ids "+azstorid)
    azstoracc=jmespath.search("{kind:kind,name:name,skuname:sku.name}",data)
    check_output(azstoracc)
    print("Name                  : %s" % azstoracc['name'])
    print("Kind                  : %s" % azstoracc['kind'])
    print("SKU name              : %s" % azstoracc['skuname'])

    azstoraccprop=jmespath.search("properties.{tier:accessTier,public:allowBlobPublicAccess,TLS:minimumTlsVersion,blob:primaryEndpoints.blob,acldefault:networkAcls.defaultAction,netaclbypass:networkAcls.bypass}",data)

    if (check_output(azstoraccprop,1)==0):
        print("\nStorage Properties")
        print("Tier                  : %s" % azstoraccprop['tier'])
        print("Public Access         : %s" % azstoraccprop['public'])
        print("Minimum TLS version   : %s" % azstoraccprop['TLS'])
        print("blob endpoint         : %s" % azstoraccprop['blob'])
        print("Net ACL default action: %s" % azstoraccprop['acldefault'])
        print("Net ACL bypass        : %s" % azstoraccprop['netaclbypass'])

    azstoraccenc=jmespath.search("properties.encryption.{keysource:keySource,svcblob:services.blob.enabled,svcblobkeytype:services.blob.keyType}",data)
    if (check_output(azstoraccenc,1)==0):
        print("\nEncryption")
        print("Key Source            : %s" % azstoraccenc['keysource'])
        print("Services blob         : %s" % azstoraccenc['svcblob'])
        print("Services blob key Type: %s" % azstoraccenc['svcblobkeytype'])

    azstorpriveps=jmespath.search("properties.privateEndpointConnections[].{id:id,name:name,privepid:properties.privateEndpoint.id,privlinkstat:properties.privateLinkServiceConnectionState.status,provstate:properties.provisioningState}",data)
    if (check_output(azstorpriveps,1)==0):
       print("\nStorage Private Endpoint")
       for azstorprivep in azstorpriveps:
           print("ID                    : %s" % azstorprivep['id'])
           print("Name                  : %s" % azstorprivep['name'])
           print("Network Priv endpoint : %s" % azstorprivep['privepid'])
           print("Priv Link conn status : %s" % azstorprivep['privlinkstat'])
           print("Provisioning State    : %s" % azstorprivep['provstate'])
           print("\n")




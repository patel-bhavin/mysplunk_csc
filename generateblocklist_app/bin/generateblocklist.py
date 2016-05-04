'''
#This code contains snipppets of code lines which is referred from SPLUNK KV Store REST Python Example written by PHONEIXDIGITAL. Please check the following links if required.
# http://docs.python-requests.org/en/latest/index.html
# http://isbullsh.it/2012/06/Rest-api-in-python/
# http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
# http://pastebin.com/5LG8YAr1 

This is an example of "Generating Custom Commands" in Splunk using Python SDK. It contains third party library and the Python SDK for Splunk. More information about the code can be found in the ReadME file in the application directory

This example shows how to enrich threat intel feeds with WHOIS information using generating custom search commands. Please write me an email to bhavin.j.patel91@gmail.com if you  have any questions about the code or if you need help to develop similar use cases

'''
#!/usr/bin/env python
import sys,time
from splunklib.searchcommands import *
import json, requests
from ipwhois import IPWhois
from ipwhois.utils import unique_addresses
from pprint import pprint
import requests as requests

@Configuration()
class GenerateBlocklistCommand(GeneratingCommand):
   
#Parameter configration for the generateblocklist command    
    url = Option(require=False)  
    delete = Option(require=False, validate=validators.Boolean())
    whois =  Option(require=False, validate=validators.Boolean())

'''Initialize variables to interact with the KV Store.'''
'''Storing Credentials is clear text is not a secure way of coding, this is done only for development of this example'''

    splunkApp = "generateblocklist"
    splunkUser = "admin"
    splunkPwd = "admin"
    splunkURI = "https://localhost:8089/servicesNS/nobody/generateblocklist/storage/collections/data/"
    KV_Store="kvwhois"
    kvURI = "%s/%s" % (splunkURI, KV_Store)
    headers = {'Content-Type': 'application/json'}

#querying whois database and adding data to KV store after we receive the whois response object

    def add_kvstore(self,ips_fin):
        
        i=0
        new_ip=""
        dict_yield_new=[]

        #Ignore Splunk certificate warnings
        requests.packages.urllib3.disable_warnings()

        count =len(ips_fin)-1

        for ip in range(0,count):

            #if its contains CIDR, convert it to an IP address and call WHOIS database

            if (str(ips_fin.keys()[i])).find("/") != -1:

                cidr_string = str(ips_fin.keys()[i])
                new_ip = cidr_string.split("/")[0]

                obj = IPWhois(new_ip)
                results1 = obj.lookup_whois()
                
                kv_data = json.dumps(results1)
                r = requests.post(self.kvURI, kv_data, auth=(self.splunkUser, self.splunkPwd), verify=False, headers=self.headers)
                dict_yield_new.append(results1)
                

            #IF NOT CIDR then call WHOIS
            else:
                

                old_ip=str(ips_fin.keys()[i])
                obj = IPWhois(old_ip)
                results2 = obj.lookup_whois()
                kv_data = json.dumps(results2)
                r = requests.post(self.kvURI, kv_data, auth=(self.splunkUser, self.splunkPwd), verify=False, headers=self.headers)
                dict_yield_new.append(results2)
                #print results2

        return dict_yield_new
        

    
    def generate(self):


        dict_yield = []
        recv_data=None
        ips={}

#Delete KVstore data
        if self.delete == True:

             #Ignore Splunk certificate warnings
            requests.packages.urllib3.disable_warnings()

            r = requests.delete(self.kvURI, auth=(self.splunkUser, self.splunkPwd), verify=False, headers=self.headers)
            msg="Data successfully deleted"
            yield{'_raw': msg}
            sys.exit()

        if self.delete == False:

            yield{'_raw': 'No KV store selected. \n delete = <true/false> to delete default KVstore : kvwhois' }
            sys.exit()

        
#Check if URL is default or provided and initiate a get request to fetch the list of RAW Threat Intel 

        if self.url == "default":

                r=requests.get("https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt")
                recv_data=r.text


        else:
                if (self.url != "default" and self.url !=None):
                    #print "URL provided"
                    r=requests.get(self.url)
                    recv_data=r.text

# check if data is recevied from the url listing the bad IPs and query them to 'whois database' if whois=true.
''' This is where the enrichment process takes place'''

        if(recv_data !=None):

            ips=unique_addresses(data=recv_data,file_path=None)

            if self.whois == True:

                dict_yield= self.add_kvstore(ips)
                
                for i in range(len(dict_yield)-1):

                    yield {'sourcetype': "emerging_newthreats",'KVStore':self.KV_Store,'lookup_name': 'emergingthreats' , '_time': time.time(),'_raw':dict_yield[i] ,'event_no': i, 'ASN-Registry': dict_yield[i]['asn_registry'], 'Search Query': dict_yield[i]['query'],'asn_country_code': dict_yield[i]['asn_country_code'], 'asn_cidr': dict_yield[i]['asn_cidr'], 'asn_date': dict_yield[i]['asn_date'],'nets_address':dict_yield[i]['nets'][0]['address'],'nets_cidr':dict_yield[i]['nets'][0]['cidr'],'nets_city':dict_yield[i]['nets'][0]['city'],'nets_country':dict_yield[i]['nets'][0]['country'],'nets_created':dict_yield[i]['nets'][0]['created'],'nets_emails':dict_yield[i]['nets'][0]['emails'],'nets_description':dict_yield[i]['nets'][0]['description'],'nets_handle':dict_yield[i]['nets'][0]['handle'],'nets_name':dict_yield[i]['nets'][0]['name'],'nets_postal_code':dict_yield[i]['nets'][0]['postal_code'],'nets_range':dict_yield[i]['nets'][0]['range'],'nets_state':dict_yield[i]['nets'][0]['state'],'nets_updated':dict_yield[i]['nets'][0]['updated']}
                    i=i+1

 #if whois=false , generate the list of Bad IPs as events in the Splunk Indexer
           
            i=0 

            if (self.whois == False):

                for key,value in ips.iteritems():

                    yield {'sourcetype': "emerging_newthreats",'KVStore':self.KV_Store,'lookup_name': 'emergingthreats' , '_time': time.time(),'_raw': key , 'bad_ip' : key}
                    i=i+1          
#error if nothing is provided

        else:

            msg='Usage: |generateblocklist url = <default/URL names> whois = <True/False> to generate a KVStore :kvwhois \n If you want to use older data set use the inputlookup <emergingthreats> \n To Delete generated old KVstore : "delete =<true/false>"' 
            yield {'_raw': msg}     
                
dispatch(GenerateBlocklistCommand, sys.argv, sys.stdin, sys.stdout, __name__)
                







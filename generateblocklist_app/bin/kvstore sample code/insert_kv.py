#This code is from SPLUNK KV Store REST Python Example written by PHONEIXDIGITAL 
# http://docs.python-requests.org/en/latest/index.html
# http://isbullsh.it/2012/06/Rest-api-in-python/
# http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
#http://pastebin.com/5LG8YAr1 


import requests, json
 
 
# Sadly due to the Splunk certs containing a password we need to disable warnings
requests.packages.urllib3.disable_warnings()
 
# One possible way to use certs for warnings but you cannot pass the password for the cert so it's close but not quite there
# SplunkCert = '/opt/splunk/etc/auth/server.pem'
# SpunkCertKey = 'password'
#r = requests.delete(splunkURI, auth=(splunkUser, splunkPwd), verify=False, headers=headers, cert=(SplunkCert)
 
splunkApp = "generateblocklist"
splunkUser = "admin"
splunkPwd = "admin"
splunkURI = "https://localhost:8089/servicesNS/nobody/generateblocklist/storage/collections/data/" 
 
KV_Store = "kvwhois"
 


print "\n************** INSERT EXAMPLE ****************"
 
kvURI = "%s/%s" % (splunkURI, KV_Store)
headers = {'Content-Type': 'application/json'}
data = json.dumps({"cve":"MOFO","cwe":"test","score":3,"datePublished":"20150617","dateModified":"20150621","accessVector":"test","summary":"A test record","multivalue":["theFirst","theSecond"]})

r = requests.post(kvURI, data, auth=(splunkUser, splunkPwd), verify=False, headers=headers)
print data

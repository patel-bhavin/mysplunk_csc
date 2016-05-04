# http://docs.python-requests.org/en/latest/index.html
# http://isbullsh.it/2012/06/Rest-api-in-python/
# http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
 
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
 
# Curl Example
# curl -k -u admin:changeme  https://localhost:8089/servicesNS/nobody/nvd_datafeeds/storage/collections/data/cve_database  -H "Content-Type: application/json" -d '{"cve":"test","cwe":"test","score":"here","datePublished":"test","dateModified":"test","accessVector":"test","summary":"test"}'
 
 
# DELETE Data we just added above
print "\n************** DELETE ENTIRE KV STORE EXAMPLE ****************"
 
if True == True:
        kvURI = "%s/%s" % (splunkURI, KV_Store)
        headers = {'Content-Type': 'application/json'}
        r = requests.delete(kvURI, auth=(splunkUser, splunkPwd), verify=False, headers=headers)
 
        print 'Status Code %d' % r.status_code
        # print r.json
        print r.text


        
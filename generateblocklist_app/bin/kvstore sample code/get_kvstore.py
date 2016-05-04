import requests, json
requests.packages.urllib3.disable_warnings()

splunkApp = "generateblocklist"
splunkUser = "admin"
splunkPwd = "admin"
splunkURI = "https://localhost:8089/servicesNS/nobody/generateblocklist/storage/collections/data/"
KV_Store="kvwhois"


kvURI = "%s/%s" % (splunkURI, KV_Store)
data = {"limit":3000}
r = requests.get(kvURI, data, auth=(splunkUser, splunkPwd), verify=False)
 
print 'Status Code %d' % r.status_code
print r.json()[1]

#pprint(r)
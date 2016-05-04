This custom command provides you with a method to interact with third party data sources and integrate them using Python SDK for Splunk and query whois information around it. 

Tools/Library/Environment

	- Splunk Enterprise 6.4.0
	- Python SDK for SPLUNK (splunklib)
	- third party libraries: dns, ipwhois, ipaddr.py, requests

| generateblocklist : 

	The custom command is written with reference to the original application skeleton of Generating Commands. Refer to the blog by Glenn Block to understand the structure of Generating Commands and how they work in the Splunk environment. 
	1)	Primary function is to get a list of known Bad IPs from open source threat feeds which are or can be potentially malicious to your infrastructure. However, you guys can feel free to apply this concept to enrich a variety of datasets with DNS,WHOIS, Domain information and /or Virus total reputation score or reputation on Project Honey Pot.
	2)	Query the Bad IP against the WHOIS database to generate more context and store it to the Splunk KV Store for future splunking.
	3)	Delete and refresh the threat intel KVstore to ensure that we do not have any non-relevant or obsolete data to work with. 

	Let’s see how we can integrate the command generablocklist with the whois data in order to create an enhanced threat list.

______________________
man generateblocklist
______________________

Name: -
	|generateblocklist
	
Synopsis: -
	|generateblocklist [OPTIONS]

Description: -

The idea behind this is to enable everyone to get started with Splunk Custom search commands and to gather whois information around the IP data which may not be directly available from the threat feed providers. Any values that contain spaces, must be within double quotes. This is a Generating custom command and the Python SDK allows you to extend Splunk’s search language and teach it new capabilities. 

OPTIONS:

¥	url = [required] <default> / <URL of the Threat Intel website >
 	URL of the threat feed provider which returns a list of IP addresses.

¥	whois = [required] <true> / <false>
	To query the whois server and enrich the IP addresses with WHOIS information, if whois=true

¥	delete = [optional] <true> / <false>
	To delete the current KVStore data. If the threat intel data is not useful anymore or obsolete, we can delete the KV store data and run the “generateblocklist”command again to gather new updated intelligence. 

__________________________________________________________________________

Examples:
1) to view all BadIP in your SPlunk instance
|generateblocklist url=default whois=false

2) To generate whois information around the IPs in the Splunk instance and store in kvstore : kvwhois
|generateblocklist url= < www . website of threatfeed containing IP addresses.com >  whois=true

3)to delete the KV store 
| generateblocklist delete= true

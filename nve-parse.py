import os
import datetime
from os.path import isfile, join
import json
from pymongo import MongoClient
import pprint

""""""

def flatten_json(y):
	"""Called on a dict or json to remove all nesting"""
	out = {}
	def flatten(x, name=''):
		if type(x) is dict:
			for a in x:
				flatten(x[a], name + a + '_')
		elif type(x) is list:
			i = 0
			for a in x:
				flatten(a, name + str(i) + '_')
				i += 1
		else:
			out[name[:-1]] = x
	flatten(y)
	return out

def grab_db_meta(entry):
	"""Used to get metadata about the current yearly database"""
	cveMeta_json = { }

	cveMeta_json["meta_type"] = entry["CVE_data_type"]
	cveMeta_json["meta_format"] = entry["CVE_data_format"]
	cveMeta_json["meta_version"] = entry["CVE_data_version"]
	cveMeta_json["meta_numberOfCVEs"] = entry["CVE_data_numberOfCVEs"]
	cveMeta_json["meta_timestamp"] = entry["CVE_data_timestamp"]

	return cveMeta_json

def grab_cve(entry):
	"""Assigns chosen items in the list entry into vars 
	for insert into a dictionary. Flattens nested dicts. Returns 
	a JSON to append into cves_json."""
	cveInfo_json = { }

	cveInfo_json["_id"] = entry["cve"]["CVE_data_meta"]["ID"]
	cveInfo_json["cve_assigner"] = entry["cve"]["CVE_data_meta"]["ASSIGNER"]

	# parses and flattens affected vendor entries for the cve
	vendor_list = entry["cve"]["affects"]["vendor"]["vendor_data"]
	for vendor in vendor_list:
		vendor["product"] = vendor["product"]["product_data"]
		for p in vendor["product"]:
			version_list = []
			p["version"] = p["version"]["version_data"]
			for v in p["version"]:
				version_list.append(v["version_value"])
			p["version"] = version_list

	# parses reference entries into dicts
	refs_list = entry["cve"]["references"]["reference_data"]
	# gets the first english cwe description
	cweDesc_data = []
	cwe_list = entry["cve"]["problemtype"]["problemtype_data"]
	for cwe in cwe_list:
		for cweDesc in cwe["description"]:
			if cweDesc["lang"] == 'en':
				cweDesc_data.append(cweDesc["value"])
			break
	# gets the first cve description
	cveDesc_data = ''
	cveDesc_list = entry["cve"]["description"]["description_data"]
	for desc in cveDesc_list:
		if desc["lang"] == 'en':
			cveDesc_data = desc["value"]

	# checks for presence of CVSS metric v3
	if len(entry["impact"]) == 2:
		# entry has metric v2 and v3
		flattened_v2 = flatten_json(entry["impact"]["baseMetricV2"])
		flattened_v3 = flatten_json(entry["impact"]["baseMetricV3"])
	elif len(entry["impact"]) == 1:
		# entry only has metric v2
		flattened_v2 = flatten_json(entry["impact"]["baseMetricV2"])
		flattened_v3 = {}
	else:
		flattened_v2 = {}
		flattened_v3 = {}
	
	cve_publishedDate = entry["publishedDate"]
	cve_lastModifiedDate = entry["lastModifiedDate"]

	# assign dictionaries to json output
	cveInfo_json["vendor"] = vendor_list
	cveInfo_json["references"] = refs_list
	cveInfo_json["cwe"] = cweDesc_data
	cveInfo_json["description"] = cveDesc_data
	cveInfo_json["impactv2"] = flattened_v2
	cveInfo_json["impactv3"] = flattened_v3
	cveInfo_json["publishedDate"] = cve_publishedDate
	cveInfo_json["lastModifiedDate"] = cve_lastModifiedDate

	return cveInfo_json

def rejectCheck(entry):
	"""If there are no references validating this CVE (may be reserved),
	skip the insert for the time"""
	if len(entry["cve"]["references"]["reference_data"]) == 0:
		return 0
	else:
		return 1

def insert_cve(entry):
	test_json_dump.insert(entry)
	print("Inserted {}".format(entry["_id"]))

# load mongo client and establish collections
client = MongoClient('127.0.0.1', 27017)
db = client.pymongo_test
cve_entries = db.cve_entries
test_json_dump = db.test_json_dump
print("Connected to database.")

pp = pprint.PrettyPrinter(indent=4)

now = datetime.datetime.now()
start_year = 2002
end_year = now.year

for year in range(start_year, end_year+1):

	# open and load json into a dict
	jsonfile = open("/home/charles/Desktop/mongo-database/nvd-docs/nvdcve-1.0-" + str(year) + ".json")
	cve_dict = json.loads(jsonfile.read())
	jsonfile.close()

	for k, v in (grab_db_meta(cve_dict)).items():
		print(v)

	cve_list = cve_dict["CVE_Items"]

	for cve in cve_list:
		if rejectCheck(cve) == 0:
			print("{} rejected, skipping insert".format(cve["cve"]["CVE_data_meta"]["ID"]))
			continue
		current_cve = grab_cve(cve)
		insert_cve(current_cve)
		#pp.pprint(current_cve)

client.close()
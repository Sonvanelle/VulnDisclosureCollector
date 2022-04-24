import sys
import time
import zipfile
import pprint
import datetime
from urllib.request import urlopen
import glob
import json
from pymongo import MongoClient

def getModified():
	datestr = datetime.date.today().strftime('%Y-%m-%d')
	existingFile = glob.glob("/home/charles/Desktop/mongo-database/nvd-docs/modified/*")
	for f in existingFile:
		os.remove(f)

	print("grabbing file off nvd")
	file = urlopen("https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.zip")
	dataToWrite = file.read()
	print('read file')
	filePath = '/home/charles/Desktop/mongo-database/nvd-docs/modified/nvdcve-1.0-modified' + datestr + '.zip'
	with open(filePath, 'wb') as f:
		f.write(dataToWrite)
		print("Downloaded.")

	with zipfile.ZipFile(filePath, "r") as zip_ref:
		zip_ref.extractall('/home/charles/Desktop/mongo-database/nvd-docs/modified')
		print("Extracted json.")
		os.remove(filePath)
		timestampedPath = '/home/charles/Desktop/mongo-database/nvd-docs/modified/' + datestr + '.json'
		newfile = os.rename('/home/charles/Desktop/mongo-database/nvd-docs/modified/nvdcve-1.0-modified.json', timestampedPath)

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
	"""Used to get metadata about the modified database"""
	cveMeta_json = { }

	cveMeta_json["meta_type"] = entry["CVE_data_type"]
	cveMeta_json["meta_format"] = entry["CVE_data_format"]
	cveMeta_json["meta_version"] = entry["CVE_data_version"]
	cveMeta_json["meta_numberOfCVEs"] = entry["CVE_data_numberOfCVEs"]
	cveMeta_json["meta_timestamp"] = entry["CVE_data_timestamp"]

	return cveMeta_json

def grab_cve(entry):
	"""A copy of the function from nve-parse.py. Assigns chosen items in the list entry into vars 
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
	if len(entry["cve"]["references"]["reference_data"]) == 0:
		return 0
	else:
		return 1

def insert_cve(entry):
	"""Called to mass-insert the modified entries"""
	modified_json_dump.insert(entry)
	print("Inserted {}".format(entry["_id"]))

def check_id(entry):
	"""Check if the id exists in the database, if not, insert"""
	id = entry["_id"]
	return test_json_dump.find({"_id": id}, {"_id": 1}).count()

def compare_date(entry):
	"""Compares the modfied dates"""
	id = entry["_id"]
	new_date = entry["lastModifiedDate"][:10]
	existing_entry = test_json_dump.find_one({"_id": id})
	existing_date = existing_entry["lastModifiedDate"][:10]

	# print("Old modified date: {}".format(existing_date))
	# print("New modified date: {}".format(new_date))
	new_date_converted = time.strptime(new_date, "%Y-%m-%d")
	existing_date_converted = time.strptime(existing_date, "%Y-%m-%d")	

	if new_date_converted > existing_date_converted:
		return 1
	else:
		return 0

# load mongo client and establish collections
client = MongoClient('127.0.0.1', 27017)
db = client.pymongo_test
test_json_dump = db.test_json_dump
modified_json_dump = db.modified_json_dump
print("Connected to database.")

def get_cache():
	getModified()
	# steps to process and insert entries into the database mostly the same
	jsonfile = open(glob.glob("/home/charles/Desktop/mongo-database/nvd-docs/modified/*")[0])
	cve_dict = json.loads(jsonfile.read())
	jsonfile.close()

	modified_json_dump.drop()
	cve_list = cve_dict["CVE_Items"]
	cves_json = { "cves": [] }

	pp = pprint.PrettyPrinter(indent=4)
	print("Parsing modified cache.")
	for cve in cve_list:
		if rejectCheck(cve) == 0:
			print("{} rejected, skipping insert".format(cve["cve"]["CVE_data_meta"]["ID"]))
			continue
		current_cve = grab_cve(cve)
		insert_cve(current_cve)

def use_cache():
	for doc in modified_json_dump.find():
		id = doc["_id"]
		if check_id(doc) == 1:  # entry id exists
			if compare_date(doc) == 1: # date modified is later than existing entry
				test_json_dump.replace_one({"_id": id}, doc)
				print("Updated {}".format(doc["_id"]))
		
		elif check_id(doc) == 0:  # entry id does not exist (add)
			test_json_dump.insert(doc)
			print("Inserted {}".format(doc["_id"]))
	print("Done.")	

print("""
	1. Get latest Modified db
	2. Apply db
	""")

option = input(">> ")

if option == "1":
	get_cache()
elif option == "2":
	use_cache()
else:
	print("Invalid option.")

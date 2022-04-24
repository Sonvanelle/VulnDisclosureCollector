#!/usr/bin/python3

import os
import sys
import json
import pprint
import gridfs
import urllib
import datetime
from pymongo import MongoClient
from os.path import isfile, join
from urllib.request import urlopen

def print_table(data, cols, wide):
    '''Prints formatted data on columns of given width.'''
    n, r = divmod(len(data), cols)
    pat = '{{:{}}}'.format(wide)
    line = '\n'.join(pat * cols for _ in range(n))
    last_line = pat * r
    print(line.format(*data))
    print(last_line.format(*data[n*cols:]))

def print_cvssV2(impact):
	print("==CVSS v2.0 Severity and Metrics==")
	print("Base Score: {} ({})".format(impact["cvssV2_baseScore"], impact["severity"]))
	print("Vector: {}".format(impact["cvssV2_vectorString"]))
	print("Impact Score: {}".format(impact["impactScore"]))
	print("Exploitability Score: {}".format(impact["exploitabilityScore"]))
	print("")
	print("Access Vector (AV): {}".format(impact["cvssV2_accessVector"]))
	print("Access Complexity (AC): {}".format(impact["cvssV2_accessComplexity"]))
	print("Authentication (AU): {}".format(impact["cvssV2_authentication"]))
	print("Confidentiality (C): {}".format(impact["cvssV2_confidentialityImpact"]))
	print("Integrity (I): {}".format(impact["cvssV2_integrityImpact"]))
	print("Availibility (A): {}".format(impact["cvssV2_availabilityImpact"]))
	print("")

def print_cvssV3(impact):
	print("==CVSS v3.0 Severity and Metrics== ")
	print("Base Score: {} ({})".format(impact["cvssV3_baseScore"], impact["cvssV3_baseSeverity"]))
	print("Vector: {}".format(impact["cvssV3_vectorString"]))
	print("Impact Score: {}".format(impact["impactScore"]))
	print("Exploitability Score: {}".format(impact["exploitabilityScore"]))
	print("")
	print("Access Vector (AV): {}".format(impact["cvssV3_attackVector"]))
	print("Attack Complexity (AC): {}".format(impact["cvssV3_attackComplexity"]))
	print("Privileges Required (PR): {}".format(impact["cvssV3_privilegesRequired"]))
	print("User Interaction (UI): {}".format(impact["cvssV3_userInteraction"]))
	print("Scope (S): {}".format(impact["cvssV3_scope"]))
	print("Confidentiality (C): {}".format(impact["cvssV3_confidentialityImpact"]))
	print("Integrity (I): {}".format(impact["cvssV3_integrityImpact"]))
	print("Availibility (A): {}".format(impact["cvssV3_availabilityImpact"]))

def print_exploit(cve_id):
	result = exploit_dump.find_one({'cve_id': cve_id})
	if result == None:
		return 0

	print("{}".format(result['description']))
	print("E-DB ID: {}".format(result['_id']))
	print("Published: {}".format(result['date']))

	print("\nE-DB file: {}".format(result['file']))
	print("Author: {}".format(result['author']))
	print("Type: {}".format(result['type']))
	print("Platform: {}".format(result['platform']))

	filename = result['file'].split("/")[-1]	
	
	print('\n=={}=='.format(filename))
	print("{}".format(result['poc'].decode('utf-8')))
	#print("{}".format(result['poc_txt']))

	print('\n==END CODE==\n')

def print_tweets(cve_id):
	result = good_tweets.find({"cve_id": cve_id})
	if result == None:
		return 0

	for entry in result:
		print("https://twitter.com/malwaregarry/status/{}".format(entry['id']))
		print("===============================================================")
		print(entry['tweet'])
		print(entry['url'])
		print()

def cve_search(cveQuery):

	cve_result = test_json_dump.find({"_id": cveQuery})
	
	for cve in cve_result:
		#solves the small issue if cwe is still in a list, for some reason
		if type(cve['cwe']) == list:
			if not cve['cwe']:
				cve_cwe = "[No CWE assigned] "
			else:	
				cve_cwe = cve['cwe'][0]
		else:
			cve_cwe = cve['cwe']
			
		print("\n{:15}{:10}{:15}\n".format(cve["_id"], cve_cwe, cve["cve_assigner"]))
		print(cve["description"])
		print("")
		
		for vendor in cve["vendor"]:
			print("{:7} : {}".format("Vendor", vendor["vendor_name"]))
			for product in vendor["product"]:
				print("{:7} : {}".format("Product", product["product_name"]))
				print("Affected versions:")
				
				print_table(product["version"], 4, 12)
				print("_" * 14)
			print("")

		print("==Advisories & References==")
		for ref in cve["references"]:
			print("{} - {}".format(ref["refsource"], ref["name"]))
			print(ref["url"])
			if len(ref["tags"]) > 0:
				for tag in ref["tags"]:
					print(str("| ") + tag, end=" | ")
				print("\n")
			else:
				print("")
		
		if len(cve["impactv2"]) != 0 and len(cve["impactv3"]) != 0:
			print_cvssV2(cve["impactv2"])
			print_cvssV3(cve["impactv3"])

		elif len(cve["impactv2"]) != 0 and len(cve["impactv3"]) == 0:		
			print_cvssV2(cve["impactv2"])


	
		print("\nPublished Date: {:.10}".format(cve["publishedDate"]))
		print("Last Modified: {:.10}".format(cve["lastModifiedDate"]))
		print('')

		print_exploit(cve["_id"])
		print_tweets(cve["_id"])

		global result
		result = 1


# load mongo client and establish collections
client = MongoClient('127.0.0.1', 27017)
db = client.pymongo_test
test_json_dump = db.test_json_dump
good_tweets = db.fgood_tweets
shellcode_dump = db.shellcode_dump
exploit_dump = db.exploit_dump
exploit_dump_copy = db.exploit_dump_copy
print("Connected to database.")

# # load GridFS connnection
# db2 = MongoClient().gridfs_test  #attached to the main db, stores exploits
# fs = gridfs.GridFS(db)

# db3 = MongoClient().gridfs_test2 #attached to gridfs_test2 db, stores shellcode
# fs2 = gridfs.GridFS(db3)
# print("Connected to GridFS.")
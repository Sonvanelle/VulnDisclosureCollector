import os
import re
import sys
import cgi
import glob
import json
import shutil
import gridfs
import pprint
import csvdiff
import datetime
import pandas as pd
import multiprocessing
from bson import Binary
from pymongo import MongoClient
from urllib.request import urlopen
from requests_html import HTMLSession

def check_id(entry, database):
	"""Check if the id exists in the database"""
	if len(entry) == 2:
		id = entry['key'][0]
	else:
		id = entry["id"]
	return database.find({'_id': id}, {"_id": 1}).count()

def push_addition(entry, database):
	"""Pushes the entry from the comparison file to the exploit dump."""
	entry['_id'] = entry.pop('id')
	print("Inserted entry {}".format(entry['_id']))
	database.insert(entry)

def push_change(entry, database):
	"""Navigates to the entry in the database and updates all fields."""
	id = entry['key'][0]
	for k, v in entry['fields'].items():
		update_key = k
		update_value = v['to']
		database.update_one({'id': id}, {'$set': {update_key: update_value}})
		print("Updated {}: {} - {}".format(id, update_key, update_value))

def mark_removal(entry, database):
	"""Navigates to the entry in the database and plants a 'deleted' flag"""
	id = entry['id']
	database.update_one({'id': id}, {'$set': {'removed': 1}})
	print("Exploit {} marked as removed.".format(id))

def cve_crawl(entry):
	"""Grabs the CVE ID from E-DB based off its static xpath"""
	url = "https://www.exploit-db.com/exploits/{}/".format(entry)
	session = HTMLSession()
	r = session.get(url)
	print(url)
	
	cve_box = r.html.find('.stats-title')[1]
	cve_box_text = str("")

	if cve_box.text == 'N/A':
		print('No CVE')

	else:
		for cve in cve_box.text.split(' '):
			cve = "CVE-{}".format(cve)
			cve_box_text += cve
			cve_box_text += ' '

		return cve_box_text

def download_exploit(entry):
	url = "https://www.exploit-db.com/download/{}".format(entry)
	file = urlopen(url)
	data = file.read()

	_, params = cgi.parse_header(file.headers.get('Content-Disposition', ''))
	filename = params['filename']
	exploit_dump.find_one_and_update({'_id': entry}, {'$set': {"poc": Binary(data)}})
	a = fs.put(data, filename=filename)
	print("Inserted {}.".format(filename))
	return filename

def download_shellcode(entry):
	url = "https://www.exploit-db.com/download/{}".format(entry)
	file = urlopen(url)
	data = file.read()

	_, params = cgi.parse_header(file.headers.get('Content-Disposition', ''))
	filename = params['filename']
	shellcode_dump.find_one_and_update({'_id': entry}, {'$set': {"shellcode": Binary(data)}}, upsert=True)
	a = fs2.put(data, filename=filename)
	print("Inserted {}".format(filename))
	return filename

def print_comparison():
	print("Removed: {}  Added: {}  Changed: {}".format(len(comparison['removed']), len(comparison['added']), len(comparison['changed'])))

	# print("\nAdded")
	# for entry in comparison['added']:
	# 	for k, v in entry.items():
	# 		print("{}: {}".format(k, v))
	# 	print('\n')
	# print("\nChanged")
	# for entry in comparison['changed']:
	# 	for k, v in entry.items():
	# 		print("{}: {}".format(k, v))
	# 	print('\n')
	# print("\nRemoved")
	# for entry in comparison['removed']:
	# 	for k, v in entry.items():
	# 		print("{}: {}".format(k, v))

# load mongo client and establish collections
client = MongoClient('127.0.0.1', 27017)
db = client.pymongo_test
shellcode_dump = db.shellcode_dump
exploit_dump = db.exploit_dump
exploit_dump_copy = db.exploit_dump_copy
print("Connected to database.")

db2 = MongoClient().gridfs_test  #attached to the main db, stores exploits
fs = gridfs.GridFS(db)

db3 = MongoClient().gridfs_test2 #attached to gridfs_test2 db, stores shellcode
fs2 = gridfs.GridFS(db3)
print("Connected to GridFS.")

pool = multiprocessing.Pool()
datestr = datetime.date.today().strftime('%Y-%m-%d')

def update_exploits():
	original_file = glob.glob("/home/charles/Desktop/mongo-database/e-db/exploits/*")[0]
	print("Current cache: {}".format(original_file))

	file = urlopen('https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv')
	dataToWrite = file.read()
	filePath = '/home/charles/Desktop/mongo-database/e-db/exploits-update/exploits' + datestr + '.csv'
	with open(filePath, 'wb') as f:
		f.write(dataToWrite)
		print("Grabbed latest exploit CSV.")

	# get comparison dict
	global comparison
	comparison = csvdiff.diff_files(original_file, filePath, ['id'])

	# prepare json for insert/update/delete
	if len(comparison['added']) != 0:
		addition_dump = json.loads(json.dumps(comparison['added']))
	if len(comparison['removed']) != 0:
		removal_dump = json.loads(json.dumps(comparison['removed']))
	if len(comparison['changed']) != 0:
		changes_dump = json.loads(json.dumps(comparison['changed']))

	print_comparison()
	if len(comparison['added']) == 0 and len(comparison['changed']) == 0:
		print("No changes to db, quitting.")
		sys.exit()

	if len(comparison['added']) != 0:
		for entry in addition_dump:
			if check_id(entry, exploit_dump) == 0:
				push_addition(entry, exploit_dump)
				pool.apply_async(cve_crawl, args=(entry['_id'],))
				# check exploits for matching entry and if there is a cve, try and download exploit
				if exploit_dump.find_one({'_id': entry['_id']}, {'cve_id': 1}) != 1:
					pool.apply_async(download_exploit, args=(entry['_id'],))
					print("Exploit archived.")
			else:
				print("ID {} exists, skipping insert. Checking exploits...".format(entry['id']))
				cve_crawl(entry['id'])
				if exploit_dump.find({'_id': entry['id']}, {'cve_id': 1, 'poc': 0}) != 1: # edb id has a cve	
					pool.apply_async(download_exploit, args=(entry['id'],))
					print("Exploit archived.")

	
	if len(comparison['changed']) != 0:
		for entry in changes_dump:
			if check_id(entry, exploit_dump) == 1:
				push_change(entry, exploit_dump)
				pool.apply_async(cve_crawl, args=(entry['key'][0],))
				if exploit_dump.find_one({'_id': entry['key']}, {'cve_id': 1}) != 1:
					pool.apply_async(download_exploit, args=(entry['key'], ))
			else:
				print("ID {} does not exist, skipping modify.".format(entry['key'][0]))

	if len(comparison['removed']) != 0:
		print(removal_dump)
		for entry in removal_dump:
			if check_id(entry, exploit_dump) == 1:
				mark_removal(entry, exploit_dump)
				print("{} marked as removed.".format())
			else:
				print("fail")

	# after pushing updates, replace cache file
	os.remove(original_file)
	shutil.copy(filePath, '/home/charles/Desktop/mongo-database/e-db/exploits/')
	print("Cache updated: {}".format(glob.glob("/home/charles/Desktop/mongo-database/e-db/exploits/*")[0]))

def update_shellcode():

	original_file = glob.glob("/home/charles/Desktop/mongo-database/e-db/shellcode/*")[0]
	print("Current cache: {}".format(original_file))

	file = urlopen('https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_shellcodes.csv')
	dataToWrite = file.read()
	filePath = '/home/charles/Desktop/mongo-database/e-db/shellcode-update/shellcodes' + datestr + '.csv'
	with open(filePath, 'wb') as f:
		f.write(dataToWrite)
	print("Grabbed latest shellcode CSV.")

	# get comparison dict
	global comparison
	comparison = csvdiff.diff_files(original_file, filePath, ['id'])

	# prepare json for insert/update/delete
	if len(comparison['added']) != 0:
		addition_dump = json.loads(json.dumps(comparison['added']))
	if len(comparison['removed']) != 0:
		removal_dump = json.loads(json.dumps(comparison['removed']))
	if len(comparison['changed']) != 0:
		changes_dump = json.loads(json.dumps(comparison['changed']))

	print_comparison()

	if len(comparison['added']) == 0 and len(comparison['changed']) == 0:
		print("No changes to db, quitting.") #ignore removals
		sys.exit()
	
	if len(comparison['added']) != 0:
		for entry in addition_dump:
			if check_id(entry, shellcode_dump) == 0:
				push_addition(entry, shellcode_dump)
				pool.apply_async(download_shellcode, args=(entry['_id'],))
				print("Shellcode archived.")		
			
			else:
				print("ID {} exists, skipping insert.".format(entry['id']))

	if len(comparison['changed']) != 0:
		for entry in changes_dump:
			if check_id(entry, shellcode_dump) == 1:
				push_change(entry)
				pool.apply_async(download_shellcode, args=(entry['_id'],))
				print("Shellcode archived.")
					
			else:
				print("ID {} does not exist, skipping modify.".format(entry['key'][0]))

	if len(comparison['removed']) != 0:
		for entry in removal_dump:
			if check_id(entry, shellcode_dump) == 1:
				mark_removal(entry, shellcode_dump)

	# after pushing updates, replace cache file
	os.remove(original_file)
	shutil.copy(filePath, '/home/charles/Desktop/mongo-database/e-db/shellcode/')
	print("Cache updated: {}".format(glob.glob("/home/charles/Desktop/mongo-database/e-db/shellcode/*")[0]))

print("""
	1. Update exploit db
	2. Update shellcode db
	""")

option = input(">> ")

if option == "1":
	update_exploits()
elif option == "2":
	update_shellcode()
import os
import re
import cgi
import sys
import glob
import gridfs
import datetime
import multiprocessing
from bson import Binary
from pymongo import MongoClient
from urllib.request import urlopen

"""Script that runs through exploit_dump entries and creates an additional field for the text version
of Binary PoC samples. The poc_txt field will be used for searching."""

def check_poc(entry):
	selected = exploit_dump.find_one({"_id": entry['_id'], "poc": {"$exists": False}})
	if selected == None:
		return 1 # contains poc
	else:
		return 0 # does not contain poc

def create_exploit_index(entry):
	poc_string = entry['poc']
	escaped_code = poc_string.decode('utf-8')
	exploit_dump.find_one_and_update({'_id': entry['_id']}, {'$set': {"poc_txt": escaped_code}})
	print("Entry created for {}.".format(entry['_id']))

def download_exploit(entry):
	url = "https://www.exploit-db.com/download/{}".format(entry)
	print(url)
	file = urlopen(url)
	data = file.read()

	_, params = cgi.parse_header(file.headers.get('Content-Disposition', ''))
	filename = params['filename']
	exploit_dump.find_one_and_update({'_id': entry}, {'$set': {"poc": Binary(data)}})
	a = fs.put(data, filename=filename)
	print("Inserted {}".format(filename))
	return filename

# load mongo client and establish collections
client = MongoClient('127.0.0.1', 27017)
db = client.pymongo_test
test_json_dump = db.test_json_dump

shellcode_dump = db.shellcode_dump
exploit_dump = db.exploit_dump
print("Connected to database.")

db2 = MongoClient().gridfs_test  #attached to the main db, stores exploits
fs = gridfs.GridFS(db)

db3 = MongoClient().gridfs_test2 #attached to gridfs_test2 db, stores shellcode
fs2 = gridfs.GridFS(db3)
print("Connected to GridFS.")

pool = multiprocessing.Pool()

exploit_data = exploit_dump.find()
for entry in exploit_data:
	if check_poc(entry) == 1:
		pool.apply(create_exploit_index, args=(entry,))

# exploit_data = exploit_dump.find()
# for entry in exploit_data:
# 	if check_poc(entry) == 0:
# 		pool.apply(download_exploit, args=(entry['_id'],))
pool.close()
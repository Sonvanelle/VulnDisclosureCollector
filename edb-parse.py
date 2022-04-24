import os
import re
import csv
import cgi
import json
import glob
import pprint
import gridfs
import requests
import mimetypes
import pandas as pd
import multiprocessing
from bson import Binary
from pymongo import MongoClient
from urllib.request import urlopen
from requests_html import HTMLSession


def grab_shellcode():
	"""Uses the pandas tool to process the CSV dataset before inserting into the mongo database"""
	file = open(glob.glob("/home/charles/Desktop/mongo-database/e-db/shellcode/*")[0])
	data = pd.read_csv(file)
	data_json = json.loads(data.to_json(orient='records'))
	pp = pprint.PrettyPrinter(indent=4)
	for i in data_json:
		i['_id'] = i.pop('id')
		pp.pprint(i)
		shellcode_dump.insert(i)

def grab_exploit():
	"""Uses the pandas tool to process the CSV dataset before inserting into the mongo database"""
	file = open(glob.glob("/home/charles/Desktop/mongo-database/e-db/exploits/*")[0])
	data = pd.read_csv(file)
	global data_json
	data_json = json.loads(data.to_json(orient='records'))
	pp = pprint.PrettyPrinter(indent=4)
	for i in data_json:
		i['_id'] = i.pop('id')
		pp.pprint(i)
		exploit_dump.insert(i)

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

def remove_dots():
	"""Management function to remove trailing dots parsed from the site element"""
	cve_result = exploit_dump.find({"cve_id": {'$regex': '\\.$' }})
	regex = re.compile(r'[...]')
	for result in cve_result:
		cve_id_done = regex.sub('', result['cve_id'])
		exploit_dump.find_one_and_update({'_id': result['_id']}, {'$set': {"cve_id": cve_id_done}})
		print(cve_id_done)

def download_exploit(entry):
	url = "https://www.exploit-db.com/download/{}".format(entry)
	file = urlopen(url)
	data = file.read()

	_, params = cgi.parse_header(file.headers.get('Content-Disposition', ''))
	filename = params['filename']
	exploit_dump.find_one_and_update({'_id': entry}, {'$set': {"poc": Binary(data)}})
	a = fs.put(data, filename=filename)
	print("Inserted {}".format(filename))
	return filename

def download_shellcode(entry):
	url = "https://www.exploit-db.com/download/{}".format(entry)
	file = urlopen(url)
	data = file.read()

	_, params = cgi.parse_header(file.headers.get('Content-Disposition', ''))
	filename = params['filename']
	shellcode_dump.find_one_and_update({'_id': entry}, {'$set': {"shellcode": Binary(data)}})
	a = fs2.put(data, filename=filename)
	print("Inserted {}".format(filename))
	return filename

# load mongo client and establish collections
client = MongoClient('127.0.0.1', 27017)
db = client.pymongo_test
shellcode_dump = db.shellcode_dump
exploit_dump = db.exploit_dump
print("Connected to database.")

db2 = MongoClient().gridfs_test  #attached to the main db, stores exploits
fs = gridfs.GridFS(db)

db3 = MongoClient().gridfs_test2 #attached to gridfs_test2 db, stores shellcode
fs2 = gridfs.GridFS(db3)
print("Connected to GridFS.")

# Populates the database with entries from the E-DB CSV cache (grab_shellcode() and grab_exploit())
grab_exploit()
exploit_dump.update_many({}, {'$set': {"cve_id": 1}})
file = open(glob.glob("/home/charles/Desktop/mongo-database/e-db/exploits/*")[0])
data = pd.read_csv(file)
exploit_json = json.loads(data.to_json(orient='records'))
jobs = []
pool = multiprocessing.Pool()
for exploit in exploit_json:
	entry_id = exploit['id']
	pool.apply_async(cve_crawl, args=(entry_id,))

exploit_data = exploit_dump.find()
jobs = []
pool = multiprocessing.Pool()
for exploit in exploit_data:
	entry_id = exploit['_id']
	entry_cve = exploit['cve_id']
	if entry_cve != 1: # edb id has a cve
		print("{} - {}".format(entry_id, entry_cve))
		pool.apply_async(download_exploit, args=(entry_id,))

shellcode_data = shellcode_dump.find()
pool = multiprocessing.Pool()
for shellcode in shellcode_data:
	entry_id = shellcode['_id']
	pool.apply_async(download_shellcode, args=(entry_id,))

pool.close()
pool.join()
import os
import sys
import glob
import gridfs
import multiprocessing
from bson import Binary
from github import Github
from pymongo import MongoClient
from urllib.request import urlopen

# load mongo client and establish collections
client = MongoClient('127.0.0.1', 27017)
db = client.pymongo_test
test_json_dump = db.test_json_dump

shellcode_dump = db.shellcode_dump
exploit_dump = db.exploit_dump
print("Connected to database.")

db_bin = MongoClient().gridfs_testbin
fs_bin = gridfs.GridFS(db_bin)
print("Connected to GridFS.")

github = Github("softwaregarry", "biggestmoney5ever")
user = github.get_user()
repo = github.get_repo("offensive-security/exploitdb-bin-sploits")

def get_binaries(file):
	url = "https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/{}".format(file.name)
	print(url)
	filename = file.name
	edb_id = file.name.split(".")[0]
	print(edb_id)
	file = urlopen(url)
	data = file.read()
	print(sys.getsizeof(data))
	if sys.getsizeof(data) > 4194304:
		a = fs_bin.put(data, filename=filename, edb_id=edb_id)
		print("Inserted bin-sploit for {}.".format(edb_id))

	else:
		exploit_dump.find_one_and_update({'_id': edb_id}, {'$set': {"poc_bin": Binary(data)}})
		a = fs_bin.put(data, filename=filename, edb_id=edb_id)
		print("Inserted bin-sploit for {}.".format(edb_id))

jobs = []

contents = repo.get_dir_contents("bin-sploits")
for file in contents:
	p = multiprocessing.Process(target=get_binaries, args=(file,))
	jobs.append(p)
	p.start()

# pool = multiprocessing.Pool()
# contents = repo.get_dir_contents("bin-sploits")
# for file in contents:
# 	pool.apply_async(get_binaries, args=(file,))
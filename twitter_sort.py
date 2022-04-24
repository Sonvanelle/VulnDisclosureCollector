import os
import re
import sys
import csv
import json
import pprint
import gridfs
import datetime
import pandas as pd
import multiprocessing
import _pickle as cPickle
from pymongo import MongoClient
from timeit import default_timer as timer

# start timer
start = timer()

# load mongo client and establish collections
client = MongoClient('127.0.0.1', 27017)
db = client.pymongo_test
flagged_tweets = db.flagged_tweets
good_tweets = db.good_tweets
print("Connected to database.")

global pp
pp = pprint.PrettyPrinter(indent=2)

def specify_cve(entry):
	print("Enter CVE ID. (20XX-XXXX)")
	cveInput = input(">> ")
	cveInput = "CVE-{}".format(cveInput)
	flagged_tweets.find_one_and_update({'id': entry['id']}, {'$set': {"cve_id": cveInput}})
	print()
	print("{} specified for entry.".format(cveInput))

def remove_entry(entry):
	print("""
		Are you sure this tweet has no relation to any exploit or CVE?
		This operation is irreversible.
		Remove entry? (Y / N)
		""")
	deleteInput = input(">> ")

	if deleteInput == 'Y' or deleteInput == 'y':
		flagged_tweets.delete_one({'id': entry['id']})
		print("Deleted.")

	elif deleteInput == 'N' or deleteInput == 'n':
		print("")

	else:
		print("Invalid input.")

def mark_and_move(entry):
	current = flagged_tweets.find_one({'id': entry['id']})
	good_tweets.insert_one(current)
	flagged_tweets.delete_one({'id': entry['id']})
	print("Tweet marked for storage.")


# iterate thru every tweet in the collection
while True:
	cursor = flagged_tweets.find()
	try:
		document = cursor[0]

	except IndexError:
		print("End of file reached. Stream more tweets from the classifier.")
		print("Approved tweets are contained in the good_tweets collection in the Mongo DB.")
		exit()

	pp.pprint(document)
	print()
	print("""
		1. Specify CVE ID for entry
		2. Delete useless entry
		3. Mark useful entry
		""")
	menuInput = int(input(">> "))

	if type(menuInput) == str:
		print("Invalid input.\n")
	elif menuInput == 1:
		specify_cve(document)
	elif menuInput == 2:
		remove_entry(document)
	elif menuInput == 3:
		mark_and_move(document)
	else:
		print("Invalid input.\n")
	

# stop timer and print program time
end = timer()
print("[Time elapsed: {}s]".format(end - start))
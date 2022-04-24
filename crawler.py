import csv
import os
from urllib.request import urlopen
import time
import re
import pymongo
from pymongo import MongoClient
import pandas as pd


def init_dl():
    """Performs inital download and creates timestamp entry."""
    csvFile = urlopen('http://cve.mitre.org/data/downloads/allitems.csv')
    dataToWrite = csvFile.read()
    print("File downloaded.")
    timestr = time.strftime("%Y%m%d")
    with open('/home/charles/Desktop/mongo-database/cve/csv_cache_' + timestr + '.csv', 'wb') as f:
        f.write(dataToWrite)

    #creates timestamp in database
    meta_entries.insert_one({'_id' : 1, "cache_timestamp" : timestr})
    print("Data cached on: " + timestr)
    f.close()

def update_cache(cache_path):
    """Deletes existing cache and replaces it with a fresh one."""
    paths, dirs, files = next(os.walk("/home/charles/Desktop/mongo-database/cve/"))
    if len(files) == 1:
        print("\nRemoving old file at: " + cache_path)
        os.remove(cache_path)

        #redownloads csv and caches
        csvFile = urlopen('https://cve.mitre.org/data/downloads/allitems.csv')
        dataToWrite = csvFile.read()
        timestr = time.strftime("%Y%m%d")
        with open('/home/charles/Desktop/mongo-database/cve/csv_cache_' + timestr + '.csv', 'wb') as f:
            f.write(dataToWrite)

        #updates timestamp in database
        result = meta_entries.update({'_id' : 1}, {"$set" : {"cache_timestamp" : timestr}})
        print("Info: " + str(result))
        print("Data re-cached on: " + timestr)
        f.close()

def read_cache():
    """Checks the folder for cache file and returns path"""
    global cache_path
    for file in os.listdir("/home/charles/Desktop/mongo-database/cve/"):
        cache_path = os.path.join("/home/charles/Desktop/mongo-database/cve/", file)
    print(cache_path)

def index_cache(cache_path):
    print("Reading cache...")
    data = pd.read_csv(cache_path)
    

def main():
    """Menu function"""
    print("""
        1. Delete and update cache
        2. Import cache to DB
    """)
    option = input(">> ")


cache_path = 0

client = MongoClient('127.0.0.1', 27017)
#database
db = client.pymongo_test
#collections
cve_entries = db.cve_entries
meta_entries = db.meta_entries
print("Connected to database.")

if meta_entries.count() == 0:
    print("\nPerforming initial cache...")
    init_dl()
else:
    # grabs timestamp cursor and value
    timestamp_cursor = meta_entries.find({}, {'_id':0, 'cache_timestamp':1})[0]
    print("Cache exists. Downloaded on: {}" .format(timestamp_cursor.get('cache_timestamp')))
    read_cache()
    #update_cache(cache_path)


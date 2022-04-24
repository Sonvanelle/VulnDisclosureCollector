#!/usr/bin/python3
import os
import csv
import json
import pprint
import datetime
import jsonpickle
from TwitterAPI import TwitterAPI, TwitterPager

date = datetime.datetime.today().strftime('%Y-%m-%d')
global pp
pp = pprint.PrettyPrinter(indent=4)

with open("/home/charles/Desktop/mongo-database/twitter/twitter_credentials_malwaregarry.json") as creds:
	info = json.load(creds)
	consumer_key = info['CONSUMER_KEY']
	consumer_secret = info['CONSUMER_SECRET']
	access_key = info['ACCESS_KEY']
	access_secret = info['ACCESS_SECRET']

api = TwitterAPI(consumer_key, consumer_secret, access_key, access_secret)
# r = api.request('tweets/search/fullarchive/:dev',
#                 {'query': 'CVE exploit'})

# print(r.status_code)

# count = 0
# for item in r:
# 	count += 1
# 	print(item['text'] if 'text' in item else item)
# 	print(count)
# 	print()

def saveTweets(query):
	# '30day' or 'fullarchive' to be specified as search product
	pager = TwitterPager(api, 'tweets/search/30day/:dev', {'query': query})
	tweetCount = 1
	maxTweets = 50

	# open a JSON file and download all queried tweets
	with open('cachefull{}.json'.format(date), 'w+') as f:
		try:
			for item in pager.get_iterator():
				if tweetCount < maxTweets:
					if not item['retweeted'] and item["lang"] == "en":
						#Write the JSON format to the text file, and add one to the number of tweets we've collected
						f.write(jsonpickle.encode(item, unpicklable=False) + '\n')

						if item['truncated'] == False:
							print(item['text'])
						else:
							print(item['extended_tweet']['full_text'])
						print()
						tweetCount += 1
						print(tweetCount)
				else:
					break

		except:
			print("Twitter request error")
			# void entry

		#Display how many tweets we have collected
		print("Downloaded {0} tweets".format(tweetCount))

	# attempts to remove tweets with duplicate IDs
	jsonList = []
	with open('cachefull{}.json'.format(date), "r") as g:
		for line in g:
			jsonList.append(json.loads(line))

	uniqueDict = {}
	print()
	
	for entry in jsonList:
		pp.pprint(entry)
		print()

		tweetId = entry["id"]
		tweetText = entry['text']

		if any(tweetText in e.values() for e in uniqueDict.values()) != True:
			uniqueDict[tweetId] = entry

	print("Removed dupes. {} unique entries remaining.".format(len(uniqueDict)))
	return uniqueDict

# specify tweet search query tag(s) here
cveQuery = 'vulnerability'
uniqueDict = saveTweets(cveQuery)

with open('/home/charles/Desktop/mongo-database/learning/datasets/cachefull{}.json'.format(date), 'w+') as cacheFile:
	#cacheFile.write(uniqueDict)
	json.dump(uniqueDict, cacheFile, sort_keys=True, indent=4)

os.remove('cachefull{}.json'.format(date))
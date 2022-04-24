#!/usr/bin/python3
import os
import re
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

pager = TwitterPager(api, 'statuses/sample')
tweetCount = 0
maxTweets = 2000
jsonDict = {}

# TODO: ADD REGEX FILTERING TO TWEET CONTENT (TRACK TERM WORKAROUND)

# open a JSON file and download all queried tweets
with open('/home/charles/Desktop/mongo-database/learning/datasets/cachefull_random_{}.json'.format(date), 'w+') as f:
	try:
		for item in pager.get_iterator():
			if tweetCount < maxTweets:
				if 'delete' not in item and item["lang"] == "en":
					tweetId = item['id']
					tweetText = item['text']

					# checks if tweet body text is already in the dict
					if any(tweetText in e.values() for e in jsonDict.values()) != True:
						jsonDict[tweetId] = item
						tweetCount += 1
						print("{}. - {}".format(tweetCount, tweetId))
						print()

			else:
				break
	except:
		print("Twitter request error")
		# void entry

	# Display how many tweets we have collected
	print("Downloaded {0} tweets".format(tweetCount))
	# Dump contents of the dict into a formatted json
	json.dump(jsonDict, f, sort_keys=True, indent=4)

f.close()
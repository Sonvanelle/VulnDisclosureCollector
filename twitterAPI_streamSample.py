#!/usr/bin/python3
import os
import re
import csv
import json
import pprint
import datetime
import jsonpickle
import multiprocessing
from TwitterAPI import TwitterAPI, TwitterPager

date = datetime.datetime.today().strftime('%Y-%m-%d')
global pp
pp = pprint.PrettyPrinter(indent=4)
# pool = multiprocessing.Pool(processes=2)


def download_sample(number, term):
	"""
	Version of the twitter api stream program, but it is called as a function to 
	download a smaller sample of tweets. The number of tweets to download is called as a parameter.
	"""
	with open("/home/charles/Desktop/mongo-database/twitter/twitter_credentials_malwaregarry.json") as creds:
		info = json.load(creds)
		consumer_key = info['CONSUMER_KEY']
		consumer_secret = info['CONSUMER_SECRET']
		access_key = info['ACCESS_KEY']
		access_secret = info['ACCESS_SECRET']

	api = TwitterAPI(consumer_key, consumer_secret, access_key, access_secret)

	pager = api.request('statuses/filter', {'track': term})
	tweetCount = 0
	maxTweets = number
	jsonDict = {}

	print("Getting tweets...")
	# open a JSON file and download all queried tweets
	filePath = '/home/charles/Desktop/mongo-database/learning/datasets/sampleset.json'
	with open(filePath, 'w+') as f:

		for item in pager:
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

		# Display how many tweets we have collected
		print("Downloaded {0} tweets".format(tweetCount))
		# Dump contents of the dict into a formatted json
		json.dump(jsonDict, f, sort_keys=True, indent=4)

	f.close()
	return filePath
import os
import re
import sys
import csv
import json
import pprint

# import datetime
# import pandas as pd
import multiprocessing
# import _pickle as cPickle
# from pymongo import MongoClient
# from sklearn.externals import joblib
# from timeit import default_timer as timer
# from twitterAPI_streamSample import download_sample

# import spacy
# import numpy as np
# import itertools

# import nltk
# from nltk.corpus import stopwords
# import matplotlib.pyplot as plt
# from progressbar import ProgressBar
# from nve_query_func import cve_search

# # nltk.download('punkt')
# # nltk.download('wordnet')
# # nltk.download('stopwords')

# # prep
# from sklearn import svm, preprocessing, linear_model
# from sklearn.feature_extraction.text import CountVectorizer
# from sklearn.feature_extraction.text import TfidfTransformer
# from sklearn.pipeline import Pipeline
# from sklearn.metrics import balanced_accuracy_score, classification_report, roc_curve, roc_auc_score
# from sklearn import datasets
# from sklearn.preprocessing import StandardScaler, scale

# # models
# from sklearn.svm import LinearSVC
# from sklearn.linear_model import SGDClassifier, LogisticRegression
# from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score, cross_val_predict


# holds the dataframe_entry_dict data from the parse_cache function
global dataframe_full_dict
global pp
pp = pprint.PrettyPrinter(indent=2)


def parse_cache(entry):
	# called in a loop to parse every entry of the cache and populate dataframe_full_dict
	contains_url = 0
	contains_media = 0

	# for truncated (extended) tweets
	if ('truncated', True) in entry.items():
		if 'full_text' in entry['extended_tweet']:
			data = entry['extended_tweet']['full_text']
			username = entry['user']['name']
			screenname = entry['user']['screen_name']
			tweet_id = entry['id']

			url_list = []

			# print urls
			if len(entry['extended_tweet']['entities']['urls']) != 0:
				if len(entry['extended_tweet']['entities']['urls']) > 1: # more than one url
					for url in entry['extended_tweet']['entities']['urls']:
						url_list.append(url["expanded_url"])
					body_url = ' '.join(url_list)
					contains_url = 1

				else: # contains just one url
					body_url = entry['extended_tweet']['entities']['urls'][0]['expanded_url']
					contains_url = 1
			else:
				body_url = None

			if "media" in entry['extended_tweet']['entities']:
				media_url = entry['extended_tweet']['entities']['media'][0]['expanded_url']
				contains_media = 1
			else:
				media_url = None

	# for non-truncated tweets
	else:
		data = entry['text']

		# check for extended tweet in retweeted_status
		if 'retweeted_status' in entry:
			if 'extended_tweet' in entry['retweeted_status']:
				if 'full_text' in entry['retweeted_status']['extended_tweet']:
					# overwrite data variable
					data = entry['retweeted_status']['extended_tweet']['full_text']

		username = entry['user']['name']
		screenname = entry['user']['screen_name']
		tweet_id = entry['id']

		url_list = []

		if len(entry['entities']['urls']) != 0:
			if len(entry['entities']['urls']) > 1: # more than one url
				for url in entry['entities']['urls']:
					url_list.append(url["expanded_url"])
				body_url = ' '.join(url_list)
				contains_url = 1

			else: # contains just one url
				body_url = entry['entities']['urls'][0]['expanded_url']
				contains_url = 1

		else:
			body_url = None

		if "media" in entry['entities']:
			media_url = entry['entities']['media'][0]['expanded_url']
			contains_media = 1
		else:
			media_url = None

	# checks for cve id in tweet body
	pattern = 'CVE-\d+-\d+'
	cve_mention = re.search(pattern, data)
	if cve_mention:
		cve_id = cve_mention.group(0)
	else:
		cve_id = None

	global dataframe_entry_dict
	dataframe_entry_dict = {} # to be nested into full_dict every call

	# create nested dict with selected fields
	dataframe_entry_dict["id"] = tweet_id
	dataframe_entry_dict["username"] = username
	dataframe_entry_dict["screenname"] = screenname
	dataframe_entry_dict['body'] = data
	dataframe_entry_dict["body_url"] = body_url
	dataframe_entry_dict["media_url"] = media_url
	dataframe_entry_dict["cve_id"] = cve_id

	# place entry dict into the full dictionary
	dataframe_full_dict[str(tweet_id)] = dataframe_entry_dict


def preprocess_tweet(entry):
	# extracts cve id (if any) and does text preprocessing on the tweet
	
	pattern = 'CVE-\d+-\d+'
	cve_mention = re.search(pattern, entry)

	if cve_mention:
		cve_id = cve_mention.group(0)
		print(cve_id)
		cve_list.append(cve_id)

	else:
		cve_id = None
		print("No ID found.")
		cve_list.append(cve_id)

	print("Entry: ")
	print(entry)
	# lowercases all text
	entry = entry.lower()
	# remove urls in the tweet body
	entry = re.sub("https://t.co/\w+","",entry)
	# remove symbols
	entry = re.sub("&lt;/?.*?&gt;"," &lt;&gt; ",entry)
	entry = re.sub("(\\d|\\W)+"," ",entry)

	return entry

def tokenize_tweet(entry):
	# uses spacy to convert the tweet string into a token object
	spacyTokens = nlp(entry)
	return spacyTokens

def remove_stops(entry):
	# removes stopwords from lemmatized tokens
	stopped = ' '.join([token.lemma_ for token in entry if not token.text in stops])
	return stopped

def process_cache(cachePath):
	# calls parser and processes parsed tweet fields

	with open(cachePath) as f:
		cacheData = json.load(f)

	dataframe_full_dict.clear()

	# loop thru cache, parse into dataframe_full_dict
	for key, entry in cacheData.items():
		pool.apply(parse_cache, args=(entry, ))

	# convert to a dictionary and flatten one layer 
	dict_to_convert = dict(dataframe_full_dict)
	dict_to_convert = dict_to_convert.values()

	entry_list = []

	# make a list of dicts to feed to pandas
	for entry in dict_to_convert:
		entry_list.append(entry)

	# make pandas dataframe
	tweet_dataframe = pd.DataFrame(entry_list)

	trainingEntryCount = 1

	# only process the main text portion of the tweet
	for content in tweet_dataframe['body']:
		print("{}.".format(trainingEntryCount))
		trainingEntryCount += 1

		# calls previous func to clean tweet
		processed_tweet = preprocess_tweet(content)
		tokens = tokenize_tweet(processed_tweet)
		stopped_tweet = remove_stops(tokens)

		print("\nProcessed entry: ")
		print(stopped_tweet)
		clean_tweetlist.append(stopped_tweet)
		print()

def label_data(tweet, cveid, label):
	# adds tweets to a df and labels each one
	
	#bar = ProgressBar(maxval=len(tweets)).start()	
	tweet_tuple = []
	tweet_tuple.append(tweet)
	tweet_tuple.append(label)
	tweet_tuple.append(cveid)

	tweet_tuple = tuple(tweet_tuple)
	return tweet_tuple

def plot_roc_curve(fpr, tpr, label=None):
	plt.figure(figsize=(8,6))
	plt.plot(fpr, tpr, linewidth=2, label=label)
	plt.plot([0,1],[0,1], "k--")
	plt.axis([0,1,0,1])
	plt.xlabel("False Positive Rate")
	plt.ylabel("True Positive rate")
	plt.show()


#                                MAIN PROGRAM SECTION

pool = multiprocessing.Pool(processes=4)

# create vectorizer and term freq transform
cv = CountVectorizer()
tfidf_transformer = TfidfTransformer(use_idf=True)

# specify JSON caches to open
random_cache = "/home/charles/Desktop/mongo-database/learning/datasets/cachefull_random_2018-12-26.json"
targeted_cache = "/home/charles/Desktop/mongo-database/learning/datasets/cachefull2018-12-26.json"

print("""
Random tweets: {}
Targeted tweets: {}
""".format(random_cache, targeted_cache))
print("""
Do what with the caches?

1. Load into new classifier
2. Train saved classifier
3. Stream and flag tweets
	""")

option = input("> ")
print()

if option == '1':
	print("Processing and labelling...")

	global clean_tweetlist
	clean_tweetlist = []

	global cve_list
	cve_list = []

	# processes and labels from random set
	tweets_labelled = []
	process_cache(random_cache)
	# appends tweet, cve id and label into a dataframe
	for tweet, cveid in zip(clean_tweetlist, cve_list):
		tweets_labelled.append(label_data(tweet, cveid, 0))
	
	col_names = ['tweet', 'label', 'cve_id']
	df_random_tweets = pd.DataFrame(tweets_labelled, columns=col_names)

	cve_list = []
	clean_tweetlist = []

	# processes and labels from targeted set
	tweets_labelled = []
	process_cache(targeted_cache)

	for tweet, cveid in zip(clean_tweetlist, cve_list):
		tweets_labelled.append(label_data(tweet, cveid, 1))

	df_targeted_tweets = pd.DataFrame(tweets_labelled, columns=col_names)
	print(df_random_tweets)
	print(df_targeted_tweets)

	# concats and shuffles the two frames
	frames = [df_random_tweets, df_targeted_tweets]
	df_combined = pd.concat(frames)
	df_combined = df_combined.sample(frac=1).reset_index(drop=True)

	# splits the shuffled dataset into training and testing sets
	x_train, x_test, y_train, y_test = train_test_split(df_combined['tweet'], df_combined['label'], test_size=0.15, shuffle=True)

	# define classifier (only do this once)
	tweet_classifier = Pipeline([('vect', CountVectorizer()),
	    ('tfidf', TfidfTransformer(use_idf=True)),
	    ('clf', LogisticRegression(solver='liblinear', random_state=1, class_weight='balanced', C=0.05, max_iter=5000)),])

	tweet_classifier.fit(x_train, y_train)
	predicted_labels = tweet_classifier.predict(x_test)
	print(tweet_classifier._final_estimator)

	# print scores/metrics
	result = tweet_classifier.score(x_test, y_test)
	print("Score: {}".format(result))
	balanced = balanced_accuracy_score(y_test.values, predicted_labels)
	print("Balanced accuracy score: {}".format(balanced))

	metrics_report = classification_report(y_test, predicted_labels)
	print(metrics_report)

	filename = '/home/charles/Desktop/mongo-database/learning/models/SGDModel.sav'
	joblib.dump(tweet_classifier, filename)
	print("Saved model.")

elif option == '2':

	# load the model from disk
	filename = '/home/charles/Desktop/mongo-database/learning/models/SGDModel.sav'
	loaded_model = joblib.load(filename)
	print("Loaded model from: {}".format(filename))

	# kfold
	skfold = StratifiedKFold(10, True, 1)

	print(loaded_model._final_estimator)
	cve_list = []
	clean_tweetlist = []

	# processes and labels from RANDOM set
	tweets_labelled = []
	process_cache(random_cache)
	# appends tweet, cve id and label into a dataframe
	for tweet, cveid in zip(clean_tweetlist, cve_list):
		tweets_labelled.append(label_data(tweet, cveid, 0))
	
	col_names = ['tweet', 'label', 'cve_id']
	df_random_tweets = pd.DataFrame(tweets_labelled, columns=col_names)

	cve_list = []
	clean_tweetlist = []
	
	# processes and labels from TARGETED set
	tweets_labelled = []
	process_cache(targeted_cache)

	for tweet, cveid in zip(clean_tweetlist, cve_list):
		tweets_labelled.append(label_data(tweet, cveid, 1))

	df_targeted_tweets = pd.DataFrame(tweets_labelled, columns=col_names)

	# concats and shuffles the two frames
	frames = [df_random_tweets, df_targeted_tweets]
	df_combined = pd.concat(frames)
	df_combined = df_combined.sample(frac=1).reset_index(drop=True)

	# splits the shuffled dataset into training and testing sets, fit data on to model
	x_train, x_test, y_train, y_test = train_test_split(df_combined['tweet'], df_combined['label'], test_size=0.15)
	loaded_model.fit(x_train, y_train)

	predicted_labels = loaded_model.predict(x_test)
	result = loaded_model.score(x_test, y_test)
	print("Score: {}".format(result))
	balanced = balanced_accuracy_score(y_test.values, predicted_labels)
	print("Balanced accuracy score: {}".format(balanced))

	metrics_report = classification_report(y_test, predicted_labels)
	print(metrics_report)

	# form split data back into x and y
	combinedTweet = df_combined['tweet'].values
	combinedLabels = df_combined['label'].values

	scores = cross_val_score(loaded_model, combinedTweet, combinedLabels, cv=skfold)
	print("Scores: {}".format(scores))
	print("Avg. score: {}".format(np.mean(scores)))
	predictions = cross_val_predict(loaded_model, combinedTweet, combinedLabels, cv=skfold)
	print()
	print(predictions)

	# use params from the pipeline
	logClf = loaded_model.get_params()['clf']
	vect = loaded_model.get_params()['vect']

	x_train_trans = vect.transform(x_train)
	x_test_trans = vect.transform(x_test)

	X_train_scaled = scale(x_train_trans, with_mean=False)
	X_test_scaled = scale(x_test_trans, with_mean=False)

	logClf.fit(X_train_scaled, y_train)
	log_scores_proba = logClf.predict_proba(X_test_scaled)
	print(log_scores_proba[:1,])
	print("AUC score: {}".format(roc_auc_score(y_test, log_scores_proba[:,1])))

	# true positive, false positive, thresholds
	fpr_log, tpr_log, thresh_log = roc_curve(y_test, log_scores_proba[:,1])
	plot_roc_curve(fpr_log, tpr_log)

	# save loaded model to file again
	joblib.dump(loaded_model, filename)
	print("Saved model.")

elif option == '3':
	# load the model from disk
	filename = '/home/charles/Desktop/mongo-database/learning/models/SGDModel.sav'
	loaded_model = joblib.load(filename)
	print("Loaded model from: {}".format(filename))

	# call twitterAPI_streamSample
	# sampleNo = 20
	# term = 'vulnerability'
	# filepath = pool.apply(download_sample, args=(sampleNo, term, ))

	# #filepath = download_sample(sampleNo, term)
	# print("{} samples downloaded to {}".format(sampleNo, filepath))

	clean_tweetlist = []
	tweet_list = []
	cve_list = []
	url_list = []
	id_list = []

	# USING A 30-DAY SAMPLE FOR TESTING
	process_cache('/home/charles/Desktop/mongo-database/learning/datasets/sampleset4.json')

	sample_dict = dict(dataframe_full_dict)
	sample_dict = sample_dict.values()

	# make list for id and urls
	for entry in sample_dict:
		url_list.append(entry['body_url'])
		id_list.append(entry['id'])
		tweet_list.append(entry['body'])

	# create tuple for inserting into pandas
	sample_list = []
	for id_no, clean_tweet, tweet, cveid, url in zip(id_list, clean_tweetlist, tweet_list, cve_list, url_list):
		tweet_tuple = []
		tweet_tuple.append(id_no)
		tweet_tuple.append(clean_tweet)
		tweet_tuple.append(tweet)
		tweet_tuple.append(cveid)
		tweet_tuple.append(url)
		tweet_tuple = tuple(tweet_tuple)
		sample_list.append(tweet_tuple)

	col_names = ['id', 'clean_tweet', 'tweet', 'cve_id', 'url']
	df_sample_tweets = pd.DataFrame(sample_list, columns=col_names)
	df_sample_tweets = df_sample_tweets.sample(frac=1).reset_index(drop=True)
	predicted_labels = loaded_model.predict(df_sample_tweets['tweet'])
	df_sample_tweets['predictions'] = predicted_labels

	# contains the info of processed tweet samples
	print(df_sample_tweets)
	
	flagged_list = []
	result = 0
	for row in df_sample_tweets.itertuples(index=False):
		if row.predictions == 1 or row.cve_id != None:
			# check to see if cve is in the db
			cve_search(row.cve_id)
			if result  == 1:
				print("CVE: ")

			# list of namedtuples
			flagged_list.append(row)
	
	flagged_df = pd.DataFrame.from_records(flagged_list, columns=df_sample_tweets.columns)
	tweets_to_insert = flagged_df.to_dict(orient='records')

	if len(tweets_to_insert) != 0:	
		flagged_tweets.insert_many(tweets_to_insert)
		print("Documents: {}".format(flagged_tweets.count()))
	else:
		print("No results.")

elif option == '4':
	# manually insert a tweet to check classifier
	
	filename = '/home/charles/Desktop/mongo-database/learning/models/SGDModel.sav'
	loaded_model = joblib.load(filename)
	print("Loaded model from: {}".format(filename))

	# vect = loaded_model.get_params()['vect']
	# print(vect.get_feature_names())

	print("Paste tweet to predict label.")
	tweetInput = input(">> ")
	tweet_toInsert = []
	tweet_toInsert.append(tweetInput)

	col_names = ['tweet']
	testTweet = pd.DataFrame(tweet_toInsert, columns=col_names)

	print()
	print(testTweet['tweet'])

	predicted_labels = loaded_model.predict(testTweet['tweet'])
	print(predicted_labels[0])


# stop timer and print program time
end = timer()
print("[Time elapsed: {}s]".format(end - start))

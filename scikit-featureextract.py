import spacy
import pandas as pd
import numpy as np
import itertools

import nltk
from nltk.corpus import stopwords

# nltk.download('punkt')
# nltk.download('wordnet')
# nltk.download('stopwords')

# prep
from sklearn import svm, preprocessing
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.pipeline import Pipeline

# models
from sklearn.linear_model import SGDClassifier
from sklearn.tree import DecisionTreeRegressor
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import cross_validate

stops = stopwords.words("english")
print("No. of stopwords: {}".format(len(stops)))

# spacy en core md on desktop folder
nlp = spacy.load("/home/charles/Desktop/en_core_web_md-2.0.0/en_core_web_md/en_core_web_md-2.0.0")
print("Spacy en_core loaded.")

def preprocess_tweet(entry):
	# callled in a loop to process each entry from a set
	
	# checks for cve id in tweet body
	pattern = 'CVE-\d+-\d+'
	cve_mention = re.search(pattern, entry)

	if cve_mention:
		cve_id = cve_mention.group(0)
		print(cve_id)
	else:
		print("No ID found.")

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

def sort_coo(coo_matrix):
	# sorts the coo matrix of the tfidf vector
	tuples = zip(coo_matrix.col, coo_matrix.data)
	return sorted(tuples, key=lambda x: (x[1], x[0]), reverse=True)

def extract_topn_from_vector(feature_names, sorted_items, topn=10):
	"""get the feature names and tf-idf score of top n items"""
	
	#use only topn items from vector
	sorted_items = sorted_items[:topn]
 
	score_vals = []
	feature_vals = []
	
	# word index and corresponding tf-idf score
	for idx, score in sorted_items:
		
		#keep track of feature name and its corresponding score
		score_vals.append(score)
		feature_vals.append(feature_names[idx])
 
	#create a tuples of feature,score
	results = zip(feature_vals,score_vals)
	results= {}
	for idx in range(len(feature_vals)):
		results[feature_vals[idx]]=score_vals[idx]
	
	return results

def feature_extraction(entry):
	cv = CountVectorizer(min_df=0.04)
	word_count_vector = cv.fit_transform(entry)
	
	tfidf_transformer = TfidfTransformer(use_idf=True, smooth_idf=True)
	tfidf_vector = tfidf_transformer.fit_transform(word_count_vector)

	print(list(cv.vocabulary_.keys())[:10])
	print(len(list(cv.vocabulary_)))

	feature_names = cv.get_feature_names()
	sorted_items = sort_coo(tfidf_vector.tocoo())
	keywords=extract_topn_from_vector(feature_names,sorted_items,10)

	print("\n===Keywords===")
	for k in keywords:
		print(k,keywords[k])

	return tfidf_vector

# specify training and testing pickle files

# x_training = pd.read_pickle('/home/charles/Desktop/mongo-database/learning/datasets/twitterset2018-12-03_training.pkl')
# x_testing = pd.read_pickle('/home/charles/Desktop/mongo-database/learning/datasets/twitterset2018-12-03_testing.pkl')


clean_tweetlist = []


# loops thru body of tweets in the TRAINING set
trainingEntryCount = 1

# only process the main text portion of the tweet
for content in x_training['body']:
	print("{}.".format(trainingEntryCount))
	trainingEntryCount += 1

	processed_tweet = preprocess_tweet(content)
	tokens = tokenize_tweet(processed_tweet)
	stopped_tweet = remove_stops(tokens)

	print("\nProcessed entry: ")
	print(stopped_tweet)
	clean_tweetlist.append(stopped_tweet)
	print()

training_tfidf = feature_extraction(clean_tweetlist)


# loops thru body of tweets in the TESTING set
testingEntryCount = 1

for content in x_testing['body']:
	print("{}.".format(testingEntryCount))
	testingEntryCount += 1

	processed_tweet = preprocess_tweet(content)
	tokens = tokenize_tweet(processed_tweet)
	stopped_tweet = remove_stops(tokens)

	print("\nProcessed entry: ")
	print(stopped_tweet)
	clean_tweetlist.append(stopped_tweet)
	print()

testing_tfidf = feature_extraction(clean_tweetlist)
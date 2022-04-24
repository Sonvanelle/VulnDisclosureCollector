from flask import Flask, jsonify, request
from flask_cors import CORS

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
from sklearn.externals import joblib
from timeit import default_timer as timer
from os.path import isfile, join
from urllib.request import urlopen


# load mongo client and establish collections
client = MongoClient('127.0.0.1', 27017)
db = client.pymongo_test
test_json_dump = db.test_json_dump
good_tweets = db.good_tweets
shellcode_dump = db.shellcode_dump
exploit_dump = db.exploit_dump
exploit_dump_copy = db.exploit_dump_copy
print("Connected to database.")

BOOKS = [
    {
        'title': 'On the Road',
        'author': 'Jack Kerouac',
        'read': True
    },
    {
        'title': 'Harry Potter and the Philosopher\'s Stone',
        'author': 'J. K. Rowling',
        'read': False
    },
    {
        'title': 'Green Eggs and Ham',
        'author': 'Dr. Seuss',
        'read': True
    }
]

# configuration
DEBUG = True

# instantiate the app
app = Flask(__name__)
app.config.from_object(__name__)

# enable CORS
CORS(app)

# sanity check route
@app.route('/ping', methods=['GET'])
def ping_pong():
    return jsonify('pong!')

@app.route('/books', methods=['GET', 'POST'])
def all_books():
    response_object = {'status': 'success'}
    if request.method == 'POST':
        post_data = request.get_json()
        BOOKS.append({
            'title': post_data.get('title'),
            'author': post_data.get('author'),
            'read': post_data.get('read')
        })
        response_object['message'] = 'Book added!'
    else:
        response_object['books'] = BOOKS
    return jsonify(response_object)


if __name__ == '__main__':
    app.run()
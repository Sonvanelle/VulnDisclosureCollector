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

url = "https://www.exploit-db.com/exploits/{}/".format(45942)
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

print(cve_box_text)

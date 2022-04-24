import os
import sys
import glob
import zipfile
import datetime
from urllib.request import urlopen

"""Run this program once to get the initial caches. Subsequent updates to the 
cache will be done with edb-update.py"""

datestr = datetime.date.today().strftime('%Y-%m-%d')
def download_shellcode():
	existingFile = glob.glob('/home/charles/Desktop/mongo-database/e-db/shellcode/*')
	for f in existingFile:
		os.remove(f)

	print("Downloading...")
	file = urlopen('https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_shellcodes.csv')
	dataToWrite = file.read()
	filePath = '/home/charles/Desktop/mongo-database/e-db/shellcode/shellcodes_' + datestr + '.csv'
	print("Downloaded {}".format(filePath))
	with open(filePath, 'wb') as f:
		f.write(dataToWrite)

def download_exploits():
	existingFile = glob.glob('/home/charles/Desktop/mongo-database/e-db/exploits/*')
	for f in existingFile:
		os.remove(f)

	print("Downloading...")
	file = urlopen('https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv')
	dataToWrite = file.read()
	filePath = '/home/charles/Desktop/mongo-database/e-db/exploits/exploits_' + datestr + '.csv'
	print("Downloaded {}".format(filePath))
	with open(filePath, 'wb') as f:
		f.write(dataToWrite)

download_shellcode()
download_exploits()
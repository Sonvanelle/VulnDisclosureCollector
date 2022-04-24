import os
import sys
import zipfile
import datetime
from urllib.request import urlopen
import multiprocessing

"""Script that downloads all previous years of the NVD JSON dumps."""

now = datetime.datetime.now()
start_year = 2002
end_year = now.year

def worker(year_num):
	print('Year:', year_num)
	#download files into folder, unzip and increment
	file = urlopen('https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-%i.json.zip' % year_num)
	dataToWrite = file.read()
	filePath = '/home/charles/Desktop/mongo-database/nvd-docs/' + str(year_num) + '-nvd.zip'
	with open(filePath, 'wb') as f:
		f.write(dataToWrite)
 
	with zipfile.ZipFile(filePath, "r") as zip_ref:
		zip_ref.extractall('/home/charles/Desktop/mongo-database/nvd-docs')
		print("Extracted " + filePath)
	os.remove(filePath)

jobs = []
for year in range(start_year, end_year+1):
	p = multiprocessing.Process(target=worker, args=(year,))
	jobs.append(p)
	p.start()



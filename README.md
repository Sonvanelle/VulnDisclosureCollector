# VulnDisclosureCollector
Polytechnic final-year project to make and maintain a database of publicly-disclosed vulnerabilities, classify and update them.


**1.1.Purpose**

The project objective is to create a suite of programs which retrieve and collate public
Linux vulnerability disclosures from sources such as the NVD, E-DB and posts on
Twitter. Public disclosures can be retracted or removed without any prior warning, either
by software vendors or by the author. This project aims to create and maintain a
persistent offline store of publicly-disclosed Linux vulnerabilities and PoC code samples.
Additionally, a Twitter crawler serves to keep the databases updated, if any new exploits
surface.

**1.2.Background Information**

The project was assigned by the Linux Security section of CSIT, responsible for
conducting vulnerability assessments and analysis of code written for the operating
system. Inspection of Linux code samples for vulnerabilities will require the use of public
vulnerability databases such as the CVE and NVD, as well as the Exploit Database.
Vulnerabilities can sometimes be disclosed without notifying the affected vendor
beforehand, and those posts may be taken down without warning, only being restored
after fixes rolled out.

Every entry in the NVD has a CVE ID number, and while exploits registered in the
Exploit Database are indexed according to their E-DB ID, a CVE identifier can be linked
to it as well, if the vulnerability has been successfully exploited.

**1.3.Scope**

The program suite builds and maintains a local database using public vulnerability
disclosures from the National Vulnerability Database, Exploit Database and posts from
Twitter. Entries will use the CVE ID for common identification.
Each public source offers an API, but the approaches used to pull data from them differ,
and as such, each source will have their own loading, parsing and updating scripts. The
data will be collated into a single database server.

**1.4.Requirements and Constraints**

The requirements for the final product are as follows:
● Build a database of vulnerability entries from NVD.
● Build a database of exploit code from E-DB.
● Build a database of tweets linking to vulnerabilities.
● Link associated vulnerabilities and exploits by their CVE ID.
● Update and revise entries non-destructively, ignore removals to source database.
● Crawl and index tweets pertaining to vulnerability disclosures, using a trained
classifier.
● Entries must be queryable using their IDs, or by code samples.
The constraints for the final project are as follows:
● Programs and scripts run natively on Linux.
● Archived data resides in an offline database.
● Web-based front-end for operating the scripts.


### 2. Design

**Program design and specifications**

**_Crawler and parser scripts (NVE and E-DB)_**

The chosen public sources have webpages which offer downloads of their most current
repository, and the program will download the files in either CSV or JSON format. The
NVD sources have heavily-nested JSON entries, and is flattened before selected fields
are parsed for each entry. If there is insufficient data or sources for the entry, the
program will skip the insert.

The E-DB raw files are in the CSV format, and both PoC and shellcode samples are
hosted on the Offensive Security Github repo. Certain exploits have CVEs associated
with them, but the CVE ID is not included in the entry files. The program crawls the
E-DB webpage associated with each entry (by ID) and navigates to the XPath element
corresponding with the displayed CVE ID (if any). After placing the crawled ID into its
field, the EDB ID and text will be indexed.

**_Updater scripts (NVE and E-DB)_**

NVE published ‘modified’ entries in a separate data cache file, including any repository
updates, so the program will download and parse the file with the same process. After
performing an ID check, if no date conflicts are detected, entries will be inserted or
updated.

To update E-DB entries, the entire repository is downloaded again, and a comparison
script is run on the two. The data will be segmented into additions, removals and
changes, and the appropriate actions will be done to the entries, barring removal.
Removed entries will remain in the local database, but will be marked with a ‘removed’
flag.


**_Non-relational databases for storage_**

A noSQL document-oriented database will be used for the archival of vulnerabilities and
storage of exploit code. Since data will be inserted from multiple sources, a schemaless
database allows for flexible storage and interoperability with different data models.
Additionally, document databases feature fast write performance owing to a lower
priority for data consistency. Document fields in the database can also be indexed for
easy querying and retrieval jobs.

**_Querying database items_**

To query the database for vulnerabilities or exploits, an end-user may enter the ID of the
entry, if known. Every vulnerability has its own unique CVE ID, while an exploit will have
an EDB ID indexed. A text index will be created from every exploit code sample, which
will allow for users to query the database by inserting a snippets of code.

**_Twitter classifier_**

Often enough, code samples are uploaded on, or linked to on the Twitter platform. A
binary classifier will be trained to identify tweets containing CVE and vulnerability
disclosures, based on their common vocabulary used. Training and testing sets will be
gathered using the Twitter Dev API. After training and evaluation of the classifier model,
tweets will be streamed as input into the classifier, and flagged tweets will be placed in
an interim database collection for review.

**_Review of flagged tweets_**

The amount of training data fed into the classifier is not expected to be sufficient for a
production program, and therefore flagged tweets are stored for a pending manual
review. Each tweet’s body text and attached links will be presented to the user, who will
either attach the tweet to an existing CVE entry, or discard it.


**Considerations on feasibility**

i. Technical

The program is compatible with most machines, as its underlying technologies (Python,
MongoDB, Solr) are cross platform, and the code can be run without any major
modifications for each operating system. However, a few servers and services must be
started before usage of the main functions, and kept running throughout. This may limit
performance on low-power machines, or slow down large operations. Additionally,
training the binary classifier with large amounts of data may cause slowdowns.
Database management is mostly automated and non-relational, but querying requires
knowledge of each collection’s indexes. Users training the classifier have to know how
to create appropriate datasets by querying the Twitter database, as well as understand
the classifier evaluation metrics.

ii. Financial

The program is designed to utilise free tools, and the entire program suite may be
operated in-house with the supplied documentation.
The use of Twitter’s free API set for classifier training will be adequate for most use
cases, but paid APIs are available. Paying for the APIs will allow for more
comprehensive training sets to be created with the larger pull limits.

iii. Operational practicalities

The final program would fulfill the requirements of having a updated source of CVE
vulnerabilities and linked exploit samples, all fully queryable. The vulnerability and
exploit entries would have to be updated with no conflict, and any deletions in the
source database should not be mirrored locally. However, the update programs must be
run manually and regularly, but if entries are found to be missing, a database refresh
should restore most entries, bar those deleted.
The final product is also designed to have a binary classifier, using a common keyword
corpus to label tweets related to vulnerability disclosures. Many public disclosures can
be discovered early as links on Twitter, posted by enthusiasts and information security
professionals. Once the vulnerability is identified, the tweet will be linked to its
corresponding CVE entry.

iv. Social and/or legal responsibilities

The final product is non-commercial and makes use of open-source libraries or
technologies under a free public license. The scraping and analysis of tweets will be
done with consent from Twitter, using an approved Twitter Developer account and
credentials. No tampering, probing and accessing of non-public content will be
conducted.

**Identifying disclosed vulnerabilities**

Topic modelling was considered as an approach to automate parsing of the vulnerability
itself, from the source page. Keywords would be created from the page contents, and
the model would determine the overall topic, and by extension the contents of the
disclosure. This approach required some commonality between the vocabularies and
semantic structure used by each source. With a larger number of sources, there would
be less shared vocabulary and text structure in their texts.
Since the differences between each source was so large, consistent topic predictions
across the many different sources cannot be easily made, and the feature was dropped.

**Feature selection from tweets**

In theory, the more retweets a post gets, the more interest there is concerning the
contents of the post. By taking tweets into account, a mutual information score can be
determined for the number of retweets and how probable the tweet may be an effective
disclosure.
However, there are easily cases of tweet disclosures which fail to gain traction, either
being posted by a relatively-unknown party, or due to inadequate tagging of the post.
These tweets may contain valid disclosures and other information about the subject, but
will receive less attention.

**Accounting for poster information**

Besides extracting body text and other data from a tweet, retrieving the information of
the tweet poster was also considered. The account age and how often they disclosed
vulnerabilities would be taken into account, and a mutual information (MI) score would
be calculated. This MI score (in nats) could determine the correlation between the
background of the poster, and the quality of the content being posted.

**Database**

A non-relational, document-oriented database was chosen to store vulnerability and
exploit data pulled from multiple sources. This database format aligns with the project
design requirements, allowing for flexible storage and high-performance write and query
jobs.
Certain shellcode and exploit samples are only available in binary format, and cannot be
stored natively in a document database (due to size limits). A grid file system (GridFS)
will chunk the binary file into smaller documents for storage, while still linking to the a
field in the main document.

Every CVE entry pulled from NVE’s public repo will be cleaned, with the exception of
important fields. The CVE ID is set as the unique index for the collection, for searching
and retrieval. Exploits from E-DB will be stored in a similar way after cleaning, and the
ID and PoC text will be indexed for use in searching.


### Implementation

NoSQL Database Management

A document-oriented database was chosen for its flexibility with different data models.
NoSQL databases can be designed schemaless, but consistency would make retrieval
and querying data easier. A soft schema was drafted up for each database collection,
with indexes being assigned to facilitate searching and to correlate documents across
collections. The data was also made as flat as possible, reducing the complexity of
query operations.


Scikit-learn Classifier Training

A binary classifier is used to filter out tweets containing vulnerability disclosures, or link
to proof-of-concepts. To know how to implement a classifier, the documentation must be
read for the scikit-learn machine learning framework, as well as the classifier algorithm
chosen. The proper training procedures have to be used for the binary classifier to
accurately sort contents, and to reduce false positives.

Python

Python offers extensibility due to a large module library, as well as offering native
compatibility with many existing technologies. This makes it easy to integrate
databases, services and interfaces with the program. Python modules are used to
facilitate access to MongoDB and the Solr search engine, as well as interact with the
Twitter API.
The high-level design of the language easily maintains code visibility throughout,
allowing the planned program structure to be followed closely. Mistakes in
implementation can also be reduced if the code is readable.

MongoDB

Mongo was selected as it was a document database which archived data in a JSON-like
format, which meant raw data required little to no translation before being stored. This
also ensured that stored objects may be easily called from Python code. With no strict
schema and entity-relationship model, document fields and database structure is more
flexible. The database was tolerant of the varying specifications found in
publically-sourced data, such as tweets.
The Pymongo module was used in the Python programs to establish database
connections, and let MongoDB queries be called directly from Python.

Apache Solr / Apache Lucene

was the search platform used to enable full-text searching on MongoDB fields. The
mongo-connector pipeline was used to connect Solr to MongoDB and index the data.
The Solr core is kept running throughout to ensure that any changes to Mongo will
reflect on the index. The pysolr module was used to query the Solr server and return the
output in a supported format. Implementation of Solr allows full text searching of the
exploit code samples contained in MongoDB.

mongo-connector

Enables a constant data stream from MongoDB to a target system. The pipeline service
is started after the database server is online. The service will mirror the MongoDB
oplog, so any changes made to the database will be reflected on the target system as
well.
The service is connected to the Solr server so it can receive the most current iteration of
the database to index for search.

**_Libraries used_**
The full list of Python modules and dependencies for this project will be listed in the
Appendix section.

TwitterAPI

The module served as a wrapper for Twitter’s REST and streaming APIs. After
registering for a developer account and API credentials, this module was called to
download tweets to build tweet datasets for supervised learning. It will return the API
output as Python objects, which can be easily formatted before inserting into the
classifier.

The streaming API was used to gather random tweets, which was fed to the classifier as
noise data. The search REST API function was called to selectively pull tweets, making
up the training set.

pandas

Pandas is a data analysis library which operates on time series and numerical table
objects. Its implementation in this project serves to convert data from the database into
a two-dimensional dataframe. Documents from MongoDB will be retrieved in their
BSON/JSON format and packed into an ordered dataframe. This dataframe structure is
easily read by many data analysis algorithms, and will be used to train and test the
machine learning classifier.

Scikit-learn

A Python library for machine learning containing data preprocessing modules, APIs for
estimator models, as well as metrics generators for model evaluation. C++ libraries
such as LibSVM and LibLinear are incorporated into the models as well. Scikit-learn’s
LinearRegression model was used to create the vulnerability disclosure classifier for
tweets.
The framework uses Python in its code and employs native libraries, such as numpy
and scipy for its algorithms. This makes it easy to interface with, as it natively accepts
pandas dataframes as input.

spaCy

The spaCy module is a natural language processing library. Its text processing functions
are called to prepare the raw text from the datasets for use in the classification model.
The spaCy model “‘en_core_web_md” was loaded to perform stopword removal and
lemmatization of each entry.


**3.2.Program Implementation**

**_Loading Data_**

The loader programs are meant to be run once, and will parse the data sources to
download the raw data feeds. The files are then unzipped and arranged in their folders
to be processed.

National Vulnerability Database (NVD)

The NVD publishes data feeds in CSV or JSON formats on their website sorted by year,
and changes made will be shown in a separate ‘CVE-modified’ feed. Links on the site
have their year in the URL, along with the data feed format. The program will parse the
links to retrieve the JSON feeds for every year of publishing, up to the current year.
Exploit Database (E-DB)

The Exploit Database archives the latest version of the repository on Github, which is
updated every few days. The archives are notably uploaded in CSV, and must be
converted to a JSON-type format later. The program will parse the
raw.githubusercontent.com link for the file and download it to a folder.


**Twitter Classifier Training & Testing_**

Using the scikit-learn cross_val_score module along with a k-fold iterator set to 10, the
dataset is shuffled and split into k groups. Each group is split into

1. Shuffle the dataset randomly.
2. Split the dataset into k groups
3. For each unique group:
    1. Take the group as a hold out or test data set
    2. Take the remaining groups as a training data set
    3. Fit a model on the training set and evaluate it on the test set
    4. Retain the evaluation score and discard the model
4. Summarize the skill of the model using the sample of model evaluation scores

**_Graphical User Interface_**

The primary interface for the final program suite is still the Python CLI, but a
JavaScript-based web interface was included to allow for easier querying and cleaner
display of results. The GUI uses Vue js and Flask to wrap around Python and display
the query results. Since the GUI is of a lower-priority, less polish was applied to that
portion of the software package, notably lacking any security features. The Solr query
server is only intended to be accessed by users on the local network.

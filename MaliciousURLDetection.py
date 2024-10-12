import pandas as pd
import matplotlib

import re
from googlesearch import search
from urllib.parse import urlparse
#import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn import svm
from sklearn import metrics
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, classification_report
from imblearn.over_sampling import SMOTE




# loading only the first 20000 rows of the dataset
df = pd.read_csv('/content/drive/MyDrive/DataSet_Data_Science/malicious_phish.csv', nrows=20000)
#Creating Dataframes for each URL type , [Phishing, Benign, Defacement, Malware]
phishing_URLs = df[df.type == 'phishing']
Benign_URLs = df[df.type == 'benign']
Defacement_URLs = df[df.type == 'defacement']
Malware_URLs = df[df.type == 'malware']


#Feature Engineering
#Creating new Features, or modifying existing ones to improve the model's performance
#The following features are created to improve the model's performance


#//////////////////////////////////////////////
#Feature 1: Use of IP Address
#A comman technique used in phishing is attacks is to use an IP address instead of a domain name
def contains_ip_address(url):
    #re , Regular Expression module is used to search for a pattern in the URL
    match = re.search(
        #so the ipv4 has 4 parts , each part in here is separated by a dot
        #let's take a look at the regular expression
        #([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\ , [01]?\\d\\d?, matches two digits, the first digit can be 0 or 1  and it's optional, the second digit can be any digit between 0-99
        #2[0-4]\\d, matches 200-249
        #25[0-5], matches 250-255
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'

        #IPv4 in hexadecimal
        #let's explain the regular expression
        #0x[0-9a-fA-F]{1,2}, matches 0x followed by 1 or 2 hexadecimal digits

        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'#this regular expression is used to match the ipv4 address in hexadecimal format

#for the ipv6 address, let's take a look at the regular expression
#(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}, matches 7 groups of 1-4 hexadecimal digits followed by a colon, and then 1-4 hexadecimal digits at the end of the string
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
#if it matches the pattern, return 1, else return 0
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0
#creates a new column in the dataframe, use_of_ip, which contains the result of the function, that is applied to each url in the dataframe

df['use_of_ip'] = df['url'].apply(lambda i: contains_ip_address(i))


# This feature can be extracted from the WHOIS database.
# For a legitimate website, identity is typically part of its URL.
def abnormal_url(url):
    #using the urlparse function from the urllib.parse module, to extract the hostname from the URL, so for exemple if we have the URL: https://www.google.com/search?q=python , the hostname is www.google.com
    hostname = urlparse(url).hostname
    #the hostname is converted to a string
    hostname = str(hostname)
    #search for the hostname in the URL
    #this function returns 1 if the hostname is found in the URL, else it returns 0
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0


df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))

#this function searches for the URL in the google search engine, if the URL is indexed by google, it returns 1, else it returns 0
def google_index(url):
    site = search(url, 5) # 5 is the number of results to search
    return 1 if site else 0


df['google_index'] = df['url'].apply(lambda i: google_index(i))

#Count . : The phishing or malware websites generally use more than two sub-domains in the URL. Each domain is separated by dot (.). If any URL contains more than three dots(.), then it increases the probability of a malicious site.
def count_dot(url):
    count_dot = url.count('.')
    return count_dot


df['count.'] = df['url'].apply(lambda i: count_dot(i))
df.head()

#the probability of a malicious site increases if the URL contains more that one www
def count_www(url):
    url.count('www')
    return url.count('www')


df['count-www'] = df['url'].apply(lambda i: count_www(i))

#http://www.google.com@phishingsite.com. A user might think they're going to www.google.com when they're actually going to phishingsite.com., because evertything before the @ is ignored
def count_atrate(url):
    return url.count('@')


df['count@'] = df['url'].apply(lambda i: count_atrate(i))

#number of directories
def no_of_dir(url):
    #parse the URL and extract the path , for exemple in the URL: https://www.google.com/search?q=python , the path is /search
    #the presence of more than 3 directories in the URL increases the probability of a malicious site
    urldir = urlparse(url).path
    return urldir.count('/')


df['count_dir'] = df['url'].apply(lambda i: no_of_dir(i))

#number of embedded domains
def no_of_embed(url):
    #The number of the embedded domains can be helpful in detecting malicious URLs. It can be done by checking the occurrence of “//” in the URL.
    urldir = urlparse(url).path
    return urldir.count('//')


df['count_embed_domian'] = df['url'].apply(lambda i: no_of_embed(i))


#Shortening services are used to create a short link of a long URL. The short link is easy to share and remember. The shortening services are used by spammers to hide the real URL. The shortening services are used to create a short link of a long URL. The short link is easy to share and remember. The shortening services are used by spammers to hide the real URL.
#The presence of shortening services in the URL increases the probability of a malicious site.
def shortening_service(url):
    match = re.search('bit\\.ly|goo\\.gl|shorte\\.st|go2l\\.ink|x\\.co|ow\\.ly|t\\.co|tinyurl|tr\\.im|is\\.gd|cli\\.gs|'
                  'yfrog\\.com|migre\\.me|ff\\.im|tiny\\.cc|url4\\.eu|twit\\.ac|su\\.pr|twurl\\.nl|snipurl\\.com|'
                  'short\\.to|BudURL\\.com|ping\\.fm|post\\.ly|Just\\.as|bkite\\.com|snipr\\.com|fic\\.kr|loopt\\.us|'
                  'doiop\\.com|short\\.ie|kl\\.am|wp\\.me|rubyurl\\.com|om\\.ly|to\\.ly|bit\\.do|t\\.co|lnkd\\.in|'
                  'db\\.tt|qr\\.ae|adf\\.ly|goo\\.gl|bitly\\.com|cur\\.lv|tinyurl\\.com|ow\\.ly|bit\\.ly|ity\\.im|'
                  'q\\.gs|is\\.gd|po\\.st|bc\\.vc|twitthis\\.com|u\\.to|j\\.mp|buzurl\\.com|cutt\\.us|u\\.bb|yourls\\.org|'
                  'x\\.co|prettylinkpro\\.com|scrnch\\.me|filoops\\.info|vzturl\\.com|qr\\.net|1url\\.com|tweez\\.me|v\\.gd|'
                  'tr\\.im|link\\.zip\\.net',
                                       url)
    if match:
        return 1
    else:
        return 0


df['short_url'] = df['url'].apply(lambda i: shortening_service(i))

#The presence of more than one “https” in the URL increases the probability of a malicious site.
def count_https(url):
    return url.count('https')


df['count-https'] = df['url'].apply(lambda i: count_https(i))

#The presence of more than one “http” in the URL increases the probability of a malicious site.
def count_http(url):
    return url.count('http')


df['count-http'] = df['url'].apply(lambda i: count_http(i))

#Count%: As we know URLs cannot contain spaces. URL encoding normally replaces spaces with symbol (%). Safe sites generally contain less number of spaces whereas malicious websites generally contain more spaces in their URL hence more number of %.
def count_per(url):
    return url.count('%')


df['count%'] = df['url'].apply(lambda i: count_per(i))

#Count?: The presence of symbol (?) in URL denotes a query string that contains the data to be passed to the server. More number of ? in URL definitely indicates suspicious URL.
def count_ques(url):
    return url.count('?')


df['count?'] = df['url'].apply(lambda i: count_ques(i))

#phishers generally use hyphens in their URLs to hide the actual domain name
def count_hyphen(url):
    return url.count('-')


df['count-'] = df['url'].apply(lambda i: count_hyphen(i))

#Count=: Presence of equal to (=) in URL indicates passing of variable values from one form page t another. It is considered as riskier in URL as anyone can change the values to modify the page.
def count_equal(url):
    return url.count('=')


df['count='] = df['url'].apply(lambda i: count_equal(i))

#url_length: Attackers generally use long URLs to hide the domain name. We found the average length of a safe URL is 74.
def url_length(url):
    return len(str(url))


# Length of URL
df['url_length'] = df['url'].apply(lambda i: url_length(i))


# Hostname Length
#also , the hostname length, is a good indicator of a malicious URL
def hostname_length(url):
    return len(urlparse(url).netloc)


df['hostname_length'] = df['url'].apply(lambda i: hostname_length(i))

df.head()

#Suspicious Words: Phishers generally use some specific words in their URLs to trick users. We have created a list of such words and if any URL contains these words, it is considered as a phishing URL.
def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr|secure|'
                      'verify|credential|validation|authenticate|wallet|payment|invoice|safety|protection|security',
                      url)
    if match:
        return 1
    else:
        return 0

df['sus_url'] = df['url'].apply(lambda i: suspicious_words(i))

#Count Digits: The presence of digits in the URL is a good indicator of a malicious URL
def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits


df['count-digits'] = df['url'].apply(lambda i: digit_count(i))

#Count_letters: The number of letters in the URL also plays a significant role in identifying malicious URLs. As attackers try to increase the length of the URL to hide the domain name and this is generally done by increasing the number of letters and digits in the URL.
def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters


df['count-letters'] = df['url'].apply(lambda i: letter_count(i))

def suspicious_tld(url):
    suspicious_tlds = ['xyz', 'online', 'tech', 'site', 'top', 'club', 'guru', 'loan']
    return 1 if urlparse(url).netloc.split('.')[-1] in suspicious_tlds else 0

df['suspicious_tld'] = df['url'].apply(lambda i: suspicious_tld(i))




def has_port(url):
    return 1 if urlparse(url).port else 0

df['has_port'] = df['url'].apply(lambda i: has_port(i))


import math

def entropy(url):
    s = urlparse(url).path.strip('/')
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    entropy = sum([(p * math.log(p) / math.log(2.0)) for p in prob])
    return entropy

df['url_entropy'] = df['url'].apply(lambda i: entropy(i))


df.head()


# First Directory Length
#The length of the first directory in the URL is a good indicator of a malicious URL
def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0


df['fd_length'] = df['url'].apply(lambda i: fd_length(i))

#The following code is used to encode the target variable, that is the type of the URL, to numerical values
df['type'].value_counts()

lb_make = LabelEncoder()
df["url_type"] = lb_make.fit_transform(df["type"])
df["url_type"].value_counts()

# Predictor Variables
# filtering out google_index as it has only 1 value
X = df[['use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@',
        'count_dir', 'count_embed_domian', 'short_url', 'count-https',
        'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length',
        'hostname_length', 'sus_url', 'fd_length', 'count-digits',
        'count-letters', 'suspicious_tld', 'has_port', 'url_entropy']]

# Target Variable
y = df['url_type']

print(df.head(3))

#SVM without resampling
print("/////////////////////////////////////////")

X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, shuffle=True, random_state=42)

# Create an SVM classifier

clf = svm.SVC(kernel='linear', probability=True)

# Train the classifier on the resampled training set
clf.fit(X_train, y_train)

# Predict on the test set
y_pred = clf.predict(X_test)

# Print the accuracy score of the classifier
print("SVM Accuracy:", metrics.accuracy_score(y_test, y_pred))

# Print the confusion matrix
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Print the classification report
print("Classification Report:")
print(classification_report(y_test, y_pred))

print("/////////////////////////////////////////")





#SVM with undersampling

print("/////////////////////////////////////////")
#from imblearn.under_sampling import RandomUnderSampler
#
## Initialize the undersampler
#undersample = RandomUnderSampler(sampling_strategy='majority')
#
## Fit and apply the transform
#X_under, y_under = undersample.fit_resample(X, y)
#
## Split the undersampled data into training and testing sets
#X_train, X_test, y_train, y_test = train_test_split(X_under, y_under, stratify=y_under, test_size=0.2, shuffle=True, random_state=42)
#

#clf = svm.SVC(kernel='linear', probability=True)
#clf.fit(X_train, y_train)
#y_pred = clf.predict(X_test)
#
#print("SVM Accuracy:", metrics.accuracy_score(y_test, y_pred))
#print("Confusion Matrix:")
#print(confusion_matrix(y_test, y_pred))
#print("Classification Report:")
#print(classification_report(y_test, y_pred))

print("/////////////////////////////////////////")



# Initialize Random Forest classifier
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42,class_weight='balanced')

# Fit the model to the training data
rf_classifier.fit(X_train, y_train)

# Predict on the test data
y_pred = rf_classifier.predict(X_test)

# Evaluate model performance
accuracy = rf_classifier.score(X_test, y_test)
print("Random Forest accuracy:", accuracy)
# Confusion Matrix
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Precision, Recall, F1 Score
print("Classification Report:")
print(classification_report(y_test, y_pred))


## Initialize XGBoost classifier
#xgb_classifier = xgb.XGBClassifier(learning_rate=0.1, max_depth=3, n_estimators=100)
#
## Fit the model to the training data
#xgb_classifier.fit(X_train, y_train)
#
## Predict on the test data
#y_pred_xgb = xgb_classifier.predict(X_test)
#
## Evaluate model performance
#accuracy = accuracy_score(y_test, y_pred_xgb)
#print("XGBoost accuracy:", accuracy)


from sklearn.tree import DecisionTreeClassifier
# Initialize Decision Tree classifier
print("/////////////////////////////////////////")
clf = DecisionTreeClassifier()
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)
# Evaluate model performance
accuracy_training = clf.score(X_train, y_train)
print("Decision Tree accuracy on training data:", accuracy_training)
accuracy = clf.score(X_test, y_test)
print("Decision Tree accuracy:", accuracy)

# Confusion Matrix
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Precision, Recall, F1 Score
print("Classification Report:")
print(classification_report(y_test, y_pred))
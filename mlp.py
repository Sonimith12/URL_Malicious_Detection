import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from tld import get_tld, is_tld
from urllib.parse import urlparse
import re
from sklearn.model_selection import train_test_split



data = pd.read_csv('../Dataset/malicious_phish.csv')

# data = pd.read_csv('malicious_phish.csv')
data.head(20)
# 
data.info()
# 
data.isnull().sum()
# 
count = data.type.value_counts()
count
# 
x=count.index
x
# 
sns.barplot(x=count.index, y=count)
plt.xlabel('Types')
plt.ylabel('Count')
# remove www. prefix from the column url
data['url'] = data['url'].replace('www.', '', regex=True)
data
# using ditionary in python to assign each key to the following value
rem = {"Category": {"benign": 0, "defacement": 1, "phishing":1, "malware":1}}
data['Category'] = data['type']
data = data.replace(rem)
data.head(20)
#using lambda function to calculate the length of each url
data['url_len'] = data['url'].apply(lambda x:len(str(x)))
data.head()
#this function extract domain
def process_tld(url):
    try:
        res = get_tld(url, as_object = True, fail_silently=False, fix_protocol=True)
        #extract domain name
        pri_domain = res.parsed_url.netloc
    except:
            pri_domain = None
    return pri_domain
#
data['domain'] = data['url'].apply(lambda i: process_tld(i))
#count these feature in url
feature = ['@','?','-','=','.','#','%','+','$','!','*',',','//']
for a in feature:
     data[a] = data['url'].apply(lambda i: i.count(a))
#
def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

data['abnormal_url'] = data['url'].apply(lambda i: abnormal_url(i))

sns.countplot(x='abnormal_url',data=data)

#check if the given url uses https protocol or not
def httpSecure(url):
    htp = urlparse(url).scheme 
    match = str(htp)
    if match=='https':
        return 1
    else: 
        return 0
data['https'] = data['url'].apply(lambda i: httpSecure(i))
#check if there are any numeric character or not in each url
def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits
data['digits']= data['url'].apply(lambda i: digit_count(i))
#check how many alphabet in each character
def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

data['letters']= data['url'].apply(lambda i: letter_count(i))

#check if the url contains shortening service
def Shortining_Service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0
    
data['Shortining_Service'] = data['url'].apply(lambda x: Shortining_Service(x))
#check if the given url has ip address or not
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
        '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url)  # Ipv6
    if match:
        return 1
    else:
        return 0
#check whether the url contains domain name or ip directly 
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
        '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url)  # Ipv6
    if match:
        return 1
    else:
        return 0
    
data['having_ip_address'] = data['url'].apply(lambda i: having_ip_address(i))
#
X = data.drop(['url','type','Category','domain'],axis=1)
y = data['Category']

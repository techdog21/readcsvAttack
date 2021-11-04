#injest a nessus csv file and produce a list of servers in the web.txt file that consists of the format
# http://webserver:port, then perform a EyeWitness scan of those systems.
#you need a nessus.csv file for this function.

import pandas as pd
import time
import subprocess
import time

st = 'http://'

# reading the CSV file
data = pd.read_csv('scan.csv')
# put data into a dataFrame to manage
df = pd.DataFrame(data, columns = ['Host','Protocol','Port','Name'])

# select only the names with HTTP
dataSubset = df[df['Name'].str.match('(HTTP)')]
# show all records
pd.set_option('display.max_rows', None)
# console out host and port
#x = print(dataSubset[['Host', 'Port']])
print("Building web.txt...")

#write data to text file for reading later
print(dataSubset[['Host', 'Port']].to_csv(r'web.txt', header='Host,Protocol,Port,Name', index=None, sep=':', mode='a'))
#sleep for a second to prevent a race condition
time.sleep(1)

st = "http://" #protocol start (st)
print ("Building attack.txt")

f = open("web.txt", "r")
for x in f: # read each entry from web.txt and throw it one at a time.
        #print (st + x.rstrip())    #print result to console
        with open("attack.txt", "a") as w: #print result to file
           print (st + x.rstrip(), file=w)

# check file for header on first line, and remove
with open('attack.txt', 'r') as fin:
        data = fin.read().splitlines(True)
with open('attack.txt', 'w') as fout:
        fout.writelines(data[1:])

# call eyewitness and run the file
subprocess.call(["eyewitness", "-f", "./attack.txt", "--web"])

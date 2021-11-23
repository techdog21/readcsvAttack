#injest a nessus csv file and produce a list of servers in the web.txt file that consists of the format
# http://webserver:port, then perform a EyeWitness scan of those systems.
#you need a nessus.csv file for this function.

#add commandline argument parsing
import argparse
#add pandas for basic data analytics parsing
import pandas as pd
#added for sleep function
import time
#added for subprocessing of new commands
import subprocess

#Argument Parser
parser = argparse.ArgumentParser(description='Options')
parser.add_argument("inputFile", type=str, help='filename of CSV to read for data')
parser.add_argument("searchTerm", type=str, help='search term to use (HTTP) example')
parser.add_argument('-e', '--EyewitnessAttack', action='store_true', help='Automatically run a Eyewitness Attack.')
parser.add_argument('-n', '--NiktoAttack', action='store_true', help='Automatically run a Nikto Attack.')
args = parser.parse_args()

def getIPPort( iFile, sTerm):
        # reading the CSV file
        data = pd.read_csv(iFile)
        # put data into a dataFrame to manage
        df = pd.DataFrame(data, columns = ['Host','Protocol','Port','Name'])
        # select only the names with various ports
        dataSubset = df[df['Name'].str.contains(sTerm)]
        # take only those that have 1 instance of the host.
        dataSubsetClean = df.drop_duplicates(subset=['Name'])
        # show all records
        pd.set_option('display.max_rows', None)
        # console out host and port
        #x = print(dataSubset[['Host', 'Port']])
        print("Building ipport.txt...")
        #write data to text file for reading later
        print(dataSubset[['Host', 'Port']].to_csv(r'ipport.txt', header='', index=None, sep=':', mode='w'))
        print(dataSubset[['Host']].to_csv(r'hosts.txt', header='', index=None, mode='w'))
        #sleep for a second to prevent a race condition
        time.sleep(1)

def eyeWitness():
        st = "http://" #protocol start (st)
        print ("Building webattack.txt")

        f = open("ipport.txt", "r")
        for x in f: # read each entry from web.txt and throw it one at a time.
                #print (st + x.rstrip())    #print result to console
                with open("webattack.txt", "a") as w: #print result to file
                        print (st + x.rstrip(), file=w)

        # call eyewitness and run the file
        # disubprocess.call(["eyewitness", "-f", "./attack.txt", "--web"])

# Main loop to identify what to do.
if args.EyewitnessAttack:
        print('\n\n----------------- Running Eyewitness --------------------')
        getIPPort(args.inputFile, args.searchTerm)
        eyeWitness()
else:
        print('\n\nGenerating IP Addresses...')
        getIPPort(args.inputFile, args.searchTerm)

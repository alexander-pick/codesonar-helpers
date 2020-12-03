#   Autobot (c) 2019 Alexander Pick

import glob
import sys
import os
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
import time
import subprocess
from pprint import pprint

files = glob.glob(sys.argv[1]+"/*")
projectname = sys.argv[2]
host = "127.0.0.1:7340"

url = "http://" + host + "/index.xml"

for file in files:

    poll = 1

    while(poll):
        try:
            baseurl = parsed_uri = urllib.parse.urlparse(url)
            root = ET.parse(urllib.request.urlopen(url)).getroot()

            projects = root.findall("project")

            #polling code
            isActive = 0
            currentState = ""
            
            for project in projects:
                state = project.find("state").text
                #print(state)
                if state not in { "Finished", "Stalled", "None"}:
                    isActive = 1
                    currentState = state
                    break
            if isActive == 0:
                print("queing.. "+file)
                break
            else:
                print("AUTOBOT: waiting... "+currentState)        
                time.sleep(150)
        except Exception as e:
            print(e)
            time.sleep(150)
            pass
                
    subprocess.Popen(r'"C:\Program Files\GrammaTech\CodeSonar\codesonar\bin\codesonar.exe" analyze '+projectname+' '+host+' cs-bin-scan '+file+' -use_ida yes -foreground -clean-backend', shell=True)
    time.sleep(150)
        
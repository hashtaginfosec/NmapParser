* This is an Nmap parser that is based on Python-libnmap. It takes XML (-oX) Nmap results and outputs a CSV file. <br>
* Requires Python3 and python-libnmap  --> `pip install python-libnmap` <br>
* Run in commandline: `python NmaptoCSV.py sourcefile.xml` <br>
* Once successfully run, it'll output <sourcefilename>.csv inside current directory. Best approach is to copy that csv file's data and paste into Excel. The data is tab delimited because Nmap output often contains commans, spaces, and semi-colons. 

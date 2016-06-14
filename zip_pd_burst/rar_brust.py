import rarfile
import argparse

parser = argparse.ArgumentParser(description='burst your zip')
parser.add_argument('-z', dest='zipname', action='store', required=True)
parser.add_argument('-d', dest='dicname', action='store', required=True)
zipname = parser.parse_args().zipname
dicname = parser.parse_args().dicname

with open(dicname) as a:
    dic = a.readlines()

zip = rarfile.RarFile(zipname)

for i in dic:
    i = i.replace('\n','')
    try:
        zip.extractall('/root/Desktop/',pwd=i)
        print 'get it' + i
        break
    except Exception,e:
        print i
        pass

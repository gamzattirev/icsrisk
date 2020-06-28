import mysql.connector
import const


file='192.168.2.txt'
src='192.168.5.89'

query="INSERT INTO packet(srcip,dstip,dstport,service)  values(%s,%s,%s,%s)"

conn = mysql.connector.connect(
    host='localhost',
    port='3306',
    user='root',
    password=const.password,
    database='ics'
)

cur = conn.cursor()

f = open(file)
lines = f.readlines()
for line in lines:
    #print(line)
    if 'Nmap scan report for' in line:
        ss=line.split(" ")
        dst=ss[len(ss)-1].strip()
        print(dst)


    elif 'open' in line:
        ss=line.split("/")
        port = ss[0]
        sss=ss[len(ss)-1]
        ssss=sss.split(" ")
        service=ssss[len(ssss)-1].strip()
        print(port+","+service)
        cur.execute(query, (src,dst,port,service))
        conn.commit()

cur.close()
conn.close()

f.close()
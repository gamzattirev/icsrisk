import csv
import mysql.connector
import glob
import const

inputdir='vul'
query="INSERT INTO vul(cve, cvss, ip_addr) VALUES (%s,%s,%s)"

conn = mysql.connector.connect(
    host='localhost',
    port='3306',
    user='root',
    password=const.password,
    database='ics'
)

cur = conn.cursor()

cve = ""
cvss=0
cvss_vect=""

attack_com=""
attack_vector=""
privilege=""
user_interact=""
availability=""
integrity=""
poc=False
type=""
ip_addr=""

files = glob.glob(inputdir + "/*.csv")
for file in files:
    with open(file, 'r') as file:
        reader = csv.reader(file)
        header = next(reader)
        for row in reader:
            try:
                ip_addr =row[15]
                cve = row[1]
                cvss = row[2]
                print(ip_addr,cve, cvss)

                cur.execute(query, (cve, cvss,ip_addr))
                conn.commit()

            except:
                import traceback
                traceback.print_exc()
                continue



cur.close()
conn.close()
file.close()
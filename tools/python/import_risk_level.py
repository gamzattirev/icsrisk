import csv
import mysql.connector
import vul_level

query="INSERT INTO risk_level(ip_addr,damage,vul,security,host) VALUES (%s,%s,%s,%s,%s)"

conn = mysql.connector.connect(
    host='localhost',
    port='3306',
    user='root',
    password='',
    database='ics'
)

cur = conn.cursor()
vulobj = vul_level.vul_level()

with open('risk_level.csv', 'r') as file:
    reader = csv.reader(file)
    header = next(reader)
    for row in reader:
        try:
            ip_addr = str(row[0]).strip()
            damage = str(row[1]).strip()
            security =str(row[2]).strip()
            host=str(row[3]).strip()
            vul = str(vulobj.get_vul_level_endpoint(ip_addr))
            print(ip_addr,damage,vul,security,host)

            cur.execute(query, (ip_addr,damage,vul,security,host))
            conn.commit()

        except:
            import traceback
            traceback.print_exc()
            continue


cur.close()
conn.close()
file.close()
import csv
import mysql.connector

query="INSERT INTO vul(cve, cvss, attack_com, attack_vector, privilege, user_interact, availability, integrity, type, ip_addr) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"

conn = mysql.connector.connect(
    host='localhost',
    port='3306',
    user='root',
    password='Gamzatti0301!',
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
ip_addr="192.168.20.5"

with open('vulnerabilities.csv', 'r') as file:
    reader = csv.reader(file)
    header = next(reader)
    for row in reader:
        try:
            cve = row[3]
            cvss = row[5]
            cvss_vect=row[13]

            cvss_vect_list=cvss_vect.split('/')


            attack_vector_list = cvss_vect_list[0].split(':')
            if len(attack_vector_list) >=2:
                attack_vector=attack_vector_list[1]

            attack_com_list = cvss_vect_list[1].split(':')
            if len(attack_com_list) >=2:
                attack_com=attack_com_list[1]

            privilege_list = cvss_vect_list[2].split(':')
            if len(privilege_list) >=2:
                privilege=privilege_list[1]

            user_interact_list = cvss_vect_list[3].split(':')
            if len(user_interact_list) >=2:
                user_interact=user_interact_list[1]

            integrity_list = cvss_vect_list[6].split(':')
            if len(integrity_list) >=2:
                integrity=integrity_list[1]

            availability_list = cvss_vect_list[7].split(':')
            if len(availability_list) >= 2:
                availability = availability_list[1]

            poc = False
            type = ""

            print(cve, cvss, attack_com, attack_vector, privilege, user_interact,
                                availability, integrity, poc, type, ip_addr)

            cur.execute(query, (cve, cvss, attack_com, attack_vector, privilege, user_interact,
                                availability, integrity,  type, ip_addr))
            conn.commit()

        except:
            import traceback
            traceback.print_exc()
            continue



cur.close()
conn.close()
file.close()
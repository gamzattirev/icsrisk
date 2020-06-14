import mysql.connector
import calc_risk

class vul_level:
    __query="select distinct cve from vul where ip_addr=%s and poc=1 and (attack_vector='N' or attack_vector='A') and rce=1 and privilege='N'"
    __query2 = "select distinct cve from vul where ip_addr=%s and poc=1 and (attack_vector='N' or attack_vector='A') and rce=1 and attack_com='L'"
    __query3 = "select distinct cve from vul where ip_addr=%s and poc=1 and (attack_vector='N' or attack_vector='A') and rce=1 and user_interact='N'"

    __query_endpoint1 = "select distinct cve from vul where ip_addr=%s and poc=1 and (attack_vector='N' or attack_vector='A') and availability='H'"
    __query_endpoint2 = "select distinct cve from vul where ip_addr=%s and poc=1 and (attack_vector='N' or attack_vector='A') and integrity='H'"

    __conn=None
    __cur =None

    def __init__(self):
        self.__conn = mysql.connector.connect(
            host='localhost',
            port='3306',
            user='root',
            password='',
            database='ics'
        )

        self.__cur = self.__conn.cursor()

    def __del__(self):
        self.__cur.close()
        self.__conn.close()


    def get_vul_level(self,ip_addr):
        self.__cur.execute(self.__query, (ip_addr,))
        rows = self.__cur.fetchall()
        level=len(rows)

        self.__cur.execute(self.__query2, (ip_addr,))
        rows = self.__cur.fetchall()
        level += len(rows)

        self.__cur.execute(self.__query3, (ip_addr,))
        rows = self.__cur.fetchall()
        level += len(rows)

        if level >=3:
            level=3
        elif level==None:
            level =0

        return level

    def get_vul_level_endpoint(self, ip_addr):
        self.__cur.execute(self.__query_endpoint1, (ip_addr,))
        rows = self.__cur.fetchall()
        level = len(rows)

        self.__cur.execute(self.__query_endpoint2, (ip_addr,))
        rows = self.__cur.fetchall()
        level += len(rows)

        if level >=3:
            level=3
        elif level == None:
            level = 0
        return level



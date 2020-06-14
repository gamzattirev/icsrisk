class vul:

    __cve = ""
    __cvss=0
    __attack_com=""
    __attack_vector=""
    __privilege=""
    __user_interact=""
    __availability=""
    __integrity=""
    __poc=False
    __type=""

    def __init__(self, cve, cvss, attack_com, attack_vector, privilege, user_interact, availability, integrity, poc, type):

        self.__cve = ""
        self.__cvss=0
        self.__attack_com=""
        self.__attack_vector=""
        self.__privilege=""
        self.__user_interact=""
        self.__availability=""
        self.__integrity=""
        self.__poc=False
        self.__type=""

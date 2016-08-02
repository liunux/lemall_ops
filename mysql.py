#coding:utf-8
import MySQLdb
import time,datetime
from datetime import datetime
from datetime import timedelta
import re
#from printColor import *
import json

work_path = '/root/linpeng/test/'

def query_db(sql):
    try:
        conn=MySQLdb.connect(host="10.130.84.211",port=3306,user="res_w",passwd="0Rl8Nxzvyc3kKaVe",db="ops_res",charset="utf8")
        cursor = conn.cursor()
        cursor.execute(sql)
        alldata = cursor.fetchall()
        cursor.close()
        conn.close()
        return alldata
    except Exception, e:
        print e

def modify_db(sql):
    try:
        conn=MySQLdb.connect(host="10.130.84.211",port=3306,user="res_w",passwd="0Rl8Nxzvyc3kKaVe",db="ops_res",charset="utf8")
        cursor = conn.cursor()
        n = cursor.execute(sql)
        conn.commit()
        cursor.close()
        conn.close()
        return n
    except Exception, e:
        print e

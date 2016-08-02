#coding:utf-8
import MySQLdb
import time,datetime
from datetime import datetime
from datetime import timedelta
import re
#from printColor import *
import json

work_path = '/Users/linpeng/test/'

def query_db(sql):
    try:
        conn=MySQLdb.connect(host="127.0.0.1",port=3306,user="root",passwd="",db="ops_res",charset="utf8")
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
        conn=MySQLdb.connect(host="127.0.0.1",port=3306,user="root",passwd="",db="ops_res",charset="utf8")
        cursor = conn.cursor()
        n = cursor.execute(sql)
        conn.commit()
        cursor.close()
        conn.close()
        return n
    except Exception, e:
        print e


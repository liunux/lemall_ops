#coding:utf-8
import MySQLdb
import time,datetime
from datetime import datetime
from datetime import timedelta
import re
#from printColor import *
import json

server_url = 'http://10.182.63.65:8002/'
gap = 3
work_path = '/root/linpeng/test/'

def query_db(sql):
    try:

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

        cursor = conn.cursor()
        n = cursor.execute(sql)
        conn.commit()
        cursor.close()
        conn.close()
        return n
    except Exception, e:
        print e

#coding:utf-8
import MySQLdb
import time,datetime
from datetime import datetime
from datetime import timedelta
import re
#from printColor import *
import json

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

class Online_run():
    def __init__(self,ip,dbname,port):
        #这里是port一定要int
        port=int(port)
        try:
#            self.conn = MySQLdb.connect(host='10.126.91.34', user='admin',passwd='njMCaruI8cpzyvxKkwna',db='vip_letv',port=3318,charset="utf8")
            self.conn = MySQLdb.connect(host=ip, user='admin',passwd='njMCaruI8cpzyvxKkwna',db=dbname,port=port,charset="utf8")
            self.cursor = self.conn.cursor()
        except Exception,e:
            pass

    def close(self):
        self.cursor.close()
        self.conn.close()

    def ceshi(self):
        self.cursor.execute('''show tables''')
        list_data = self.cursor.fetchall()
        return list_data


    def server_apply_check_user(self,user):
        self.cursor.execute('''select user,host from mysql.user where user = %s limit 1''',(user))
        list_data = self.cursor.fetchall()
        return list_data

    def server_apply_grants_update_sql(self,sql):
        #GRANT ALL PRIVILEGES ON `data_raw`.* TO 'data_raw_w'@'%' IDENTIFIED BY
        print_green(sql)
        self.cursor.execute(sql)
        self.conn.commit()
        return "ok"


    def server_apply_grants_update_w(self,user,host,dbname,passwd):
        #GRANT ALL PRIVILEGES ON `data_raw`.* TO 'data_raw_w'@'%' IDENTIFIED BY
        sql ='''GRANT select,insert,update,delete ON `%s`.* TO '%s'@'%s' IDENTIFIED BY '%s' '''%(dbname,user,host,passwd)
        print sql
        self.cursor.execute(sql)
        list_data = self.cursor.fetchall()
        return list_data

    def server_apply_grants_update_r(self,user,host,dbname,passwd):
        #GRANT ALL PRIVILEGES ON `data_raw`.* TO 'data_raw_w'@'%' IDENTIFIED BY
        sql ='''GRANT select ON `%s`.* TO '%s'@'%s' IDENTIFIED BY '%s' '''%(dbname,user,host,passwd)
        print sql
        self.cursor.execute(sql)
        list_data = self.cursor.fetchall()
        return list_data

    def server_apply_check_grants(self,user,host):
        sql = ''' show grants for '%s'@'%s' '''%(user,host)
        self.cursor.execute(sql)
        list_data = self.cursor.fetchall()
        return list_data

    def selectDb(self,db):
        try:
            self.conn.select_db(db)
        except MySQLdb.Error as e:
            print("Mysql Error %d: %s" % (e.args[0], e.args[1]))
            return "Mysql Error %d: %s" % (e.args[0], e.args[1])
        else:
            return "ok"

    def gorun(self,tosql):
        try:
            self.cursor.execute(tosql)
            self.conn.commit()
        except MySQLdb.Error, e:
            print "Error %d: %s" % (e.args[0], e.args[1])
            return "Error %d: %s" % (e.args[0], e.args[1])
        else:
            print self.conn.affected_rows()
            return 'ok'

    def gorun_rows(self,tosql):
        try:
            self.cursor.execute(tosql)
            rows = self.conn.affected_rows()
            self.conn.commit()
        except MySQLdb.Error, e:
            print "Error %d: %s" % (e.args[0], e.args[1])
            return "Error %d: %s" % (e.args[0], e.args[1])
        else:
            print rows
            return 'ok %s'%rows

#encoding:utf-8
from flask import request, redirect, url_for, abort
from mysql import *
import requests,json,urllib,urllib2,thread
import ssl,os,MySQLdb,sys,time,hashlib
from functools import wraps
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

reload(sys)
sys.setdefaultencoding('utf-8')



def test_login(fn):
    @wraps(fn)
    def wrapper():
        redirect_url = request.endpoint
        username = request.cookies.get('username',None)
        if username:
            nowtime = str(time.time())[0:10]
            url = 'http://sso.leshiren.cn:20008/user.php'
            tmp = "site=zhixin_portal&time="+nowtime+"&username="+username+"vfi7qc9jlpwk"
            m = hashlib.md5()
            m.update(tmp)
            sign = m.hexdigest()
            data = {}
            data['username'] = username
            data['site'] = "zhixin_portal"
            data['time'] = nowtime
            data['sign'] = sign
            post_data = urllib.urlencode(data)
            req=urllib2.urlopen(url, post_data).read()
            info = json.loads(req)
            nickname = info['objects']['nickname']
            # print nickname
            sql = 'select username from ops_user;'
            adminlist = query_db(sql)
            usertype = 'guest'
            for i in adminlist:
                if username in i:
                    usertype = 'admin'
            # print usertype
            listsql1 = 'select count(1) from ops_app_apply where developer="'+nickname+'" and status !="已完成"; '
            listnum1 = query_db(listsql1)[0][0]
            listsql2 = 'select count(1) from rel_apply where status = "待执行" or status = "已失败" and applyer = "'+nickname+'";'
            listnum2 = query_db(listsql2)[0][0]
            actionsql1 = 'select count(1) from ops_app_apply where status = "待执行";'
            actionnum1 = query_db(actionsql1)[0][0]
            actionsql2 = 'select count(1) from rel_apply where status = "待执行" or status = "已失败";'
            actionnum2 = query_db(actionsql2)[0][0]
            badge = {'list1':listnum1,'list2':listnum2,'action1':actionnum1,'action2':actionnum2}
            #print type(badge),badge
            return fn(usertype,nickname,badge)
        else:
            return redirect(url_for('login',redirect_url=redirect_url))
    return wrapper #登录状态验证 #登录状态验证

def test_admin(fn):
    @wraps(fn)
    def wrapper(usertype,nickname,badge):
        if usertype == 'admin':
            return fn(usertype,nickname,badge)
        else:
            return abort(403)
    return wrapper #管理员验证

#根据用户名查找leader名字和邮箱
def leader(username):
    nowtime = str(time.time())[0:10]
    http = 'http://sso.leshiren.cn:20008/user.php'
    tmp = "site=idc&time="+nowtime+"&username="+username+"dd9tikjed45glkyuyiudyter8"
    m = hashlib.md5()
    m.update(tmp)
    sign = m.hexdigest()
    data = {}
    data['username'] = username
    data['site'] = "idc"
    data['time'] = nowtime
    data['sign'] = sign
    post_data = urllib.urlencode(data)
    req=urllib2.urlopen(http, post_data).read()
    info = json.loads(req)
    p_nickname = info['objects']['p_nickname']
    p_email = info['objects']['p_email']
    return p_nickname,p_email

#添加删除IP后重新计算空机器和未知机器
def empty():
    esql = 'select app_id from ops_application where app_name="空机器";'
    eid = query_db(esql)[0][0]
    nsql = 'select app_id from ops_application where app_name="未知机器";'
    nid = query_db(nsql)[0][0]
    a = query_db('select count(1) from (select distinct ip from ops_instance)a ;')[0][0]
    b = query_db('select count(1) from ops_machine; ')[0][0]
    # print a,b,eid,nid

    modify_db('delete from ops_instance where app_id = '+str(eid)+' or app_id = '+str(nid)+' ;')
    modify_db('insert into ops_instance(app_id,ip,port,status) (select "'+str(eid)+'",in_ip,"","空" from ops_machine where in_ip not in (select ip from ops_instance));')
    modify_db('update ops_instance set app_id  =  '+str(nid)+', status = "未知" where ip in ("10.100.54.166","10.100.54.40","10.110.91.143","10.110.91.160","10.110.91.161","10.120.58.127","10.121.140.101","10.121.140.102","10.121.140.104","10.121.140.105","10.121.140.107","10.121.140.109","10.121.140.110","10.121.140.111","10.121.140.112","10.121.140.113","10.121.140.114","10.121.140.115","10.121.140.116","10.121.140.117","10.121.140.118","10.121.140.119","10.121.140.120","10.121.140.122","10.121.140.123","10.121.140.124","10.121.140.125","10.121.140.126","10.121.140.127","10.121.140.128","10.121.140.129","10.121.140.131","10.121.140.132","10.121.140.133","10.121.140.134","10.121.140.135","10.121.140.136","10.121.140.138","10.121.140.139","10.121.140.140","10.121.140.141","10.121.140.142","10.121.140.143","10.121.140.144","10.121.140.145","10.121.140.146","10.121.140.147","10.121.140.148","10.121.140.149","10.121.140.151","10.121.140.152","10.121.140.153","10.121.140.154","10.121.140.155","10.121.140.156","10.121.140.157","10.121.140.158","10.121.140.159","10.121.140.160","10.121.140.161","10.121.140.162","10.121.140.163","10.121.140.164","10.121.140.165","10.121.140.166","10.121.140.167","10.121.140.168","10.121.140.169","10.121.140.170","10.121.140.171","10.121.140.172","10.121.140.173","10.121.140.174","10.121.140.175","10.121.140.176","10.121.140.177","10.121.140.178","10.121.140.179","10.121.140.180","10.121.140.181","10.121.140.182","10.121.140.183","10.121.140.184","10.121.140.185","10.121.140.186","10.121.140.187","10.121.140.56","10.121.140.59","10.121.140.60","10.121.140.61","10.121.140.63","10.121.140.64","10.121.140.67","10.121.140.68","10.121.140.69","10.121.140.70","10.121.140.71","10.121.140.73","10.121.140.74","10.121.140.75","10.121.140.76","10.121.140.77","10.121.140.78","10.121.140.79","10.121.140.80","10.121.140.81","10.121.140.82","10.121.140.83","10.121.140.84","10.121.140.86","10.121.140.87","10.121.140.88","10.121.140.89","10.121.140.90","10.121.140.92","10.121.140.93","10.121.140.94","10.121.140.95","10.121.140.96","10.121.140.97","10.121.140.98","10.121.140.99","10.121.145.139","10.121.145.140","10.121.145.153","10.121.145.154","10.121.145.155","10.121.145.219","10.121.145.220","10.121.4.10","10.121.4.11","10.121.4.12","10.121.4.13","10.121.4.14","10.121.4.15","10.121.4.16","10.121.4.17","10.121.4.18","10.121.4.19","10.121.4.20","10.121.4.21","10.121.4.22","10.121.4.23","10.121.4.24","10.121.4.25","10.121.4.26","10.121.4.27","10.121.4.28","10.121.4.29","10.121.4.30","10.121.4.39","10.121.4.40","10.121.4.50","10.121.4.59","10.121.4.61","10.127.91.45","10.127.91.46","10.127.91.47","10.127.91.48","10.127.91.49","10.135.80.123","10.135.80.47","10.140.70.101","10.140.70.102","10.140.70.103","10.140.70.106","10.140.70.107","10.140.70.108","10.148.15.164","10.148.15.165","10.148.15.201","10.148.15.202","10.148.15.203","10.148.15.204","10.148.15.206","10.148.15.207","10.148.15.208","10.148.15.209","10.148.15.210","10.148.15.212","10.148.15.213","10.148.15.214","10.148.15.215","10.148.15.216","10.148.15.217","10.148.15.218","10.148.15.219","10.148.15.220","10.148.15.223","10.148.15.224","10.148.15.225","10.148.15.226","10.148.15.227","10.148.15.228","10.148.15.229","10.148.15.230","10.148.15.231","10.148.16.35","10.148.16.36","10.148.16.37","10.148.16.38","10.148.16.39","10.148.16.40","10.148.16.41","10.148.16.42","10.149.11.164","10.149.11.165","10.150.120.193","10.154.157.123","10.154.157.124","10.154.157.125","10.154.157.130","10.154.157.137","10.154.240.142","10.154.250.19","10.176.80.203","10.176.81.180","10.176.81.229","10.176.81.234","10.176.81.32","10.180.1.136","10.182.63.29","10.182.63.65","10.182.63.66","10.182.63.74") and app_id = '+str(eid)+';')

#登录验证ajax
# def ajax():
#     username=request.form['username']
#     password=request.form['password']
#     if password:
#          #print "password",password
#          http = "https://oauth.lecloud.com/nopagelogin?&ldap=true&username="+username+"&password="+password
#          d=requests.get('%s' % http).text
#          print d
#          info = json.loads(d)
#          #print type(info)
#          try:
#             if info['client_id']:
#                 redirect_to_index = redirect('/')
#                 resp = make_response(redirect_to_index)
#                 resp.set_cookie('username',value=username,max_age=36000)
#                 #return resp
#                 a='OK'
#                 return json.dumps(a)
#             else:
#                 resp='ERROR'
#                 return json.dumps(resp)
#          except:
#             resp='ERROR'
#             return json.dumps(resp)

def faban(id,nickname):
    modify_db('update rel_apply set status = "执行中" where id = '+str(id)+';')
    app_sql = "select app_id,svn,version from rel_apply where id = "+str(id)+";"
    app_id = query_db(app_sql)[0][0]
    app_name = query_db('select app_name from ops_application where app_id ='+str(app_id)+';')[0][0]
    app_svn = query_db(app_sql)[0][1]
    app_version = int(query_db(app_sql)[0][2])
    path = "/letv/svn_tmp/"+app_name
    result = os.system('rm -rf '+path+';mkdir -p '+path+';cd '+path+';svn export '+app_svn+' trunk')
    if result != 0:
        print "源码拉取失败!"
        status = 1
    else:

        conf_sql = "select conf_key,conf_value from rel_config where location = '香港';"
        conf_list = query_db(conf_sql)
        pom_list = []
        def search(path):
            for filename in os.listdir(path):
                fp = os.path.join(path, filename)
                if os.path.isfile(fp) and "pom.xml" in filename:
                    pom_list.append(fp)
                elif os.path.isdir(fp):
                    search(fp)
        search(path)
        result_list = []
        for i in conf_list:
            for n in pom_list:
                a = open(n).read()
                b = a.replace(">"+str(i[0])+"<",">![CDATA["+str(i[1])+"]]<")
                if a != b:
                    open(n,'w').write(b)
                    result = n+","+i[0]+","+i[1]
                    #print "#已替换:",app_name,n,i[0],i[1]
                    result_list.append(result)
        print "---已替换以下pom文件---"
        for i in result_list:
            print i
        to_svn = ' http://svn.letv.cn/lemall/ops/code/auto/hk/release/'+app_name+'/'+str(app_version)+'.war'
        make = os.system('cd '+path+'/trunk;mvn clean package -DskipTests')
        if make == 0:
            from_svn = os.popen('find '+path+' -name '+app_name+'.war').read()[0:-1]
            #print to_svn
            #print from_svn
            if from_svn:
                cmd = 'svn import --username zhangxing '+from_svn+to_svn+' -m "自动上传"'
                #print "#cmd:",cmd
                os.system(cmd)
                if app_version == 1:
                    #(status, output) = commands.getstatusoutput('cd /root/zhangxing/automate/publish.sh/;sh  publish.sh '+to_svn+' 1')
                    status = os.system('cd /root/zhangxing/automate/publish.sh/;sh  publish.sh '+to_svn+' 1')
                else:
                    #(status, output) = commands.getstatusoutput('cd /root/zhangxing/automate/publish.sh/;sh  publish.sh '+to_svn+' 2')
                    status = os.system('cd /root/zhangxing/automate/publish.sh/;sh  publish.sh '+to_svn+' 2')
                # print status
                if status != 0:
                    print "上传失败!"
                else:
                    print "上传成功!"
            else:
                status = 1
                print "找不到war包!"
        else:
            print "编译失败!"
    if status == 0:
        operate_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        print "发版成功!"
        modify_db('update rel_apply set status = "已完成",operate_time="'+operate_time+'",operator="'+nickname+'"  where id = '+str(id)+';')
        modify_db('update rel_operate set version = "'+str(app_version)+'",operator="'+nickname+'",operate_time="'+operate_time+'" where app_id='+str(app_id)+';')
    else:
        print "发版失败!"
        modify_db('update rel_apply set status = "待执行" where id = '+str(id)+';')
    thread.exit_thread()


def curl(method,ask,yes_id,nickname,app_id):
    url = server_url + method
    try:
        r = requests.post(url,data = ask)
        result = r.text
    except Exception, e:
        print "------",e
        result = e
    # print "#test-----:",r.text,method
    if method == "publish":
        operate_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

        svn = ask.get('app_svn', "ci")
        print "svn:",svn,type(svn)
        # version = svn.strip('/').split('/')[-1]
        version = query_db('select version from rel_apply where id = ' + str(yes_id)+';')[0][0]
        publishsql = 'select id from rel_publish where status like "%失败%" and rel_id = '+str(yes_id)+';'
        publishinfo = query_db(publishsql)
        print "--------:",result
        if result == "0" and not publishinfo:
            status = "已完成"
            ope_status = "成功"
            operate_note = ""
        else:
            status = "已失败"
            ope_status = "失败"
            if  "ConnectionError" in str(result):
                print "1"
                operate_note = "连接后端失败!"
            else:
                print "2"
                operate_note = ""
        print status,operate_note
        sql = 'update rel_apply set status = "'+status+'",operate_time="'+operate_time+'",operate_note = "'+operate_note+'",operator="'+nickname+'" where id = '+str(yes_id)+';'
        ope_sql = 'update rel_operate set status = "'+ope_status+'",version = "'+version+'",svn ="'+svn+'",operate_time="'+operate_time+'",operator="'+nickname+'" where app_id = '+str(app_id)+';'
        modify_db(ope_sql)
        modify_db(sql)
    thread.exit_thread()


#加密解密
class prpcrypt():
    def __init__(self, key):
        self.key = key
        self.mode = AES.MODE_CBC

    #加密函数，如果text不是16的倍数【加密文本text必须为16的倍数！】，那就补足为16的倍数
    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.key)
        #这里密钥key 长度必须为16（AES-128）、24（AES-192）、或32（AES-256）Bytes 长度.目前AES-128足够用
        length = 16
        count = len(text)
        add = length - (count % length)
        text = text + ('\0' * add)
        self.ciphertext = cryptor.encrypt(text)
        #因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        #所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)

    #解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.key)
        plain_text = cryptor.decrypt(a2b_hex(text))
        return plain_text.rstrip('\0')

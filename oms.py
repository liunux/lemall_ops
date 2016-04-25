#encoding:utf-8
from flask import Flask,app,request,render_template, redirect, url_for, session, abort,jsonify,make_response,send_from_directory,make_response
from mysql import *
import requests,json,urllib,urllib2
import ssl,os,MySQLdb,sys,time,hashlib
from functools import wraps
reload(sys)
sys.setdefaultencoding('utf-8')

app = Flask(__name__)

@app.route('/login',methods=['POST', 'GET']) #登录
def login():
    redirect_url = request.args.get('redirect_url','')
    if request.method == 'POST':
        try:
            username = request.form['username']
            redirect_url = request.form['redirect_url']
            url = 'https://oauthtest.lecloud.com/nopagelogin?&ldap=true'
            data = {}
            data['username'] = request.form['username']
            data['password'] = request.form['password']
            post_data = urllib.urlencode(data)
            req=urllib2.urlopen(url, post_data).read()
            #print req,type(req)
            #http = "https://oauth.lecloud.com/nopagelogin?&ldap=true&username="+username+"&password="+password
            #d=requests.get('%s' % http).text
            print req
            info = json.loads(req)
            if info['client_id']:
                print "###",redirect_url
                redirect_to_index = redirect(redirect_url)
                resp = make_response(redirect_to_index)
                resp.set_cookie('username',value=username,max_age=36000)
                return resp
            else:
                 return render_template('pages/login.html',redirect_url=redirect_url)
        except:
            result = "fail"
	    return render_template('pages/login.html',result=result,redirect_url=redirect_url)
    else:
        return render_template('pages/login.html',redirect_url=redirect_url)

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
            print nickname
            sql = 'select username from ops_user;'
            adminlist = query_db(sql)
            usertype = 'guest'
            for i in adminlist:
                if username in i:
                    usertype = 'admin'
            print usertype
            listsql = 'select count(1) from ops_app_apply where developer="'+nickname+'" and status !="已完成"; '
            listnum = query_db(listsql)[0][0]
            approvesql = 'select count(1) from ops_app_apply where  leader="'+nickname+'" and status = "待审批";'
            approvenum = query_db(approvesql)[0][0]
            actionsql = 'select count(1) from ops_app_apply where status = "待执行";;'
            actionnum = query_db(actionsql)[0][0]
            badge = {'list':listnum,'approve':approvenum,'action':actionnum}
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

@app.route('/logout',methods=['POST', 'GET']) #登出
def logout():
    redirect_to_index = redirect('/')
    resp = make_response(redirect_to_index)
    resp.delete_cookie('username')
    return resp

@app.route('/rbac') #权限管理
@test_login
@test_admin
def rbac(usertype,nickname,badge):
    user_add = request.args.get('user_add','')
    delid = request.args.get('id','')
    if delid:
        delsql = 'delete from ops_user where id ='+delid+';'
        modify_db(delsql)
        result = 4
    print delid
    print user_add
    if user_add:
        nowtime = str(time.time())[0:10]
        url = 'http://sso.leshiren.cn:20008/user.php'
        tmp = "site=zhixin_portal&time="+nowtime+"&username="+user_add+"vfi7qc9jlpwk"
        m = hashlib.md5()
        m.update(tmp)
        sign = m.hexdigest()
        data = {}
        data['username'] = user_add
        data['site'] = "zhixin_portal"
        data['time'] = nowtime
        data['sign'] = sign
        post_data = urllib.urlencode(data)
        req=urllib2.urlopen(url, post_data).read()
        info = json.loads(req)
        status = info['respond']['status']
        #nickname = info['objects']['nickname']
        if status == 0:
            result = 2
            print result
        elif status == 1:
            add_nickname = info['objects']['nickname']
            add_email = info['objects']['email']
            sql = 'insert into ops_user(username,nickname,email) values("'+user_add+'","'+add_nickname+'","'+add_email+'");'
            sql1 = 'select id from ops_user where username="'+user_add+'" and email="'+add_email+'"; '
            check = query_db(sql1)
            if check:
                result = 3
            else:
                insert = modify_db(sql)
                result = 1
            #print sql
            #n = modify_db(sql)
    allsql = 'select * from ops_user;'
    allinfo = query_db(allsql)
    return render_template('pages/rbac.html',**locals())

@app.route('/') #主页
@app.route('/index')
@test_login
def index(usertype,nickname,badge):
    return render_template('pages/index.html',**locals())

@app.route('/cmdb')
@test_login
@test_admin
def cmdb(usertype,nickname,badge):
    word =  request.args.get('word','')
    if word:
        infosql = "select sn,brand,hardmodel,system,idc,cabinet,onlineDate,out_ip,in_ip,cpu,mem,disk from ops_machine where idc like '%"+word+"%' or out_ip like '%"+word+"%' or in_ip like '%"+word+"%';"
    else:
        infosql = "select sn,brand,hardmodel,system,idc,cabinet,onlineDate,out_ip,in_ip,cpu,mem,disk from ops_machine limit 50;"
    info = query_db(infosql)
    total = query_db("select count(1) from ops_machine;")[0][0]
    kvm = query_db("select count(1) from ops_machine where hardmodel like '%VM%';")[0][0]
    others = total - kvm
    print total,kvm
    kvmp = kvm * 100 / total
    print kvmp
    othersp = 100 - kvmp

    cn_w = query_db("select count(1) from ops_machine where idc like '%北京%' and hardmodel not like '%VM%';")[0][0]
    cn_v = query_db("select count(1) from ops_machine where idc like '%北京%' and hardmodel like '%VM%';")[0][0]
    hk_w = query_db("select count(1) from ops_machine where idc like '%香港%' and hardmodel not like '%VM%';")[0][0]
    hk_v = query_db("select count(1) from ops_machine where idc like '%香港%' and hardmodel like '%VM%';")[0][0]
    us_w = query_db("select count(1) from ops_machine where idc like '%美国%' and hardmodel not like '%VM%';")[0][0]
    us_v = query_db("select count(1) from ops_machine where idc like '%美国%' and hardmodel like '%VM%';")[0][0]
    sg_w = query_db("select count(1) from ops_machine where idc like '%新加坡%' and hardmodel not like '%VM%';")[0][0]
    sg_v = query_db("select count(1) from ops_machine where idc like '%新加坡%' and hardmodel like '%VM%';")[0][0]
    in_w = query_db("select count(1) from ops_machine where idc like '%印度%' and hardmodel not like '%VM%';")[0][0]
    in_v = query_db("select count(1) from ops_machine where idc like '%印度%' and hardmodel like '%VM%';")[0][0]

    return render_template('pages/cmdb.html',**locals()) #cmdb

def empty():
    esql = 'select app_id from ops_application where app_name="空机器";'
    eid = query_db(esql)[0][0]
    nsql = 'select app_id from ops_application where app_name="未知机器";'
    nid = query_db(nsql)[0][0]
    a = query_db('select count(1) from (select distinct ip from ops_instance)a ;')[0][0]
    b = query_db('select count(1) from ops_machine; ')[0][0]
    print a,b,eid,nid

    modify_db('delete from ops_instance where app_id = '+str(eid)+' or app_id = '+str(nid)+' ;')
    modify_db('insert into ops_instance(app_id,ip,port,status) (select "'+str(eid)+'",in_ip,"","空" from ops_machine where in_ip not in (select ip from ops_instance));')
    print "1"
    modify_db('update ops_instance set app_id  =  '+str(nid)+', status = "未知" where ip in ("10.100.54.166","10.100.54.40","10.110.91.143","10.110.91.160","10.110.91.161","10.112.28.21","10.112.28.23","10.112.29.155","10.112.29.156","10.112.29.157","10.112.29.161","10.112.29.166","10.112.29.168","10.112.29.169","10.112.29.170","10.112.80.110","10.112.80.147","10.112.80.152","10.112.80.154","10.112.80.155","10.112.80.156","10.112.80.157","10.112.80.158","10.112.80.161","10.112.80.167","10.112.80.171","10.112.80.172","10.112.80.177","10.112.80.181","10.112.80.184","10.112.80.185","10.112.80.187","10.112.80.188","10.112.80.192","10.112.80.193","10.112.80.203","10.112.80.209","10.112.80.54","10.112.80.59","10.112.80.80","10.112.81.1","10.112.81.153","10.112.81.157","10.112.81.158","10.112.81.162","10.112.81.178","10.112.81.90","10.112.81.92","10.112.81.93","10.112.81.94","10.112.81.96","10.112.81.98","10.112.82.11","10.112.82.12","10.112.82.13","10.112.82.14","10.112.82.15","10.112.82.158","10.112.82.161","10.112.82.162","10.112.82.163","10.112.82.164","10.112.82.166","10.112.82.167","10.112.82.168","10.112.82.169","10.112.82.17","10.112.82.170","10.112.82.171","10.112.82.173","10.112.82.175","10.112.82.177","10.112.82.178","10.112.82.179","10.112.82.18","10.112.82.180","10.112.82.181","10.112.82.182","10.112.82.183","10.112.82.184","10.112.82.185","10.112.82.186","10.112.82.187","10.112.82.188","10.112.82.189","10.112.82.19","10.112.82.190","10.112.82.191","10.112.82.192","10.112.82.194","10.112.82.196","10.112.82.2","10.112.82.20","10.112.82.200","10.112.82.203","10.112.82.214","10.112.82.215","10.112.82.218","10.112.82.227","10.112.82.228","10.112.82.23","10.112.82.24","10.112.82.25","10.112.82.26","10.112.82.3","10.112.82.5","10.112.82.6","10.112.82.7","10.112.82.8","10.112.82.9","10.112.83.105","10.112.83.111","10.112.83.121","10.112.83.137","10.112.83.142","10.112.83.148","10.112.83.155","10.112.83.156","10.112.83.160","10.112.83.178","10.112.83.99","10.120.14.86","10.120.14.96","10.120.16.200","10.120.34.165","10.120.34.166","10.120.34.171","10.120.34.174","10.120.34.178","10.120.34.182","10.120.34.183","10.120.34.187","10.120.34.188","10.120.34.194","10.120.34.196","10.120.34.201","10.120.34.204","10.120.34.211","10.120.34.213","10.120.34.219","10.120.34.221","10.120.34.224","10.120.34.225","10.120.34.229","10.120.34.239","10.120.34.240","10.120.34.244","10.120.34.245","10.120.34.254","10.120.35.0","10.120.35.10","10.120.35.104","10.120.35.105","10.120.35.113","10.120.35.119","10.120.35.121","10.120.35.122","10.120.35.129","10.120.35.135","10.120.35.14","10.120.35.140","10.120.35.146","10.120.35.153","10.120.35.156","10.120.35.16","10.120.35.160","10.120.35.162","10.120.35.163","10.120.35.167","10.120.35.170","10.120.35.175","10.120.35.178","10.120.35.2","10.120.35.24","10.120.35.27","10.120.35.28","10.120.35.29","10.120.35.32","10.120.35.35","10.120.35.45","10.120.35.46","10.120.35.48","10.120.35.57","10.120.35.65","10.120.35.68","10.120.35.69","10.120.35.7","10.120.35.73","10.120.35.76","10.120.35.81","10.120.35.84","10.120.35.88","10.120.35.95","10.120.35.97","10.120.58.127","10.120.9.101","10.120.9.102","10.121.140.101","10.121.140.102","10.121.140.104","10.121.140.105","10.121.140.106","10.121.140.107","10.121.140.109","10.121.140.110","10.121.140.111","10.121.140.112","10.121.140.113","10.121.140.114","10.121.140.115","10.121.140.116","10.121.140.117","10.121.140.118","10.121.140.119","10.121.140.120","10.121.140.122","10.121.140.123","10.121.140.124","10.121.140.125","10.121.140.126","10.121.140.127","10.121.140.128","10.121.140.129","10.121.140.130","10.121.140.131","10.121.140.132","10.121.140.133","10.121.140.134","10.121.140.135","10.121.140.136","10.121.140.137","10.121.140.138","10.121.140.139","10.121.140.140","10.121.140.141","10.121.140.142","10.121.140.143","10.121.140.144","10.121.140.145","10.121.140.146","10.121.140.147","10.121.140.148","10.121.140.149","10.121.140.151","10.121.140.152","10.121.140.153","10.121.140.154","10.121.140.155","10.121.140.156","10.121.140.157","10.121.140.158","10.121.140.159","10.121.140.160","10.121.140.161","10.121.140.162","10.121.140.163","10.121.140.164","10.121.140.165","10.121.140.166","10.121.140.167","10.121.140.168","10.121.140.169","10.121.140.170","10.121.140.171","10.121.140.172","10.121.140.173","10.121.140.174","10.121.140.175","10.121.140.176","10.121.140.177","10.121.140.178","10.121.140.179","10.121.140.180","10.121.140.181","10.121.140.182","10.121.140.183","10.121.140.184","10.121.140.185","10.121.140.186","10.121.140.187","10.121.140.56","10.121.140.59","10.121.140.60","10.121.140.61","10.121.140.62","10.121.140.63","10.121.140.64","10.121.140.65","10.121.140.67","10.121.140.68","10.121.140.69","10.121.140.70","10.121.140.71","10.121.140.72","10.121.140.73","10.121.140.74","10.121.140.75","10.121.140.76","10.121.140.77","10.121.140.78","10.121.140.79","10.121.140.80","10.121.140.81","10.121.140.82","10.121.140.83","10.121.140.84","10.121.140.86","10.121.140.87","10.121.140.88","10.121.140.89","10.121.140.90","10.121.140.92","10.121.140.93","10.121.140.94","10.121.140.95","10.121.140.96","10.121.140.97","10.121.140.98","10.121.140.99","10.121.145.139","10.121.145.140","10.121.145.153","10.121.145.154","10.121.145.155","10.121.145.219","10.121.145.220","10.121.4.10","10.121.4.11","10.121.4.12","10.121.4.13","10.121.4.14","10.121.4.15","10.121.4.16","10.121.4.17","10.121.4.18","10.121.4.19","10.121.4.20","10.121.4.21","10.121.4.22","10.121.4.23","10.121.4.24","10.121.4.25","10.121.4.26","10.121.4.27","10.121.4.28","10.121.4.29","10.121.4.30","10.121.4.39","10.121.4.40","10.121.4.50","10.121.4.59","10.121.4.61","10.127.91.45","10.127.91.46","10.127.91.47","10.127.91.48","10.127.91.49","10.127.91.50","10.127.91.51","10.127.91.52","10.127.91.53","10.127.91.54","10.127.91.55","10.127.91.56","10.127.91.57","10.127.91.58","10.127.91.59","10.135.80.123","10.135.80.47","10.135.80.66","10.135.80.97","10.140.36.24","10.140.36.25","10.140.45.107","10.140.45.108","10.140.45.121","10.140.45.122","10.140.45.71","10.140.45.72","10.140.45.87","10.140.45.88","10.140.70.101","10.140.70.102","10.140.70.103","10.140.70.106","10.140.70.107","10.140.70.108","10.148.15.164","10.148.15.165","10.148.15.201","10.148.15.202","10.148.15.203","10.148.15.204","10.148.15.206","10.148.15.207","10.148.15.208","10.148.15.209","10.148.15.210","10.148.15.211","10.148.15.212","10.148.15.213","10.148.15.214","10.148.15.215","10.148.15.216","10.148.15.217","10.148.15.218","10.148.15.219","10.148.15.220","10.148.15.223","10.148.15.224","10.148.15.225","10.148.15.226","10.148.15.227","10.148.15.228","10.148.15.229","10.148.15.230","10.148.15.231","10.148.16.35","10.148.16.36","10.148.16.37","10.148.16.38","10.148.16.39","10.148.16.40","10.148.16.41","10.148.16.42","10.149.11.164","10.149.11.165","10.149.11.220","10.149.11.221","10.150.120.193","10.150.150.65","10.150.150.66","10.150.150.78","10.150.150.79","10.150.150.80","10.154.157.123","10.154.157.124","10.154.157.125","10.154.157.130","10.154.157.131","10.154.157.137","10.154.240.142","10.154.250.19","10.154.252.119","10.154.80.15","10.154.80.158","10.154.80.16","10.154.80.17","10.154.80.18","10.154.80.190","10.154.80.201","10.154.80.217","10.154.80.69","10.154.81.14","10.154.81.156","10.154.81.164","10.154.81.167","10.154.81.185","10.154.81.189","10.154.81.19","10.154.81.193","10.154.81.194","10.154.81.197","10.154.81.201","10.154.81.252","10.154.81.40","10.154.81.42","10.154.81.86","10.154.82.15","10.154.82.202","10.154.82.203","10.154.82.204","10.154.82.205","10.154.82.206","10.154.82.207","10.154.82.208","10.154.82.209","10.154.82.210","10.154.82.211","10.154.82.212","10.154.82.213","10.154.82.214","10.154.82.215","10.154.82.216","10.154.82.238","10.154.82.239","10.154.82.24","10.154.82.240","10.154.82.241","10.154.82.243","10.154.83.154","10.176.80.203","10.176.80.217","10.176.80.225","10.176.80.54","10.176.80.58","10.176.81.108","10.176.81.180","10.176.81.229","10.176.81.234","10.176.81.32","10.176.81.79","10.180.1.136","10.180.91.71","10.182.63.25","10.182.63.29","10.182.63.65","10.182.63.66","10.182.63.74","10.183.92.68","10.183.92.69","10.183.92.70","10.183.92.71","10.183.92.72","10.183.92.73","10.183.92.74","10.183.92.75","10.183.92.76","10.183.92.77","10.183.92.78","10.183.92.79","10.183.92.80","10.183.92.81","10.183.92.82","10.183.92.83","10.183.92.84","10.183.92.85","10.183.92.86","10.183.92.87","10.185.28.117","10.185.28.164","10.185.28.214","10.185.28.253","10.185.29.0","10.185.29.108","10.185.29.137","10.185.29.158","10.185.29.47","10.185.29.87") and app_id = '+str(eid)+';')
@app.route('/app_list',methods=['POST', 'GET']) #服务列表
@test_login
def app_list(usertype,nickname,badge):
    location = request.args.get('location','大陆')
    env =  request.args.get('env','生产')
    terminal =  request.args.get('terminal','%')
    word =  request.args.get('word','')
    word1 =  request.args.get('word','')
    mohu = request.args.get('mohu','')
    de_id = request.args.get('de_id','')
    app_num = query_db("select count(1) from ops_application  where  location like '"+location+"' and env like '"+env+"';")[0][0]
    mac_num = query_db("select count(1) from (select ip from ops_application a,ops_instance b where a.app_id=b.app_id and  location like '"+location+"' and env like '"+env+"' group by ip) a;")[0][0]
    ins_num = query_db("select count(1) from ops_application a,ops_instance b where a.app_id=b.app_id and  location like '"+location+"' and env like '"+env+"';")[0][0]
    #print location,env,app_num,mac_num,ins_num
    if de_id and usertype == 'admin':
        deleteappsql = 'delete from ops_application where app_id = '+de_id+'; '
        modify_db(deleteappsql)
        deleteinssql = 'delete from ops_instance where app_id = '+de_id+'; '
        modify_db(deleteinssql)
        qw = empty()
        result = "ok"
    if mohu:
        word = '%'+word+'%'
    if word:
        applicationsql = "select a.*,count(b.app_id) from ops_application a,ops_instance b where a.app_id=b.app_id and location " \
                         "like '"+location+"' and env like '"+env+"' and terminal like '"+terminal+"' and (app_name like '"+word+"'" \
                         " or developer like '"+word+"' or ip like '"+word+"' or b.status like '"+word+"') group by app_name,location,env,terminal order by location,app_name,env,terminal;"
        #print applicationsql
    elif usertype == 'admin':
        applicationsql = "select a.*,count(b.app_id) from ops_application a,ops_instance b where a.app_id=b.app_id and  location " \
                     "like '"+location+"' and env like '"+env+"' and terminal like '"+terminal+"' group by app_name,location,env,terminal order by location,app_name,env,terminal limit 20;"
        #print applicationsql
    elif usertype == 'guest':
        applicationsql = "select a.*,count(b.app_id) from ops_application a,ops_instance b where a.app_id=b.app_id group by app_name,location,env,terminal order by location,app_name,env,terminal;"
    applicationinfo = query_db(applicationsql)
    machinesql = "select app_id,idc,count(1) from ops_instance a,ops_machine b where ip=in_ip  group by app_id,idc;"
    machineinfo = query_db(machinesql)
    instancesql = "select app_id,idc,ip,port,cpu,mem,disk,status from ops_instance a,ops_machine b  where ip=in_ip order by ip;"
    instanceinfo = query_db(instancesql)
    gnginxsql = "select ngx_gname,vip,count(1),ngx_id from ops_nginx  group by ngx_gname,vip;"
    gnginxinfo = query_db(gnginxsql)
    nginxsql = "select vip,ip,status from ops_nginx;"
    nginxinfo = query_db(nginxsql)


    return render_template('pages/app_list.html',**locals())

@app.route('/app_update',methods=['POST', 'GET']) #服务修改
@test_login
def app_update(usertype,nickname,badge):
    username = request.cookies.get('username')
    app_id = request.args.get('app_id','')
    app_name = request.values.get('app_name','')
    location = request.values.get('location','')
    env = request.values.get('env','')
    terminal = request.values.get('terminal','')
    app_type = request.values.get('app_type','')
    domain = request.values.get('domain','')
    container = request.values.get('container','')
    function = request.values.get('function','')
    url = request.values.get('url','')
    developer = request.values.get('developer','')
    app_id = request.values.get('app_id','')
    mode = request.values.get('mode','')
    ins_id = request.values.get('ins_id','')
    checkbox_list = request.values.getlist('checkbox_list')
    add =  request.values.get('add','')
    IP = request.values.get('IP','')
    port = request.values.get('port','')
    set_id = request.values.get('set_id','')
    off_id = request.values.get('off_id','')
    print "#add:",add
    print "#checkbox_list:",checkbox_list
    if set_id:
        setsql = 'update ops_instance set status = "" where ins_id = '+str(set_id)+';'
        result = modify_db(setsql)
    if off_id:
        offsql = 'update ops_instance set status = "备" where ins_id = '+str(off_id)+';'
        result = modify_db(offsql)
    if ins_id:
        deletesql = 'delete from ops_instance where ins_id = '+str(ins_id)+';'
        result = modify_db(deletesql)
        empty()
        #print deletesql
    if checkbox_list:
        for i in checkbox_list:
            deletesql = 'delete from ops_instance where ins_id = '+str(i)+';'
            #print deletesql
            result = modify_db(deletesql)
            empty()
    if mode:
        updatesql = 'update ops_application set app_name="'+app_name+'",location="'+location+'",env="'+env+'",terminal="'+terminal+'",app_type' \
                 '="'+app_type+'",domain="'+domain+'",container="'+container+'",function="'+function+'",url="'+url+'",developer="'+developer+'" where app_id='+str(app_id)+';'
        #print updatesql
        result = modify_db(updatesql)
        print "#1 result:", result
    if add:
        iplist = IP.split(',')
        no_ip = ''
        for i in iplist:
            selectsql = 'select count(1) from ops_machine where in_ip ="'+i+'";'
            n = query_db(selectsql)[0][0]
            if n == 0:
                no_ip = no_ip +","+ i
        if no_ip:
            result = "no_ip"
        else:
            for i in iplist:
                instancesql = 'INSERT INTO ops_instance(app_id,ip,port,status) SELECT '+str(app_id)+', "'+i+'",'+str(port)+',"" FROM DUAL WHERE NOT' \
                              ' EXISTS(SELECT app_id FROM ops_instance WHERE app_id='+str(app_id)+' and ip="'+i+'" and port='+str(port)+');'
                result = modify_db(instancesql)
                empty()

    if app_id:
        querysql = 'select * from ops_application where app_id ='+app_id+';'
        info = query_db(querysql)[0]
        IPsql = 'select ip,port,status,idc,cpu,mem,disk,ins_id from ops_instance a,ops_machine b where ip=in_ip and app_id ='+app_id+' order by ip,status,port;'
        IPinfo = query_db(IPsql)
    else:
        return abort(403)

    return render_template('pages/app_update.html',**locals())
# @app.route('/ajax/showclasstodb_auth',methods=['GET','POST'])
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
@app.route('/myapp_list') #我的申请列表
@test_login
def myapp_list(usertype,nickname,badge):
    result = request.args.get('result','')
    print "#result:",result
    if usertype == 'admin':
        sql = 'select * from ops_app_apply order by createtime desc;'
    else:
        sql = 'select * from ops_app_apply where developer="'+nickname+'" order by createtime desc;'
    info = query_db(sql)
    listsql = 'select count(1) from ops_app_apply where developer="'+nickname+'" and status !="已完成"; '
    listnum = query_db(listsql)[0][0]
    approvesql = 'select count(1) from ops_app_apply where  leader="'+nickname+'" and status = "待审批";'
    approvenum = query_db(approvesql)[0][0]
    actionsql = 'select count(1) from ops_app_apply where status = "待执行";;'
    actionnum = query_db(actionsql)[0][0]
    badge = {'list':listnum,'approve':approvenum,'action':actionnum}

    return render_template('pages/myapp_list.html',**locals())


@app.route('/myapp_update',methods=['POST', 'GET']) #修改我的申请
@test_login
def myapp_update(usertype,nickname,badge):
    username = request.cookies.get('username')
    id = request.args.get('id','')
    querysql = 'select * from ops_app_apply where id ='+id+'';
    info = query_db(querysql)[0]
    createtime = str(info[18]).split(" ",1)[0]
    domain1 = str(info[7]).split(".",1)[0]
    try:
        domain2 = str(info[7]).split(".",1)[1]
    except:
        domain2 = ""


    return render_template('pages/myapp_update.html',**locals())

@app.route('/myapp_apply',methods=['POST', 'GET']) #新服务申请
@test_login
def myapp_apply(usertype,nickname,badge):
    now = time.strftime("%Y-%m-%d", time.localtime())
    username = request.cookies.get('username')
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
    if request.method == 'POST':
        project_name = request.values.get('project_name','')
        app_name = request.values.get('app_name','')
        location = request.values.get('location','')
        env = request.values.get('env','')
        terminal = request.values.get('terminal','')
        app_type = request.values.get('app_type','')
        #print "##app_type",type(app_type)
        domain1 = request.values.get('domain1','')
        domain2 = request.values.get('domain2','')
        #print "#domain2",domain2
        if domain1:
            domain = domain1+domain2
        else:
            domain = ''
        container = request.values.get('container','')
        instance_mem = request.values.get('instance_mem','')
        machine_num = request.values.get('machine_num','')
        slave = request.values.get('slave','')
        machine_status = request.values.get('machine_status','')
        same_app_name = request.values.get('same_app_name','')
        function = request.values.get('function','')
        url = request.values.get('url','')
        common_server = request.values.get('common_server','')
        createtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        phone = request.values.get('phone','')
        note = request.values.get('note','')
        status = "待审批"
        checksql = 'select id from ops_app_apply where app_name="'+app_name+'" and location="'+location+'" and env="'+env+'" and terminal="'+terminal+'"; '
        checkinfo = query_db(checksql)
        checksql2 = 'select app_id from ops_application where app_name="'+app_name+'" and location="'+location+'" and env="'+env+'" and terminal="'+terminal+'"; '
        checkinfo2 = query_db(checksql2)
        #print checkinfo
        mode =  request.values.get('mode','')
        id = request.values.get('id','')

        if app_name and not checkinfo2:
            if checkinfo:
                result = "该应用已添加过,请更换应用名..."
                #print result
            if mode and id:
                updatesql = 'update ops_app_apply set project_name="'+project_name+'",app_name="'+app_name+'",location="'+location+'",env="'+env+'",terminal="'+terminal+'",app_type="'+app_type+'",' \
                    ' domain="'+domain+'",container="'+container+'", instance_mem="'+instance_mem+'G", machine_num="'+machine_num+'台", slave="'+slave+'", machine_status="'+machine_status+'", same_app_name' \
                    '="'+same_app_name+'", function="'+function+'", url="'+url+'", common_server="'+common_server+'", createtime="'+createtime+'", phone="'+phone+'", note="'+note+'", status="'+status+'" where id='+id+';'
                result = modify_db(updatesql)
                print result
                return redirect(url_for('myapp_list',result=result))

            elif checkinfo:
                result = "该应用已添加过,请更换应用名..."
                print result

            else:
                applysql = 'insert into ops_app_apply values("","'+project_name+'","'+app_name+'","'+location+'","'+env+'","'+terminal+'","'+app_type+'","'+domain+'","'+container+'","'+instance_mem+'G","'+machine_num+'台","'+slave+'",' \
                    '"'+machine_status+'","'+same_app_name+'","'+function+'","'+url+'","'+common_server+'","'+nickname+'","'+createtime+'",null,null,"'+p_nickname+'","'+phone+'","'+status+'","'+note+'",null,null,null);'
                print phone,applysql
                n = modify_db(applysql)
                print n
                if n == 1:
                    result = "提交成功..."
                else:
                    result = "提交失败..."

        else:
            return abort(403)
        listsql = 'select count(1) from ops_app_apply where developer="'+nickname+'" and status !="已完成"; '
        listnum = query_db(listsql)[0][0]
        approvesql = 'select count(1) from ops_app_apply where  leader="'+nickname+'" and status = "待审批";'
        approvenum = query_db(approvesql)[0][0]
        actionsql = 'select count(1) from ops_app_apply where status = "待执行";;'
        actionnum = query_db(actionsql)[0][0]
        badge = {'list':listnum,'approve':approvenum,'action':actionnum}


    return render_template('pages/myapp_apply.html',**locals())

@app.route('/myapp_approve',methods=['POST', 'GET']) #我的审批
@test_login
def myapp_approve(usertype,nickname,badge):
    if request.method == 'POST':
        approvetime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        leader_note = request.values.get('leader_note','')
        check_id = request.values.get('check_id','')
        times_id =  request.values.get('times_id','')
        print "#leader_note",leader_note
        if check_id:
            checksql = 'update ops_app_apply set status = "待执行",leader_note = "'+leader_note+'",approvetime="'+approvetime+'" where id='+check_id+';'
            print checksql
            result = modify_db(checksql)
        if times_id:
            timessql = 'update ops_app_apply set status = "已驳回",leader_note = "'+leader_note+'",approvetime="'+approvetime+'" where id='+times_id+';'
            print timessql
            result = modify_db(timessql)
    if usertype == 'admin':
        sql = 'select * from ops_app_apply order by createtime desc;'
    else:
        sql = 'select * from ops_app_apply where leader="'+nickname+'" order by createtime desc;'
    info = query_db(sql)
    listsql = 'select count(1) from ops_app_apply where developer="'+nickname+'" and status !="已完成"; '
    listnum = query_db(listsql)[0][0]
    approvesql = 'select count(1) from ops_app_apply where  leader="'+nickname+'" and status = "待审批";'
    approvenum = query_db(approvesql)[0][0]
    actionsql = 'select count(1) from ops_app_apply where status = "待执行";;'
    actionnum = query_db(actionsql)[0][0]
    badge = {'list':listnum,'approve':approvenum,'action':actionnum}
    return render_template('pages/myapp_approve.html',**locals())

@app.route('/myapp_action',methods=['POST', 'GET']) #我的执行
@test_login
def myapp_action(usertype,nickname,badge):
    if request.method == 'POST':
        dotime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        approvetime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        IP = request.values.get('IP','')
        port = request.values.get('port','')
        slaveIP = request.values.get('slaveIP','')
        operator_note = request.values.get('operator_note','')
        check_id = request.values.get('check_id','')
        times_id =  request.values.get('times_id','')
        if check_id:
            applicationsql = 'insert into ops_application(app_name,location,env,terminal,container,domain,app_type,developer,function,createtime) (select app_name,location,' \
                        'env,terminal,container,domain,app_type,developer,function,dotime from ops_app_apply where id='+check_id+');'
            modify_db(applicationsql)
            app_idsql = 'select app_id from ops_application a,ops_app_apply b where a.app_name=b.app_name and a.location=b.location and a.env=b.env and  a.terminal=b.terminal and id ='+check_id+';'
            app_id = query_db(app_idsql)[0][0]
            #print "#app_id",app_id

            #判断新增IP是否在CMDB存在
            iplist = IP.split(',')
            #print iplist
            no_ip = ''
            for i in iplist:
                selectsql = 'select count(1) from ops_machine where in_ip ="'+i+'";'
                n = query_db(selectsql)[0][0]
                if n == 0:
                    no_ip = no_ip +","+ i
            if no_ip:
                result = "no_ip"
            else:
                for i in iplist:
                    instancesql = 'insert into ops_instance(app_id,ip,port,status) values('+str(app_id)+',"'+i+'",'+str(port)+',""); '
                    modify_db(instancesql)
                    empty()
                checksql = 'update ops_app_apply set status = "已完成",operator_note = "'+operator_note+'",dotime="'+dotime+'",operator="'+nickname+'" where id='+check_id+';'
                #print checksql
                result = modify_db(checksql)
            if slaveIP:
                statussql = 'update ops_instance set status = "备" where app_id ='+str(app_id)+' and ip = "'+slaveIP+'"; '
                #print statussql
                result = modify_db(statussql)

        if times_id:
            timessql = 'update ops_app_apply set status = "已驳回 ",operator_note = "'+operator_note+'",dotime="'+dotime+'",operator="'+nickname+'" where id='+times_id+';'
            #print timessql
            result = modify_db(timessql)

    if usertype == 'admin':
        sql = 'select * from ops_app_apply order by createtime desc;'
        info = query_db(sql)
    else:
        return abort(403)
    listsql = 'select count(1) from ops_app_apply where developer="'+nickname+'" and status !="已完成"; '
    listnum = query_db(listsql)[0][0]
    approvesql = 'select count(1) from ops_app_apply where  leader="'+nickname+'" and status = "待审批";'
    approvenum = query_db(approvesql)[0][0]
    actionsql = 'select count(1) from ops_app_apply where status = "待执行";;'
    actionnum = query_db(actionsql)[0][0]
    badge = {'list':listnum,'approve':approvenum,'action':actionnum}

    return render_template('pages/myapp_action.html',**locals())

@app.route('/rel_config',methods=['POST', 'GET'])  #配置KEY列表
@test_login
def rel_config(usertype,nickname,badge):
    location = request.args.get('location','')
    env  = request.args.get('env','')
    type = request.args.get('type','')
    word = request.args.get('word','')
    id = request.args.get('id','')
    if id:
        delsql = 'delete from rel_config where id= '+id+';'
        result = modify_db(delsql)

    sql = 'select * from rel_config where location like "%'+location+'%" and env like "%'+env+'%" and type like "%'+type+'%" and conf_key like "%'+word+'%";'
    print sql
    info = query_db(sql)
    print info,location,env,type,word
    return render_template('pages/rel_config.html',**locals())

@app.route('/rel_conf_add',methods=['POST', 'GET'])  #新增KEY
@test_login
def rel_conf_add(usertype,nickname,badge):
    location = request.values.get('location','')
    env  = request.values.get('env','')
    type = request.values.get('type','')
    conf_value = request.values.get('conf_value','')
    conf_key = request.values.get('conf_key','')
    print location,env,conf_value,conf_key
    if conf_key:
        insertsql = 'insert into rel_config values("","'+conf_key+'","'+conf_value+'","'+location+'","'+env+'","'+type+'");'
        print insertsql
        result = modify_db(insertsql)
        print result
    return render_template('pages/rel_conf_add.html',**locals())

@app.route('/rel_conf_update',methods=['POST', 'GET'])  #新增KEY
@test_login
def rel_conf_update(usertype,nickname,badge):
    location = request.values.get('location','')
    env  = request.values.get('env','')
    type = request.values.get('type','')
    conf_value = request.values.get('conf_value','')
    conf_key = request.values.get('conf_key','')
    id = request.args.get('id','')
    print location,env,type,conf_value,conf_key,id
    if conf_key:
        updatesql = 'update rel_config set location = "'+location+'",env = "'+env+'",type = "'+type+'",conf_key = "'+conf_key+'",conf_value = "'+conf_value+'" where id = '+id+';'
        print updatesql
        result = modify_db(updatesql)
        print result
    sql = 'select * from rel_config where id ='+id+';'
    info = query_db(sql)

    return render_template('pages/rel_conf_update.html',**locals())

#脚本调用接口
@app.route('/query',methods=['POST', 'GET'])
def query():
    if request.method == 'POST':
        app_name = request.values.get('a','')
        location = request.values.get('b','大陆')
        env = request.values.get('c','生产')
        ip = request.values.get('ip','')
        ip_sql = 'select app_name,ip,port,b.status from ops_application a,ops_instance b where a.app_id=b.app_id and app_name like "'+app_name+'" and location="'+location+'" and env = "'+env+'" order by ip,port,b.status;'
        ipinfo = query_db(ip_sql)
        app_sql = 'select app_name,location,env from ops_application a,ops_instance b where a.app_id=b.app_id and ip like "'+ip+'";'
        appinfo = query_db(app_sql)

    return render_template('query.html',**locals())



if __name__ == '__main__':
    app.debug = True
    #app.run(host='10.154.81.158',port=8000)
    app.run(host='0.0.0.0',port=8001)
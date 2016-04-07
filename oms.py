#encoding:utf-8
from flask import Flask,app,request,render_template, redirect, url_for, session, abort,jsonify,make_response,send_from_directory,make_response
from mysql import *
import requests,json,urllib,urllib2
import ssl,os,MySQLdb,sys,time,hashlib
from functools import wraps
reload(sys)
sys.setdefaultencoding('utf-8')

app = Flask(__name__)

@app.route('/login',methods=['POST', 'GET'])
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
            print type(badge),badge
            return fn(usertype,nickname,badge)
        else:
            return redirect(url_for('login',redirect_url=redirect_url))
    return wrapper

def test_admin(fn):
    @wraps(fn)
    def wrapper(usertype,nickname,badge):
        if usertype == 'admin':
            return fn(usertype,nickname,badge)
        else:
            return abort(403)
    return wrapper

@app.route('/logout',methods=['POST', 'GET'])
def logout():
    redirect_to_index = redirect('/')
    resp = make_response(redirect_to_index)
    resp.delete_cookie('username')
    return resp

@app.route('/rbac')
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

@app.route('/')
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

    return render_template('pages/cmdb.html',**locals())

@app.route('/app_list',methods=['POST', 'GET'])
@test_login
def app_list(usertype,nickname,badge):
    location = request.args.get('location','大陆')
    env =  request.args.get('env','生产')
    terminal =  request.args.get('terminal','%')
    word =  request.args.get('word','')
    word1 =  request.args.get('word','')
    mohu = request.args.get('mohu','')
    de_id = request.args.get('de_id','')

    if de_id and usertype == 'admin':
        deleteappsql = 'delete from ops_application where app_id = '+de_id+'; '
        modify_db(deleteappsql)
        deleteinssql = 'delete from ops_instance where app_id = '+de_id+'; '
        modify_db(deleteinssql)
        result = "ok"
    if "空" in word:
        esql = 'select app_id from ops_application where app_name="空机器";'
        eid = query_db(esql)[0][0]
        print eid
        modify_db('delete from ops_instance where app_id = '+str(eid)+';')
        modify_db('insert into ops_instance(app_id,ip,port) (select "'+str(eid)+'",in_ip,"" from ops_machine where in_ip not in (select ip from ops_instance));')
    if mohu:
        word = '%'+word+'%'
    if word:
        applicationsql = "select a.*,count(b.app_id) from ops_application a,ops_instance b where a.app_id=b.app_id and location " \
                         "like '"+location+"' and env like '"+env+"' and terminal like '"+terminal+"' and (app_name like '"+word+"'" \
                         " or developer like '"+word+"' or ip like '"+word+"') group by app_name,location,env,terminal order by location,app_name,env,terminal;"
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
    instancesql = "select app_id,idc,ip,port,cpu,mem,disk from ops_instance a,ops_machine b  where ip=in_ip;"
    instanceinfo = query_db(instancesql)
    gnginxsql = "select ngx_gname,vip,count(1),ngx_id from ops_nginx  group by ngx_gname,vip;"
    gnginxinfo = query_db(gnginxsql)
    nginxsql = "select vip,ip,status from ops_nginx;"
    nginxinfo = query_db(nginxsql)


    return render_template('pages/app_list.html',**locals())

@app.route('/app_update',methods=['POST', 'GET'])
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
    print "#add:",add
    print "#checkbox_list:",checkbox_list
    if mode:
        updatesql = 'update ops_application set app_name="'+app_name+'",location="'+location+'",env="'+env+'",terminal="'+terminal+'",app_type' \
                 '="'+app_type+'",domain="'+domain+'",container="'+container+'",function="'+function+'",url="'+url+'",developer="'+developer+'" where app_id='+str(app_id)+';'
        #print updatesql
        result = modify_db(updatesql)
    if ins_id:
        deletesql = 'delete from ops_instance where ins_id = '+str(ins_id)+';'
        result = modify_db(deletesql)
        #print deletesql
    if checkbox_list:
        for i in checkbox_list:
            deletesql = 'delete from ops_instance where ins_id = '+str(i)+';'
            #print deletesql
            result = modify_db(deletesql)
    if add:
        iplist = IP.split(',')
        print iplist
        for i in iplist:
            instancesql = 'INSERT INTO ops_instance(app_id,ip,port,status) SELECT '+str(app_id)+', "'+i+'",'+str(port)+',"" FROM DUAL WHERE NOT EXISTS(SELECT app_id FROM ops_instance WHERE app_id='+str(app_id)+' and ip="'+i+'" and port='+str(port)+');'
            #print instancesql
            result = modify_db(instancesql)
            print result

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
@app.route('/myapp_list')
@test_login
def myapp_list(usertype,nickname,badge):
    result = request.args.get('result','')
    print "#result:",result
    if usertype == 'admin':
        sql = 'select * from ops_app_apply order by createtime desc;'
    else:
        sql = 'select * from ops_app_apply where developer="'+nickname+'" order by createtime desc;'
    info = query_db(sql)
    return render_template('pages/myapp_list.html',**locals())


@app.route('/myapp_update',methods=['POST', 'GET'])
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

@app.route('/myapp_apply',methods=['POST', 'GET'])
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

    return render_template('pages/myapp_apply.html',**locals())

@app.route('/myapp_approve',methods=['POST', 'GET'])
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
    return render_template('pages/myapp_approve.html',**locals())

@app.route('/myapp_action',methods=['POST', 'GET'])
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

            iplist = IP.split(',')
            for i in iplist:
                instancesql = 'insert into ops_instance(app_id,ip,port,status) values('+str(app_id)+',"'+i+'",'+str(port)+',""); '
                #print instancesql
                modify_db(instancesql)
                checksql = 'update ops_app_apply set status = "已完成",operator_note = "'+operator_note+'",dotime="'+dotime+'",operator="'+nickname+'" where id='+check_id+';'
                print checksql
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

    return render_template('pages/myapp_action.html',**locals())

if __name__ == '__main__':
    app.debug = True
    #app.run(host='10.154.81.158',port=8000)
    app.run(host='0.0.0.0',port=8001)
#encoding:utf-8
from flask import Flask,app,request,render_template, redirect, url_for, session, abort,jsonify,make_response,send_from_directory,make_response,jsonify
from mysql import *
from function import *
import requests,json,urllib,urllib2,thread
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
            # print req
            info = json.loads(req)
            if info['client_id']:
                # print "###",redirect_url
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
    # print delid
    # print user_add
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
            # print result
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
    username = request.cookies.get('username',None)
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
    # print total,kvm
    kvmp = kvm * 100 / total
    # print kvmp
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

@app.route('/app_list',methods=['POST', 'GET']) #服务列表
@test_login
def app_list(usertype,nickname,badge):
    username = request.cookies.get('username')
    org_name = leader(username)[1].split("@")[0]
    # print org_name
    location = request.args.get('location','大陆')
    env =  request.args.get('env','生产')
    terminal =  request.args.get('terminal','%')
    word =  request.args.get('word','').strip()
    word1 =  request.args.get('word','').strip()
    mohu = request.args.get('mohu','')
    de_id = request.args.get('de_id','')
    app_num = query_db("select count(1) from ops_application  where  location like '"+location+"' and env like '"+env+"';")[0][0]
    mac_num = query_db("select count(1) from (select ip from ops_application a,ops_instance b where a.app_id=b.app_id and  location like '"+location+"' and env like '"+env+"' group by ip) a;")[0][0]
    ins_num = query_db("select count(1) from ops_application a,ops_instance b where a.app_id=b.app_id and  location like '"+location+"' and env like '"+env+"';")[0][0]
    print location,env,word
    if de_id and usertype == 'admin':
        deleteappsql = 'delete from ops_application where app_id = '+de_id+'; '
        modify_db(deleteappsql)
        deleteinssql = 'delete from ops_instance where app_id = '+de_id+'; '
        modify_db(deleteinssql)
        deleterelsql = 'delete from rel_operate where app_id = '+de_id+'; '
        modify_db(deleterelsql)
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
        applicationsql = "select a.*,count(b.app_id) from ops_application a,ops_instance b where a.app_id=b.app_id and  location " \
                     "like '"+location+"' and env like '"+env+"' and terminal like '"+terminal+"' group by app_name,location,env,terminal order by location,app_name,env,terminal;"
    applicationinfo = query_db(applicationsql)
    print applicationinfo
    print applicationsql
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
    # print "#add:",add
    # print "#checkbox_list:",checkbox_list
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
        # print "#1 result:", result
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

@app.route('/myapp_list') #我的申请列表
@test_login
def myapp_list(usertype,nickname,badge):
    result = request.args.get('result','')
    page = request.args.get('page','')

    # print "#result:",result
    if usertype == 'admin':
        sql = 'select * from ops_app_apply order by FIELD(`status`,"待执行" ) desc,createtime desc;'
        sql1 = 'select app_name,location,env,terminal,b.*,b.status as bstatus from ops_application a,rel_apply b where a.app_id=b.app_id order by FIELD(`bstatus`,"执行中","待执行","已失败"),apply_time desc;'

    else:
        sql = 'select * from ops_app_apply where developer="'+nickname+'" order by  FIELD(`status`,"待执行" ) desc,createtime desc;'
        sql1 = 'select app_name,location,env,terminal,b.*,b.status as bstatus from ops_application a,rel_apply b where a.app_id=b.app_id and applyer="'+nickname+'" order by FIELD(`bstatus`,"执行中","待执行","已失败") desc,apply_time desc;'

    info = query_db(sql)
    info1 = query_db(sql1)

    return render_template('pages/myapp_list.html',**locals())


@app.route('/myapp_update',methods=['POST', 'GET']) #修改我的申请
@test_login
def myapp_update(usertype,nickname,badge):
    username = request.cookies.get('username')
    id = request.args.get('id','')
    querysql = 'select * from ops_app_apply where id ='+id+'';
    info = query_db(querysql)[0]
    createtime = str(info[18]).split(" ",1)[0]
    domain = str(info[7])
    if 'shop.letv.com' in domain:
        domain1 = domain.replace('.shop.letv.com','')
        domain2 = 'shop.letv.com'

    elif 'lemall.com' in domain:
        domain1 = domain.replace('.lemall.com','')
        domain2 = 'lemall.com'
    else:
        domain1 = ""
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
    org_name = p_email.split('@')[0]
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
        status = "待执行"
        checksql = 'select id from ops_app_apply where app_name="'+app_name+'" and location="'+location+'" and env="'+env+'" and terminal="'+terminal+'" and status !="已完成"; '
        checkinfo = query_db(checksql)
        checksql2 = 'select app_id from ops_application where app_name="'+app_name+'" and location="'+location+'" and env="'+env+'" and terminal="'+terminal+'"; '
        checkinfo2 = query_db(checksql2)
        # print checkinfo2
        mode =  request.values.get('mode','')
        id = request.values.get('id','')

        if app_name and not checkinfo2:
            if checkinfo:
                result = "该应用已提交过,请不要重复提交..."
                #print result
            if mode and id:
                updatesql = 'update ops_app_apply set project_name="'+project_name+'",app_name="'+app_name+'",location="'+location+'",env="'+env+'",terminal="'+terminal+'",app_type="'+app_type+'",' \
                    ' domain="'+domain+'",container="'+container+'", instance_mem="'+instance_mem+'G", machine_num="'+machine_num+'台", slave="'+slave+'", machine_status="'+machine_status+'", same_app_name' \
                    '="'+same_app_name+'", function="'+function+'", url="'+url+'", common_server="'+common_server+'", createtime="'+createtime+'", phone="'+phone+'", note="'+note+'", status="'+status+'" where id='+id+';'
                result = modify_db(updatesql)
                # print result
                return redirect(url_for('myapp_list',result=result))


            else:
                applysql = 'insert into ops_app_apply values("","'+project_name+'","'+app_name+'","'+location+'","'+env+'","'+terminal+'","'+app_type+'","'+domain+'","'+container+'","'+instance_mem+'G","'+machine_num+'台","'+slave+'",' \
                    '"'+machine_status+'","'+same_app_name+'","'+function+'","'+url+'","'+common_server+'","'+nickname+'","'+createtime+'",null,null,"'+org_name+'","'+phone+'","'+status+'","'+note+'",null,null,null,null);'
                # print phone,applysql
                n = modify_db(applysql)
                # print n
                if n == 1:
                    result = "提交成功..."
                else:
                    result = "提交失败..."

        else:
            result = "该应用已添加过,请更换应用名..."

    return render_template('pages/myapp_apply.html',**locals())

@app.route('/myapp_approve',methods=['POST', 'GET']) #我的审批
@test_login
def myapp_approve(usertype,nickname,badge):
    if request.method == 'POST':
        approvetime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        leader_note = request.values.get('leader_note','')
        check_id = request.values.get('check_id','')
        times_id =  request.values.get('times_id','')
        # print "#leader_note",leader_note
        if check_id:
            checksql = 'update ops_app_apply set status = "待执行",leader_note = "'+leader_note+'",approvetime="'+approvetime+'" where id='+check_id+';'
            # print checksql
            result = modify_db(checksql)
        if times_id:
            timessql = 'update ops_app_apply set status = "已驳回",leader_note = "'+leader_note+'",approvetime="'+approvetime+'" where id='+times_id+';'
            # print timessql
            result = modify_db(timessql)
    if usertype == 'admin':
        sql = 'select * from ops_app_apply order by createtime desc;'
    else:
        sql = 'select * from ops_app_apply where leader="'+nickname+'" order by createtime desc;'
    info = query_db(sql)
    return render_template('pages/myapp_approve.html',**locals())

@app.route('/myapp_action',methods=['POST', 'GET']) #我的执行
@test_login
def myapp_action(usertype,nickname,badge):
    page = request.args.get('page','')
    if request.method == 'POST':
        dotime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        approvetime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        page = request.values.get('page','')
        IP = request.values.get('IP','')
        port = request.values.get('port','')
        slaveIP = request.values.get('slaveIP','')
        operator_note = request.values.get('operator_note','')
        check_id = request.values.get('check_id','')
        times_id =  request.values.get('times_id','')
        if check_id:
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
                applicationsql = 'insert into ops_application(app_name,location,env,terminal,container,domain,app_type,developer,function,createtime,org_name) (select app_name,location,' \
                        'env,terminal,container,domain,app_type,developer,function,dotime,leader from ops_app_apply where id='+check_id+');'
                modify_db(applicationsql)
                app_idsql = 'select app_id,a.app_name,a.container from ops_application a,ops_app_apply b where a.app_name=b.app_name and a.location=b.location and a.env=b.env and  a.terminal=b.terminal and id ='+check_id+';'
                app_id = query_db(app_idsql)[0][0]
                #print "#app_id",app_id
                rel_sql = "insert into rel_operate(app_id) values("+str(app_id)+");"
                modify_db(rel_sql)
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
                # #安装tomcat
                # ipsql = 'select ip,port from ops_instance where app_id ='+str(app_id)+';'
                # ipinfo = query_db(ipsql)
                # app_name = query_db(app_idsql)[0][1]
                # container = query_db(app_idsql)[0][2]
                # if container == "tomcat":
                #     method = "software"
                #     ask = {"ipinfo":str(ipinfo),"app_name":app_name,"app_id":app_id,"software":"tomcat","software_mode":"install"}
                #     thread.start_new_thread(curl, (method,ask,"",nickname,""))

        if times_id:
            timessql = 'update ops_app_apply set status = "已驳回",operator_note = "'+operator_note+'",dotime="'+dotime+'",operator="'+nickname+'" where id='+times_id+';'
            #print timessql
            result = modify_db(timessql)
    else:
        yes_id = request.values.get('yes_id','')
        no_id = request.values.get('no_id','')
        operate_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        if yes_id and usertype == "admin":
            modify_db('update rel_apply set status = "执行中" where id = '+str(yes_id)+';')
            app_sql = "select app_id,svn,version,type from rel_apply where id = "+str(yes_id)+";"
            app_id = query_db(app_sql)[0][0]
            app_name = query_db('select app_name from ops_application where app_id ='+str(app_id)+';')[0][0]
            app_type = query_db(app_sql)[0][3]
            if app_type == "回滚":
                app_svn = int(str(query_db(app_sql)[0][1]).split('_')[0])+int(gap)
            else:
                app_svn = str(query_db(app_sql)[0][1])
            ipsql = 'select ip,port,status from ops_instance where app_id = '+str(app_id)+';'
            ipinfo = query_db(ipsql)
            # print type(ipinfo)
            method = "publish"
            ask={"ipinfo":str(ipinfo),"app_name":app_name,"app_svn":str(app_svn),"app_type":app_type,"rel_id":yes_id}
            # print "ask:",app_svn,app_type
            thread.start_new_thread(curl, (method,ask,yes_id,nickname,app_id))
            return redirect(url_for('process',id=yes_id))

        if no_id and usertype == "admin":
            nosql = 'update rel_apply set status = "已驳回",operate_time="'+operate_time+'",operator="'+nickname+'" where id='+no_id+';'
            result = modify_db(nosql)

    if usertype == 'admin':
        sql = 'select * from ops_app_apply order by  FIELD(`status`,"待执行") desc,createtime desc;'
        sql1 = 'select app_name,location,env,terminal,b.*,b.status as bstatus from ops_application a,rel_apply b where a.app_id=b.app_id order by FIELD(`bstatus`,"执行中","待执行","已失败") desc,apply_time desc;;'

        info = query_db(sql)
        info1 = query_db(sql1)

    else:
        return abort(403)

    return render_template('pages/myapp_action.html',**locals())

@app.route('/rel_config',methods=['POST','GET'])  #配置KEY列表
@test_login
def rel_config(usertype,nickname,badge):
    location = request.values.get('location','')
    env  = request.values.get('env','')
    type = request.values.get('type','')
    word = request.values.get('word','')
    id = request.values.get('id','')
    if id:
        delsql = 'delete from rel_config where id= '+id+';'
        result = modify_db(delsql)

    sql = 'select * from rel_config where location like "%'+location+'%" and env like "%'+env+'%" and type like "%'+type+'%" and conf_key like "%'+word+'%";'
    # print sql
    info_1 = query_db(sql)
    info = []
    pc = prpcrypt('yj_L]<xQ07zrOqlf')
    for i in info_1:
        print i[2]
        conf_value = pc.decrypt(i[2])
        info.append([i[0],i[1],conf_value,i[3],i[4],i[5]])
    # print info,location,env,type,word
    return render_template('pages/rel_config.html',**locals())

@app.route('/rel_conf_add',methods=['POST', 'GET'])  #新增KEY
@test_login
def rel_conf_add(usertype,nickname,badge):
    location = request.values.get('location','')
    env  = request.values.get('env','')
    type = request.values.get('type','')
    conf_value = request.values.get('conf_value','')
    conf_key = request.values.get('conf_key','')
    # print location,env,conf_value,conf_key
    if conf_key and conf_value:
        pc = prpcrypt('yj_L]<xQ07zrOqlf')
        conf_value = pc.encrypt(conf_value)
        insertsql = 'insert into rel_config values("","'+conf_key+'","'+conf_value+'","'+location+'","'+env+'","'+type+'");'
        # print insertsql
        result = modify_db(insertsql)
        # print result
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
    pc = prpcrypt('yj_L]<xQ07zrOqlf')
    # print location,env,type,conf_value,conf_key,id
    if conf_key:
        conf_value = pc.encrypt(conf_value)
        updatesql = 'update rel_config set location = "'+location+'",env = "'+env+'",type = "'+type+'",conf_key = "'+conf_key+'",conf_value = "'+conf_value+'" where id = '+id+';'
        # print updatesql
        result = modify_db(updatesql)
        # print result
    sql = 'select * from rel_config where id ='+id+';'
    info_1 = query_db(sql)
    info = []

    for i in info_1:
        conf_value = pc.decrypt(i[2])
        info.append([i[0],i[1],conf_value,i[3],i[4],i[5]])
    return render_template('pages/rel_conf_update.html',**locals())

#-----------------------------------------------------------------------------------------------------------------------

@app.route('/app_info',methods=['POST', 'GET'])  #服务基本信息
@test_login
def app_info(usertype,nickname,badge):

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
    org_name = request.values.get('org_name','')
    app_id = request.values.get('app_id','')
    mode = request.values.get('mode','')
    ins_id = request.values.get('ins_id','')
    checkbox_list = request.values.getlist('checkbox_list')
    add =  request.values.get('add','')
    IP = request.values.get('IP','')
    port = request.values.get('port','')
    set_id = request.values.get('set_id','')
    off_id = request.values.get('off_id','')
    # print "#add:",add
    # print "#checkbox_list:",checkbox_list
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
                 '="'+app_type+'",domain="'+domain+'",container="'+container+'",function="'+function+'",url="'+url+'",developer="'+developer+'" ,org_name="'+org_name+'" where app_id='+str(app_id)+';'
        #print updatesql
        result = modify_db(updatesql)
        # print "#1 result:", result
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
            ipinfo = []
            for i in iplist:
                instancesql = 'INSERT INTO ops_instance(app_id,ip,port,status) SELECT '+str(app_id)+', "'+i+'",'+str(port)+',"" FROM DUAL WHERE NOT' \
                              ' EXISTS(SELECT app_id FROM ops_instance WHERE app_id='+str(app_id)+' and ip="'+i+'" and port='+str(port)+');'
                result = modify_db(instancesql)
                ipinfo.append([i,port])
            # print "ipinfo",ipinfo
            empty()
            # #安装tomcat
            # appsql = 'select app_name,container from ops_application where app_id ='+str(app_id)+';'
            # appinfo = query_db(appsql)
            # app_name = appinfo[0][0]
            # container = appinfo[0][1]
            # if container == "tomcat":
            #     method = "software"
            #     ask = {"ipinfo":str(ipinfo),"app_name":app_name,"app_id":app_id,"software":"tomcat","software_mode":"install"}
            #     thread.start_new_thread(curl, (method,ask,"",nickname,""))

    if app_id:
        querysql = 'select * from ops_application where app_id ='+app_id+';'
        info = query_db(querysql)[0]
        IPsql = 'select ip,port,status,idc,cpu,mem,disk,ins_id from ops_instance a,ops_machine b where ip=in_ip and app_id ='+app_id+' order by ip,status,port;'
        IPinfo = query_db(IPsql)
    else:
        return abort(403)

    return render_template('pages/app_info.html',**locals())


@app.route('/app_action',methods=['POST', 'GET'])  #服务操作
@test_login
def app_action(usertype,nickname,badge):
    app_id = request.args.get('app_id','')
    appsql = 'select app_name from ops_application where app_id='+str(app_id)+';'
    logname = 'action_'+query_db(appsql)[0][0]+'.log'
    os.system('rm -f '+work_path+logname )
    if app_id:
        IPsql = 'select ip,port,status,idc,cpu,mem,disk,ins_id from ops_instance a,ops_machine b where ip=in_ip and app_id ='+app_id+' order by ip,status,port;'
        IPinfo = query_db(IPsql)
    else:
        return abort(403)
    return render_template('pages/app_action.html',**locals())

@app.route('/soft_install',methods=['POST', 'GET'])  #发版
@test_login
@test_admin
def soft_install(usertype,nickname,badge):
    app_id = request.args.get("app_id","")
    appsql = 'select app_name,location,env,terminal from ops_application where app_id ='+str(app_id)+';'
    appinfo = query_db(appsql)
    app_name = appinfo[0][0]
    type = request.values.get('type','')
    checkbox_list = request.values.getlist('checkbox_list')
    id_list = ','.join(checkbox_list)
    sql = 'select * from ops_instance where app_id='+app_id+';'
    info = query_db(sql)
    if type:
        ipsql = 'select ip,port from ops_instance where ins_id in ('+str(id_list)+');'
        ipinfo = query_db(ipsql)
        ask = {"ipinfo":str(ipinfo),"app_name":app_name,"app_id":app_id,"software":"tomcat","software_mode":type}
        print ask
        url = "http://10.182.63.65:8888/software"
        r = requests.post(url,data = ask)
        print r.text
        result =  r.text.split(":")[-1]
    url = "http://10.182.63.65:8888/software_check"
    ask = {"ipinfo":str(info),"software":"tomcat","app_name":app_name}

    r = requests.post(url,data = ask)
    statusinfo = eval(r.text)
    info_new = []
    for i in info:
        for n in statusinfo:
            if i[0] == n[0]:
                list = [i[0],i[1],i[2],i[3],i[4],n[1]]
                info_new.append(list)

    return render_template('pages/soft_install.html',**locals())


@app.route('/rel_list',methods=['POST', 'GET'])  #发版
@test_login
def rel_list(usertype,nickname,badge):
    apply_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    svn  = request.values.get('svn','').strip('/')
    backup_id  = request.values.get('backup_id','')
    type = request.values.get('app_type','')
    location = request.args.get('location','大陆')
    env =  request.args.get('env','生产')
    terminal =  request.args.get('terminal','%')
    # print "#type:",type,svn
    word =  request.args.get('word','')
    word1 =  request.args.get('word','')
    mohu = request.args.get('mohu','')
    apply_note  = request.values.get('apply_note','')
    publish_id  = request.values.get('publish_id','')
    rollback_id  = request.values.get('rollback_id','')

    if publish_id:
        # print publish_id
        version = svn.strip('/').split('/')[-1]
        check = query_db('select count(1) from rel_apply where app_id = '+str(publish_id)+' and status in ("待执行","已失败");')
        if check[0][0] != 0:
            result = 2
        else:
            applysql = 'insert into rel_apply(app_id,type,version,svn,applyer,apply_time,apply_note,status) ' \
                   'values('+str(publish_id)+',"'+type+'","'+str(version)+'","'+svn+'","'+nickname+'","'+apply_time+'","'+apply_note+'","待执行");'
            result = modify_db(applysql)
    if rollback_id:
        # print rollback_id,backup_id
        version = str(backup_id).split('_')[-1]
        check = query_db('select count(1) from rel_apply where app_id = '+str(rollback_id)+' and status in ("待执行","已失败");')
        if check[0][0] != 0:
            result = 2
        else:
            applysql = 'insert into rel_apply(app_id,type,version,svn,applyer,apply_time,apply_note,status) ' \
                   'values('+str(rollback_id)+',"'+type+'","'+str(version)+'","'+backup_id+'","'+nickname+'","'+apply_time+'","'+apply_note+'","待执行");'
            result = modify_db(applysql)
    if mohu:
        word = '%'+word+'%'
    if word:
        infosql = "select app_name,location,env,terminal,a.svn,version,operate_time,operator,note,b.status,b.app_id,container,domain,app_type,developer,function,url from ops_application a,rel_operate b where" \
              " a.app_id=b.app_id and  location like '"+location+"' and env like '"+env+"' and terminal like '"+terminal+"' and app_name like '"+word+"';"
    else:
        infosql = "select app_name,location,env,terminal,a.svn,version,operate_time,operator,note,b.status,b.app_id,container,domain,app_type,developer,function,url from ops_application a,rel_operate b where" \
              " a.app_id=b.app_id and  location like '"+location+"' and env like '"+env+"' and terminal like '"+terminal+"' limit 20;"
    info = query_db(infosql)
    rel_applysql = 'select id,app_id,operate_time,version from rel_apply where status = "已完成" order by operate_time desc limit 6;'
    rel_applyinfo = query_db(rel_applysql)
    # print info
    return render_template('pages/rel_list.html',**locals())

@app.route('/send_cmd',methods=['POST', 'GET'])  #clush命令接口
@test_login
def send_cmd(usertype,nickname,badge):
    if usertype == 'admin':
        app_id = request.args.get('app_id','')
        cmd = request.args.get('cmd','')
        ipssql = 'select ip,port,b.status from ops_application a,ops_instance b where a.app_id=b.app_id and a.app_id='+str(app_id)+';'
        info = query_db(ipssql)
        # print cmd,app_id
        for i in info:
            if i[2] == '备':
                print i
        ips = ','.join([x[0] for x in query_db(ipssql)])

        appsql = 'select app_name from ops_application where app_id='+str(app_id)+';'
        logname = 'action_'+query_db(appsql)[0][0]+'.log'
        if cmd:
            clush_cmd = 'ssh root@10.182.63.65 \'clush -w "'+ips+'" "'+cmd+'"\' >> '+work_path+logname+' 2>&1'
            a = os.system(clush_cmd)
        return str(a)

@app.route('/rizhi',methods=['POST', 'GET'])  #rizhi
@test_login
@test_admin
def rizhi(usertype,nickname,badge):
    app_id = request.args.get('app_id','')
    nownum = request.args.get('nownum','')
    appsql = 'select app_name from ops_application where app_id='+str(app_id)+';'
    logname = work_path+'action_'+query_db(appsql)[0][0]+'.log'
    rizhi = open(logname,'r')
    if nownum != 0 :
        rizhi.seek(int(nownum))
    rizhiinfo = rizhi.read()
    nownum = rizhi.tell()
    rzinfo = str(nownum)+"^^^"+rizhiinfo
    rizhi.close()
    return rzinfo






@app.route('/publish',methods=['POST', 'GET'])  #clush命令接口
@test_login
@test_admin
def publish(usertype,nickname,badge):
    id = request.args.get('id','')
    # print id
    time.sleep(5)
    # print id
    return "ok"

@app.route('/zhuangtai',methods=['POST', 'GET'])
@test_login
@test_admin
def zhuangtai(usertype,nickname,badge):
    id = request.args.get('id','')
    sql = 'select id,status from rel_apply;'
    info = query_db(sql)
    dict = {}
    for i in info:
        dict[i[0]] = i[1]
    # print dict,"---",type(dict)
    # info = json.dumps(info)
    return jsonify(dict)



@app.route('/process')
@test_login
def process(usertype,nickname,badge):
    id = request.args.get('id','')
    # print "##id",id
    # print prenum
    sql = 'select * from ops_application a,rel_apply b where a.app_id=b.app_id and id='+str(id)+';'
    info = query_db(sql)
    publishsql = 'select * from rel_publish where rel_id ='+str(id)+' order by status;'
    publishinfo = query_db(publishsql)
    if publishinfo:
        total = len(publishinfo)
        done = 0
        for i in publishinfo:
            if i[4] == '完成':
                done += 1
        percent = done * 100 / total
    return render_template('pages/process.html',**locals())

@app.route('/rel_publish',methods=['POST', 'GET'])

def rel_publish():
    rel_id = request.values.get('rel_id','')
    ip = request.values.get('ip','')
    port = request.values.get('port','')
    status = request.values.get('status','')
    # type = request.values.get('type','')
    now_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    # print "#rel_id:",rel_id
    checksql = 'select 1 from rel_publish where rel_id = '+rel_id+' and ip = "'+ip+'" and port = '+port+';'
    check = query_db(checksql)
    # print checksql,check
    if check:
        publishsql = 'update rel_publish set status = "'+status+'",finish_time = "'+now_time+'" where rel_id= '+rel_id+' and ip = "'+ip+'" and port = '+port+';'
    else:
        publishsql = 'insert into rel_publish(rel_id,ip,port,start_time,finish_time,status) values('+rel_id+',"'+ip+'",'+port+',"'+now_time+'","'+now_time+'","'+status+'");'
    # print publishsql
    result = modify_db(publishsql)
    # print publishsql
    return "ok"


@app.route('/query_key',methods=['POST'])  #key查询api
def query_key():
    location = request.values.get('location','')
    env  = request.values.get('env','')
    key = request.values.get('key','')
    sql = 'select conf_value from rel_config where location = "'+location+'" and env = "'+env+'" and  conf_key = "'+key+'";'
    result = query_db(sql)
    if result != ():
        result = result[0][0]
        return result
    else:
        return abort(404)


@app.route('/sub_key',methods=['POST'])  #key查询api
def sub_key():
    location = request.values.get('location','')
    env  = request.values.get('env','')
    svn = request.values.get('svn','')
    url = 'http://10.182.63.65:8888/sub_key'
    ask = {'location':location,'env':env,'svn_url':svn}
    r = requests.post(url,data=ask)
    result = r.text
    print location,env,svn,result
    return result


#-----------------------------------------------------------------------------------------------------------------------

#脚本调用接口
@app.route('/query',methods=['POST', 'GET'])
def query():
    if request.method == 'POST':
        app_name = request.values.get('a','')
        location = request.values.get('b','大陆')
        env = request.values.get('c','生产')
        ip = request.values.get('ip','')
        dict1 = {"cn":"大陆","us":"美国","in":"印度","hk":"香港","":"俄罗斯"}
        if location in dict1.keys():
            location = dict1[location]
        dict2 = {"sc":"生产","cs":"测试","yw":"运维","kf":"开发","yc":"压测","yl":"预览"}
        if env in dict2.keys():
            env = dict2[env]
        ip_sql = 'select app_name,ip,port,b.status from ops_application a,ops_instance b where a.app_id=b.app_id and app_name like "'+app_name+'" and location="'+location+'" and env = "'+env+'" order by ip,port,b.status;'
        ipinfo = query_db(ip_sql)
        app_sql = 'select app_name,location,env from ops_application a,ops_instance b where a.app_id=b.app_id and ip like "'+ip+'";'
        appinfo = query_db(app_sql)

    return render_template('query.html',**locals())



if __name__ == '__main__':
    app.debug = True
    #app.run(host='10.154.81.158',port=8000)
    app.run(host='0.0.0.0',port=8001)
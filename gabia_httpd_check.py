# -*- coding: utf-8 -*-

# Import python libs
import os
import re
import fnmatch

# Import salt libs
import salt.utils
import psutil,time

__opts__ = {}
def __virtual__():
    if salt.utils.is_windows():
        return False
    return 'gabia_httpd_check'

def loadavg():
    load_avg = os.getloadavg()
    return {'1-min': load_avg[0]}

def stat():
    ret = {}
    cpu_load = loadavg()
    cpu_load = cpu_load['1-min']
    mem = {}
    mem_info = psutil.virtual_memory()
    mem_percent = mem_info.percent
    #httpd_stat = __salt__['service.status']("httpd")
    httpd_count = __salt__['cmd.run']("ps -u nobody | grep -c http[d]",python_shell=True)
    httpd_count = int(httpd_count)
    if httpd_count == 0 :
        httpd_stat = 'False'
    else:
        httpd_stat = 'True'
    ret['loadavg'] = cpu_load
    ret['httpd_stat'] = httpd_stat
    ret['mem_percent'] = mem_percent
    return ret

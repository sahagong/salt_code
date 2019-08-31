# -*- coding: utf-8 -*-

# Import python libs
import os
import re
import fnmatch
import json

# Import salt libs
import salt.utils

__opts__ = {}

def __virtual__():
    if salt.utils.is_windows():
        return False
    return 'hw'

# list() : grains 에 따라 설정값이 추출 함수
def list():
    ret = {}
    ret['kernel_config'] = kernel()
    ret['serverinfo'] = serverinfo()
    ret['cronjob'] = cron()
    ret['mon'] = "G-C-M"
    ret = json.dumps(ret)

    return ret

# kernel()
def kernel():
    kernel_config_list = {}

    kernel_version = __salt__['cmd.run']("uname -r",python_shell=True)
    command_result = __salt__['cmd.run']("cat /etc/sysctl.conf | grep -v \# | grep -ve '^ *$'",python_shell=True)
    parameter = list_output(command_result, 1)

    kernel_config_list['kernel_version'] = kernel_version
    kernel_config_list['kernel_config'] = parameter

    return kernel_config_list


# serverinfo()
def serverinfo():
    server_info_list = {}

    #바디 벤더사, 모델명
    server_body_vendor = __salt__['cmd.run']("dmidecode -s 'system-manufacturer' | grep -v \#",python_shell=True)
    server_body_name = __salt__['cmd.run']("dmidecode -s 'system-product-name' | grep -v \#",python_shell=True)
    server_info_list['body_vendor'] = server_body_vendor
    server_info_list['body_name'] = server_body_name

    #CPU  개수, 모델명
    server_cpu_number = __salt__['cmd.run']("dmidecode | grep 'Processor Information' -A 5 | grep Family | grep -v Unknown | wc -l",python_shell=True)
    server_cpu_name = __salt__['cmd.run']("cat /proc/cpuinfo  | grep 'model name' | uniq | awk -F\: '{print $2}'",python_shell=True)
    server_info_list['cpu_number'] = server_cpu_number
    server_info_list['cpu_name'] = server_cpu_name

    #메모리 개수, 용량
    server_memory_number = __salt__['cmd.run']("dmidecode | grep 'Memory Device' -A 5 | grep Size | grep MB | wc -l",python_shell=True)
    server_memory_usage = __salt__['cmd.run']("dmidecode | grep 'Memory Device' -A 5 | grep Size | grep MB | awk 'BEGIN{sum=0}{split($0,line,\" \"); sum +=line[2];}END{print sum;}'",python_shell=True)
    server_info_list['memory_number'] = server_memory_number
    server_info_list['memory_usage'] = server_memory_usage

    #NIC 개수 , 사용 개수 , negotiation
    server_nic_number = __salt__['cmd.run']("dmidecode | grep NIC -A 5 | grep Enabled | wc -l",python_shell=True)
    server_nic_usenumber = __salt__['cmd.run']("ifconfig | grep Ethernet | awk '{print $5}' | sort | uniq | wc -l",python_shell=True)
    server_info_list['nic_number'] = server_nic_number
    server_info_list['nic_usenumber'] = server_nic_usenumber
    nic_list = __salt__['cmd.run']("ifconfig | grep -v '^ ' | grep -v ^$ | awk '{print $1}' | grep -v lo",python_shell=True)
    nic_list = nic_list.split('\n')
    for nic_interface in nic_list:
        result = __salt__['cmd.run']("ethtool "+ nic_interface +"| egrep '(Duplex|Speed)' | tr -d '\n' | awk '{print $2\" \"$4}'",python_shell=True)
        server_info_list['nic_negotiation_' + nic_interface] = result

    #DISK 정보
    server_disk_info = __salt__['cmd.run']("fdisk -l 2>&1 | grep 'Disk /' | awk '{print $2\" \"$3$4}'",python_shell=True)
    server_info_list['disk_info'] = server_disk_info

    #login 정보
    server_login_info = __salt__['cmd.run']("last -x -n 30 | grep -v 'wtmp begins'",python_shell=True)
    server_info_list['server_login'] = server_login_info

    #raid 정보
    if 'Dell' in server_body_vendor:
        sever_raid_exec = __salt__['cmd.run']("ls /opt/MegaRAID/MegaCli/MegaCli 2>/dev/null",python_shell=True)
        if 'MegaCli' in sever_raid_exec:
            sever_raid_info1 = __salt__['cmd.run']("/opt/MegaRAID/MegaCli/MegaCli -PDList -aALL | grep -v \\' | perl -p -e 's|\n|\<br\>|'",python_shell=True)
            sever_raid_info2 = __salt__['cmd.run']("/opt/MegaRAID/MegaCli/MegaCli -LDInfo -Lall -aALL | grep -v \\' | perl -p -e 's|\n|\<br\>|'",python_shell=True)
        else:
            sever_raid_info1 = __salt__['cmd.run']("/opt/MegaRAID/MegaCli/MegaCli64 -PDList -aALL | grep -v \\' | perl -p -e 's|\n|\<br\>|'",python_shell=True)
            sever_raid_info2 = __salt__['cmd.run']("/opt/MegaRAID/MegaCli/MegaCli64 -LDInfo -Lall -aALL | grep -v \\' | perl -p -e 's|\n|\<br\>|'",python_shell=True) 
    else:
        sever_raid_info1 = "None"
        sever_raid_info2 = "None"
    server_info_list['raid_physical_info'] = sever_raid_info1
    server_info_list['raid_virtual_info'] = sever_raid_info2

    #BIOS Release Date
    server_biosrd_exec = __salt__['cmd.run']("dmidecode -t 0 | grep Date | awk '{print $3}'",python_shell=True)
    server_info_list['bios_release_date'] = server_biosrd_exec    
 
    return server_info_list
    
# cron()
def cron():
    cron_cnf_list = {}
    cron_ret = {}
    cron_info_result = __salt__['cmd.run']("cat /etc/crontab | grep -v '#' |grep '*'; cat /var/spool/cron/* |grep -v '#' 2>/dev/null",python_shell=True)
    cron_cnf_list['cron_info'] = cron_info_result

    cron_tab_runparts = __salt__['cmd.run']("cat /etc/crontab |grep -v \# |grep -v ^$ | egrep -v 'hourly|daily|weekly|monthly'",python_shell=True)
    cron_default = __salt__['cmd.run']("cat /etc/anacrontab |egrep 'daily|weekly|monthly' | awk '{print $5}'",python_shell=True)
    cron_default = cron_default.split("\n")

    cron_defs_dir = {}
    cron_default.insert(0,"/etc/cron.hourly")
    for line_d in cron_default:
        cron_defs_value = {}
        if not len(line_d) == 1:
                cmd_list = __salt__['cmd.run']("/bin/ls -l " + line_d + " | grep \"^-rwx\" | awk '{print $5,$9}'",python_shell=True)
                cmd_list = cmd_list.split("\n")
                num = 0
                for file_line_d in cmd_list:
                        str_num = str(num)
                        value_num = 'value' + str_num
                        cron_defs_value[value_num] = file_line_d
                        num = num + 1
                cron_defs_dir[line_d] = cron_defs_value

        else:
           cron_defs_dir[line_d] == "None"


    cron_runparts = {}
    cron_runparts_dir = {}
    cron_tab_command = {}

    cron_tab_runparts = cron_tab_runparts.split("\n")
    command_num = 0
    for line in cron_tab_runparts:
        line = line.split()
        if len(line) > 6:
           cron_runparts_value={}
           cron_command = {}
           if line[6] == "run-parts":
                runparts_time_list = line[0:5]
                runparts_time_join = " ".join(runparts_time_list)
                cron_runparts_value['value1'] =  runparts_time_join

                runparts_file_list = __salt__['cmd.run']("/bin/ls -l " + line[7] + " | grep \"\\-rwx\" | awk '{print $5\" \"$9}'",python_shell=True)
                runparts_file_list = runparts_file_list.split("\n")
                file_counter = 2
                for file_line in runparts_file_list:
                        str_num = str(file_counter)
                        value_num = 'value' + str_num
                        cron_runparts_value[value_num] = file_line
                        file_counter = file_counter + 1
                cron_runparts_dir[line[7]] = cron_runparts_value
           else:
                time_list = line[0:5]
                time_join = " ".join(time_list)
                var_list = line[6:]
                var_join = " ".join(var_list)
                cron_command['value1'] = time_join
                cron_command['value2'] = var_join
                str_command_num = str(command_num)
                crontab_num = 'crontab' + str_command_num
                cron_tab_command[crontab_num] = cron_command
                command_num = command_num + 1

    cron_cnf_list['runparts'] = cron_runparts_dir
    cron_cnf_list['command'] = cron_tab_command

    cron_cnf_list['default'] = cron_defs_dir

    return cron_cnf_list



def list_output(config_list, flag): # 0 : split '\ ' / 1 : split '=' / 2 : split '=>' / 3 : split ':'

        config_list = config_list.split('\n')

        parameter = {}
        pre_line = ''   # 이전 컬럼 비교
        cnt = 0         # 첫번째 중복 카운트

        for line in config_list:
                if flag == 1:
                       line = line.split('\n')
                       line = line[0].split('=')
                elif flag == 2:
                       line = line.split('\n')
                       line = line[0].split('=>')
                elif flag == 3:
                       line = line.split('\n')
                       line = line[0].split(':')
                else:
                       line = line.split()

                value = {}
                num = 0

                #이전 컬럼 비교문
                if line[0] == pre_line:
                        dic = line[0] + '_' + str(cnt)
                        cnt = cnt+1
                else:
                        dic = line[0]
                        cnt = 1

                if len(line) == 1:
                        value['value1'] = 'None'
                        parameter[dic] = value
                        pre_line = line[0]
                        print parameter[dic]
                        pass

                for array in line:
                        if not num == 0:
                                numb = str(num)
                                result = 'value' + numb
                                value[result] = array
                        num = num + 1
                        parameter[dic] =  value

                pre_line = line[0]
        return parameter

def single_output(value_list):

     value_list = value_list.split('\n')
     value ={}
     num = 0

     for line in value_list:
         numb = str(num)
         result = 'value' + numb
         value[result] = line
         num = num + 1
     
     return value

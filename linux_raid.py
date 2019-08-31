# -*- coding: utf-8 -*-

# Import python libs
import os
import re
import fnmatch
import commands,time,os,sys,re

# Import salt libs
import salt.utils
import psutil,time
import os.path

__opts__ = {}
def __virtual__():
    if salt.utils.is_windows():
        return False
    return 'linux_raid'

def loadavg():
    load_avg = os.getloadavg()
    return {'1-min': load_avg[0],
            '5-min': load_avg[1],
            '15-min': load_avg[2]}


    #raid Á¤º¸

def raid_stats():
        sever_raid_exec = {}
	sever_raid_exec = __salt__['cmd.run']("ls /opt/MegaRAID/MegaCli/MegaCli 2>/dev/null",python_shell=True)
        
	if 'MegaCli' in sever_raid_exec:
            sever_raid_info = __salt__['cmd.run']("/opt/MegaRAID/MegaCli/MegaCli -LDinfo -Lall -aALL |egrep -w 'Default Cache Policy|Current Cache Policy'  | awk '{print $4}'",python_shell=True)
        else:
            sever_raid_info = __salt__['cmd.run']("/opt/MegaRAID/MegaCli/MegaCli64 -PDList -aALL | grep -v \\' | perl -p -e 's|\n|\<br\>|'",python_shell=True)

        raid_info = sever_raid_info.split('\n')
     
 	ret = {}
    	if raid_info[0] == raid_info[1] and raid_info[2] == raid_info[3]:

       	 	ret['policy'] = "Match"
	else:
		ret['policy'] = "Miss Match"


	return ret




	
	
	



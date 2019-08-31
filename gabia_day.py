# -*- coding: utf-8 -*-
import commands,time,os,sys,re
import salt.utils

def __virtual__():
    if salt.utils.is_windows():
        return False
    return 'gabia_day'

#exec: salt '*' gabia_day.stat
def stat():
    ret = {}
    ret['grains'] = __salt__['grains.item']('roles','serviced','process')
    ret['processlist'] = __salt__['cmd.run']("ps -e | grep -v -w CMD | awk '{print $NF}' | awk -F/ '{print $1}' | sort | uniq",python_shell=True)
	
    productname = __salt__['grains.item'] ("productname")
    productname = str(productname)
    productname = productname.replace("['","")
    productname = productname.replace("']","")

    osarch = __salt__['grains.item'] ("osarch")
    osarch = str(osarch)
    osarch = osarch.replace("['","")
    osarch = osarch.replace("']","")

    match = re.search('None',productname)
    if not match:
        if 'PowerEdge' in productname:
             match2 = re.search('None',osarch)
             if not match2:
                  if 'x86_64' in osarch:
                      if os.path.isfile("/opt/MegaRAID/MegaCli/MegaCli64"):
                          physdrv_status = __salt__['cmd.run']("/opt/MegaRAID/MegaCli/MegaCli64 -PDList -aALL | grep \"Count\" | grep -v 0",python_shell=True)
                          if physdrv_status:
                             physdrv_status = "ERR - PhysDrv RAID_STATUS - "
                          raid_status = __salt__['cmd.run']("/opt/MegaRAID/MegaCli/MegaCli64 -LDInfo -Lall -aALL | grep \"^State\" | awk '{print $NF}'",python_shell=True)
                          if raid_status.strip():
                             raid_status = raid_status.replace("\n", "_")
                             ret['raid_status'] = physdrv_status + raid_status
                          else:
                             ret['raid_status'] = "WARN -  Raid controller not exist"
                      else:
                          ret['raid_status'] = "WARN -  No such raid check file"
                  if 'i686' in osarch:
                      if os.path.isfile("/opt/MegaRAID/MegaCli/MegaCli"):
                          physdrv_status = __salt__['cmd.run']("/opt/MegaRAID/MegaCli/MegaCli -PDList -aALL | grep \"Count\" | grep -v 0",python_shell=True)
                          if physdrv_status:
                             physdrv_status = "ERR - PhysDrv RAID_STATUS - "
                          raid_status = __salt__['cmd.run']("/opt/MegaRAID/MegaCli/MegaCli -LDInfo -Lall -aALL | grep \"^State\" | awk '{print $NF}'",python_shell=True)
                          if raid_status.strip():
                             raid_status = raid_status.replace("\n", "_")
                             ret['raid_status'] = physdrv_status + raid_status
                          else:
                             ret['raid_status'] = "WARN -  Raid controller not exist"
                      else:
                          ret['raid_status'] = "WARN -  No such raid check file"
        elif 'ProLiant' in productname:
            if os.path.isfile("/opt/compaq/hpacucli/bld/hpacucli"):
                raid_status = __salt__['cmd.run']("/opt/compaq/hpacucli/bld/hpacucli ctrl all show config |grep \"RAID\"| grep \"logicaldrive\" | sed 's/)//g'| awk -F\" \" '{print $7}'",python_shell=True)
                if raid_status.strip():
                    raid_status = raid_status.replace("\n", "_")
                    ret['raid_status'] = raid_status
                else:
                    ret['raid_status'] = "WARN -  Raid controller not exist"
            elif os.path.isfile("/usr/sbin/hpacucli"):
                raid_status = __salt__['cmd.run']("/usr/sbin/hpacucli ctrl all show config |grep \"RAID\"| grep \"logicaldrive\" | sed 's/)//g'| awk -F\" \" '{print $7}'",python_shell=True)
                if raid_status.strip():
                    raid_status = raid_status.replace("\n", "_")
                    ret['raid_status'] = raid_status
                else:
                    ret['raid_status'] = "WARN -  Raid controller not exist"
            else:
                ret['raid_status'] = "WARN -  No such raid check file"
        else:
                ret['raid_status'] = "WARN -  This device is not DELL or HP"

    ret['mon'] = "G-R-S"

    return ret


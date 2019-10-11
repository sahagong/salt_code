# -*- coding: utf-8 -*-

# Import python libs
import os
import re
import fnmatch
import commands,time,os,sys,re
import time,json 

# Import salt libs
import salt.utils
import psutil,time
import os.path

__opts__ = {}
def __virtual__():
    if salt.utils.is_windows():
        return False
    return 'admin_linux'

def loadavg():
    load_avg = os.getloadavg()
    return {'1-min': load_avg[0],
            '5-min': load_avg[1],
            '15-min': load_avg[2]}

def cpuinfo():
	
	cpuinfo = {}

	old_cpustat = __salt__['cmd.run']("cat /tmp/salt_cpuinfo 2>/dev/null",python_shell=True)
        __salt__['cmd.run']("cat /proc/stat | grep -w cpu > /tmp/salt_cpuinfo",python_shell=True)
	new_cpustat = __salt__['cmd.run']("cat /tmp/salt_cpuinfo 2>/dev/null",python_shell=True)
	
	new_cpuinfo_token = new_cpustat.split()
        new_cpu_um = new_cpuinfo_token[1]
        new_cpu_nice = new_cpuinfo_token[2]
        new_cpu_system = new_cpuinfo_token[3]
        new_cpu_idle = new_cpuinfo_token[4]
        new_cpu_iowait = new_cpuinfo_token[5]
        new_cpu_user_data = int(new_cpu_um)+int(new_cpu_nice)
        new_cpu_system_data = int(new_cpu_system)
        new_cpu_idle_data = int(new_cpu_idle)
        new_cpu_iowait_data = int(new_cpu_iowait)

	if old_cpustat and not old_cpustat.isspace():
		old_cpuinfo_token = old_cpustat.split()
	        old_cpu_um = old_cpuinfo_token[1]
	        old_cpu_nice = old_cpuinfo_token[2]
	        old_cpu_system = old_cpuinfo_token[3]
	        old_cpu_idle = old_cpuinfo_token[4]
	        old_cpu_iowait = old_cpuinfo_token[5]
	        old_cpu_user_data = int(old_cpu_um)+int(old_cpu_nice)
	        old_cpu_system_data = int(old_cpu_system)
	        old_cpu_idle_data = int(old_cpu_idle)
	        old_cpu_iowait_data = int(old_cpu_iowait)
	else:
		old_cpu_user_data = new_cpu_user_data
		old_cpu_system_data = new_cpu_system_data
		old_cpu_idle_data = new_cpu_idle_data
		old_cpu_iowait_data = new_cpu_iowait_data

	cpu_user_data = new_cpu_user_data-old_cpu_user_data
        cpu_system_data = new_cpu_system_data-old_cpu_system_data
        cpu_idle_data = new_cpu_idle_data-old_cpu_idle_data
        cpu_iowait_data = new_cpu_iowait_data-old_cpu_iowait_data
	
	total_data = cpu_user_data + cpu_system_data + cpu_idle_data + cpu_iowait_data
	cpu_percent_data = cpu_user_data + cpu_system_data + cpu_iowait_data
	
	if ( cpu_user_data == 0 ):
		cpuinfo['cpu_user'] = 0
	else:
		cpuinfo['cpu_user'] = cpu_user_data * 100 / total_data

	if ( cpu_system_data == 0 ):
		cpuinfo['cpu_system'] = 0
        else:
		cpuinfo['cpu_system'] = cpu_system_data * 100 / total_data

	if ( cpu_idle_data == 0 ):
		cpuinfo['cpu_idle'] = 0
        else:
	        cpuinfo['cpu_idle'] = cpu_idle_data * 100 / total_data

	if ( cpu_iowait_data == 0 ):
		cpuinfo['cpu_iowait'] = 0
        else:
	        cpuinfo['cpu_iowait'] = cpu_iowait_data * 100 / total_data

	if ( cpu_percent_data == 0 ):
	        cpuinfo['cpu_percent'] = 0
	else:
        	cpuinfo['cpu_percent'] = cpu_percent_data * 100 / total_data
	
	return cpuinfo
		
	


def trafficinfo():
	
	trafficinfo = {}
	new_trafficinfo = {}
	infointerface = {}
	disuse_int_list = []	
	old_data = {}
	new_data = {}
	filename = "/tmp/salt_traffic"

	interfaceinfo = __salt__['network.interfaces']()

	for interface in interfaceinfo:
		if ( interface == "sit0" or interface == "lo" or interfaceinfo[interface]["up"] == False ):
			disuse_int_list.append(interface)

	disuse_int_list.sort()
	command = "cat /proc/net/dev | grep -v Inter | grep -v packets"
	for disuse_int in disuse_int_list:
		command = command + " | grep -v " + disuse_int
	
	trafficstat_result = __salt__['cmd.run'](command,python_shell=True)
	new_trafficinfo["time"] = str(round( time.time() , 2))
	
	trafficstat = trafficstat_result.split('\n')
	for int_trafficstat in trafficstat:
		trafficdata_split = int_trafficstat.split(':')
		trafficinterface = trafficdata_split[0].strip()
		trafficdata_list = trafficdata_split[1].split()
		infointerface["recv_bytes"] = trafficdata_list[0]
		infointerface["send_bytes"] = trafficdata_list[8]
		infointerface["packets_recv"] = trafficdata_list[1]
		infointerface["packets_sent"] = trafficdata_list[9]
		new_trafficinfo[trafficinterface] = infointerface
		infointerface={}
	
	if os.path.exists(filename):
		try:
			old_data = json.load(open(filename))
		except ValueError, e:
			old_data = new_trafficinfo
			os.remove(filename)
	else:
		old_data = new_trafficinfo
	
	json.dump(new_trafficinfo, open(filename,'w')) 

	timegap = round( float(new_trafficinfo["time"]) - float(old_data["time"]) , 2 )
	
	total = {}
	total["all_recv"] = 0
	total["all_sent"] = 0
	total["all_packets_recv"] = 0
	total["all_packets_sent"] = 0
	for new_interface in new_trafficinfo:
		if ( new_interface != "time" ):
			if ( new_trafficinfo[new_interface]["recv_bytes"] == old_data[new_interface]["recv_bytes"] ):
				new_data[new_interface+"_recv"] = 0
			else:
				new_data[new_interface+"_recv"] = int(( int(new_trafficinfo[new_interface]["recv_bytes"]) - int(old_data[new_interface]["recv_bytes"]) ) * 8 / timegap)

			if ( new_trafficinfo[new_interface]["send_bytes"] == old_data[new_interface]["send_bytes"] ):
				new_data[new_interface+"_sent"] = 0
			else:
				new_data[new_interface+"_sent"] = int(( int(new_trafficinfo[new_interface]["send_bytes"]) - int(old_data[new_interface]["send_bytes"]) ) * 8 / timegap)

			if ( new_trafficinfo[new_interface]["packets_recv"] == old_data[new_interface]["packets_recv"] ):
				new_data[new_interface+"_packets_recv"] = 0
			else:
				new_data[new_interface+"_packets_recv"] = int(( int(new_trafficinfo[new_interface]["packets_recv"]) - int(old_data[new_interface]["packets_recv"]) ) / timegap)

			if ( new_trafficinfo[new_interface]["packets_sent"] == old_data[new_interface]["packets_sent"] ):
				new_data[new_interface+"_packets_sent"] = 0
			else:
				new_data[new_interface+"_packets_sent"] = int(( int(new_trafficinfo[new_interface]["packets_sent"]) - int(old_data[new_interface]["packets_sent"]) ) / timegap)

			total["all_recv"] = total["all_recv"] + new_data[new_interface+"_recv"]
			total["all_sent"] = total["all_sent"] + new_data[new_interface+"_sent"]
			total["all_packets_recv"] = total["all_packets_recv"] + new_data[new_interface+"_packets_recv"]
			total["all_packets_sent"] = total["all_packets_sent"] + new_data[new_interface+"_packets_sent"]
			trafficinfo[new_interface] = new_data
			new_data = {}
	
	trafficinfo["all"] = total

	return trafficinfo

	

def iostat():
        iostat = __salt__['cmd.run']("/usr/bin/iostat -p -d -k 1 2 | grep -v \"^Linux\" | grep -v \"Device\" | grep -v \"^$\" | awk '{print $1,$3,$4}'",python_shell=True)

        lines = iostat.split('\n')
        size = len(lines) / 2

        iostat = {}

        count = 0
        for line in lines:

                count = count + 1
                if ( count > size):
                        stat = {}
                        lists = line.split(" ")
                        device = lists[0]
                        rd = lists[1]
                        wr = lists[2]

                        stat[ str(device) + '_rd'] = rd
                        stat[ str(device) + '_wr'] = wr
                        iostat[device] = stat
                        #print device,rd,wr
                        #traffic[
                        #print line
        nfscheck = __salt__['cmd.run']("cat /etc/mtab | grep -w nfs | grep -v sunrpc | awk '{print $1}'",python_shell=True)



        if (len(nfscheck) > 0):
                lists = nfscheck.split('\n')
                size = len(lists) / 2


                #nfsstat = __salt__['cmd.run']("/usr/bin/iostat -n -k | grep %s | awk '{print $1,$2,$3}'" % (point),python_shell=True)
                nfsstat = __salt__['cmd.run']("/usr/bin/iostat -n -k  1 2 | awk '{print $1,$2,$3}' | grep -v ^Linux  | grep -v \"^$\" | grep -v \"^ \" | grep -v Device | grep -v avg-cpu | grep -v Filesystem|awk '{print $1,$2,$3}'",python_shell=True)
                nfsline = nfsstat.split('\n')
                count = 0
                for line in nfsline:
                    count = count + 1
                    if ( count > size):
                        stat = {}
                        lists = line.split(" ")
                        device = lists[0]
                        rd = lists[1]
                        wr = lists[2]
                        stat[ str(device) + '_rd'] = rd
                        stat[ str(device) + '_wr'] = wr
                        iostat[device] = stat

        return iostat

def devtraffic():
        interval = 1
        network = psutil.net_io_counters(pernic=True)
        before = {}
        after = {}
        cur = {}
        for key in network:
                traffic = {}
                interface = __salt__['network.interfaces']()
                interface = interface[key]['up']
                if not key == 'lo' and not key == 'sit0' and interface == True :
                        traffic['sent'] = network[key][0]
                        traffic['recv'] = network[key][1]
                        before[key] = traffic

        time.sleep(interval)

        network = psutil.net_io_counters(pernic=True)
        for key in network:
                traffic = {}
                interface = __salt__['network.interfaces']()
                interface = interface[key]['up']
                interface2 = interface
                if not key == 'lo' and not key == 'sit0' and interface == True :
                        traffic['sent'] = network[key][0]
                        traffic['recv'] = network[key][1]
                        after[key] = traffic
        all_sent = 0
        all_recv = 0
        for key in before:
                traffic = {}
                traffic[ str(key) + '_sent'] = (int(after[key]['sent']) - int(before[key]['sent'])) * 8 / interval
                traffic[ str(key) + '_recv'] = (int(after[key]['recv']) - int(before[key]['recv'])) * 8 / interval
                all_sent = int(all_sent) + (int(after[key]['sent']) - int(before[key]['sent'])) * 8 / interval
                all_recv = int(all_recv) + (int(after[key]['recv']) - int(before[key]['recv'])) * 8 / interval
                cur[key] = traffic
        traffic = {}
        traffic['all_sent'] = all_sent
        traffic['all_recv'] = all_recv
        cur['all'] = traffic
        return cur

def pcietemp():
	degree = {}

	sensor_num = 0
	dev_command = "df -P | egrep 'hio|nvme' 2>1" 
	dev_result = __salt__['cmd.run'](dev_command,python_shell=True)
	
	dev_result = dev_result.split(' ')

	if 'nvme' in dev_result[0]:
		dev = dev_result[0].split('n1')
		cmd="/usr/bin/hdm"
		command1 = cmd + " generate-report --output-format mini --path " + dev[0] + " | egrep 'Main|Inlet' | awk '{print $NF}'"
		temp_result=__salt__['cmd.run'](command1,python_shell=True)

		temp=temp_result.split('\n')

		for value in temp:

			degree['sensor' + str(sensor_num)] = value
			sensor_num = sensor_num + 1

	elif 'hio' in dev_result[0]:
		cmd ="/usr/sbin/hio_temperature"
		command2 = cmd + " -d " + dev_result[0] + " | grep 'Controller' | awk '{print $NF}'"
		temp_result=__salt__['cmd.run'](command2,python_shell=True)

		temp=temp_result.split('\n')

		for value in temp:

			degree['sensor' + str(sensor_num)] = value
			sensor_num = sensor_num + 1
	else:
		degree['none_sensor'] = 'null'

	return degree

def test_stat():
    ret = {}
    ret['disk_percent'] = disk_percent()
    ret['diskinode_percent'] = diskinode_percent()
    ret['mem_usage'] = mem()
    ret['web_checked'] = web_checked()

    return ret

def disk_percent():
    disk = dict()
    disk_percent = __salt__['disk.percent']()
    for part,value in disk_percent.items():
        match = re.search('/dev',part)
        if not match:
           value = value.replace("%","")
           disk[part] = int(value)

    return disk

def diskinode_percent():
    diskinode = dict()
    diskinode_result = __salt__['cmd.run']("df -iP | grep -v IUsed | awk '{print $1\" \"$5}'",python_shell=True)
    diskinode_result_split=diskinode_result.split('\n')
    for diskinode_result_line in diskinode_result_split:
        diskinode_result_line_split = diskinode_result_line.split()
        inodevalue = diskinode_result_line_split[1].replace("%","")
	match = re.search('-',inodevalue)
        if not match:
                diskinode[diskinode_result_line_split[0]] = int(inodevalue)

    return diskinode

def mem():
    mem = {}
    global mem_percent
    global swap_percent
    mem_info = psutil.virtual_memory()
    mem_percent = mem_info.percent
    mem['buffer+cache'] = mem_info.buffers + mem_info.cached
    mem['total'] = mem_info.total
    mem['used'] = mem_info.used
    mem['real_used'] = mem_info.used - mem_info.buffers - mem_info.cached
    swap_info = psutil.swap_memory()
    swap_total = swap_info.total
    swap_used = swap_info.used
    swap_percent = swap_info.percent
    swap_total = int(swap_total)
    swap_used = int(swap_used)
    swap_percent = int(swap_percent)
    mem['swap_total'] = swap_total
    mem['swap_used'] = swap_used
    mem['swap_percent'] = swap_percent

    return mem

def web_checked():
    ret6 = {}
    web_checked = __grains__.get('web_checked')
    web_checked = str(web_checked)
    web_checked = web_checked.replace("['","")
    web_checked = web_checked.replace("']","")
    match =re.search('None',web_checked)
    if not match:
            web_checked = web_checked.split("&&")
            for i in web_checked:
                res = i.split("/")
                resc = len(res)
                if 'https:' in res:
                        if ':' in res[2]:
                                jres = res[2].split(":")
                                if resc <= 4:
                                        w, stdin_lines3 = commands.getstatusoutput("LANG=C;/usr/lib64/nagios/plugins/check_http --ssl --sni --timeout=3 -H %s -u https://%s/ -p %s" % (jres[0],jres[0],jres[1]))
                                        ret6[i] = w
                                else:
                                        w, stdin_lines4 = commands.getstatusoutput("LANG=C;/usr/lib64/nagios/plugins/check_http  --ssl --sni --timeout=3 -H %s -u https://%s/%s -p %s" % (jres[0],jres[0],res[3],jres[1]))
                                        ret6[i] = w
                        else:
                                if resc < 4:
                                        w, stdin_lines5 = commands.getstatusoutput("LANG=C;/usr/lib64/nagios/plugins/check_http --ssl --sni --timeout=3 -H %s -u https://%s/ -p 443" % (res[2],res[2]))
                                        ret6[i] = w
                                else:
                                        w, stdin_lines6 = commands.getstatusoutput("LANG=C;/usr/lib64/nagios/plugins/check_http --ssl --sni --timeout=3 -H %s -u https://%s/%s -p 443" % (res[2],res[2],res[3]))
                                        ret6[i] = w

                else:
                        if resc <= 4:
                               w, stdin_lines = commands.getstatusoutput("LANG=C;/usr/lib64/nagios/plugins/check_http --timeout=3 -H %s -u /%s -p 80" % (res[2],res[3]))
                        else:
                               w, stdin_lines2 = commands.getstatusoutput("LANG=C;/usr/lib64/nagios/plugins/check_http --timeout=3 -H %s -u /%s/%s -p 80" % (res[2],res[3],res[4]))
                        if resc <= 4:
                                ret6[i] = w
                        else:
                                ret6[i] = w
    return ret6

def roles():
#    global roles
    roles = __grains__.get('roles')
    roles = str(roles)
    roles = roles.replace("['","")
    roles = roles.replace("']","")

    return roles

def ipmi():
    ret = __salt__['cmd.run']("ipmi-sel | tail -n 5",python_shell=True)
    
    return ret

def stat():
    ret = {}
    ret2 = {}
    ret3 = {}
    ret4 = {}
    ret5 = {}
    ret6 = {}
    cpu_load = loadavg()
    cpu_load = cpu_load['1-min']
#    cpu = psutil.cpu_times_percent(interval=0.3, percpu=False)
#    cpu_percent = 100 - cpu.idle

    ret['disk_percent'] = disk_percent()
    ret['diskinode_percent'] = diskinode_percent()
    ret['mem_usage'] = mem()
    ret['roles'] = roles()
    ret['web_checked'] = web_checked()
    ret['iostat'] = iostat()
    ret['serviced'] = serviced()
    ret['process'] = process()

    lvs = __grains__.get('lvs')
    lvs = str(lvs)
    lvs = lvs.replace("['","")
    lvs = lvs.replace("']","")

    osrelease = __salt__['grains.item'] ("osfinger")
    osrelease = str(osrelease)
    osrelease = osrelease.replace("['","")
    osrelease = osrelease.replace("']","")

    mount_stat = __salt__['cmd.run']('mount | grep -v \(rw | wc -l',python_shell=True)

    match = re.search('None',osrelease)
    if not match:
        if 'CentOS-5' in osrelease:
           if os.path.isfile("/proc/sys/net/ipv4/netfilter/ip_conntrack_count"):
		   ip_conn_count = __salt__['cmd.run']("cat /proc/sys/net/ipv4/netfilter/ip_conntrack_count",python_shell=True)
		   ip_conn_count = float(ip_conn_count)
		   ip_conn_max = __salt__['cmd.run']("cat /proc/sys/net/ipv4/ip_conntrack_max",python_shell=True)
		   ip_conn_max = float(ip_conn_max)
		   ip_conn_percent = ip_conn_count / ip_conn_max * 100
		   ip_conn_percent = round(ip_conn_percent,2)
		   ret2['ip_conntrack'] = ip_conn_count
		   ret2['ip_conn_percent'] = ip_conn_percent
        elif 'CentOS-6' in osrelease:
           if os.path.isfile("/proc/sys/net/netfilter/nf_conntrack_count"):
		   ip_conn_count = __salt__['cmd.run']("cat /proc/sys/net/netfilter/nf_conntrack_count",python_shell=True)
		   ip_conn_count = float(ip_conn_count)
		   ip_conn_max = __salt__['cmd.run']("cat /proc/sys/net/netfilter/nf_conntrack_max",python_shell=True)
		   ip_conn_max = float(ip_conn_max)
		   ip_conn_percent = ip_conn_count / ip_conn_max * 100
		   ip_conn_percent = round(ip_conn_percent,2)
		   ret2['ip_conntrack'] = ip_conn_count
		   ret2['ip_conn_percent'] = ip_conn_percent


    traffic = trafficinfo()
    ret['traffic'] = traffic
    ret2['loadavg'] = cpu_load
    ret2['mem_info'] = mem_percent

    cpustat = cpuinfo()
    ret2['cpu_idle'] = cpustat['cpu_idle']
    ret2['cpu_iowait'] = cpustat['cpu_iowait']
    ret2['cpu_system'] = cpustat['cpu_system']
    ret2['cpu_user'] = cpustat['cpu_user']
    ret2['cpu_percent'] = cpustat['cpu_percent']

    ret2['swap_info'] = swap_percent
    ret['mount_stat'] = mount_stat
    ret['mon'] = "G-S-M_hi"

    match = re.search('None',roles())
    if not match:
            if 'webserver' in roles():
                web_count = __salt__['cmd.run']("ps -u nobody | grep -c httpd",python_shell=True)
		web_count = int(web_count)
                ret6['web_count'] = web_count
            if 'mysql' in roles():
                mysql_ver = __salt__['cmd.run']("mysql -V | awk '{print $5}' | awk -F. '{print $1\".\"$2}'",python_shell=True)
		if ( float(mysql_ver) > 5.5):
                	mysql_count = __salt__['cmd.run']("mysql --login-path=/root -e 'show processlist' | wc -l",python_shell=True)
		else:
			mysql_count = __salt__['cmd.run']("mysql -u root -p'admin' -e 'show processlist' | wc -l",python_shell=True)
		mysql_count = int(mysql_count)
                ret6['mysql_count'] = mysql_count
            if 'queue' in roles():
                queue_count = __salt__['cmd.run']("find /var/qmail/queue/mess -type f | wc -l",python_shell=True)
		queue_count = int(queue_count)
                ret6['queue_count'] = queue_count
            if 'sendmail' in roles():
                queue_count = __salt__['cmd.run']('let "c=`find /var/spool/mqueue/* -type f |wc -l`/2";echo $c',python_shell=True)
		queue_count = int(queue_count)
                ret6['queue_count'] = queue_count
            if 'spam' in roles():
                queue_count = __salt__['cmd.run']("find /sniper/snipe/queue/mess -type f | wc -l",python_shell=True)
                queue_count = int(queue_count)
                ret6['queue_count'] = queue_count
            if 'pop3' in roles():
                pop3_count = __salt__['cmd.run']("ps -ef | grep popup | wc -l",python_shell=True)
		pop3_count = int(pop3_count)
                ret6['pop3_count'] = pop3_count
            if 'couch' in roles():
                couch_count = __salt__['cmd.run']("ps -efT | grep couch | wc -l",python_shell=True)
		couch_count = int(couch_count)
                ret6['couch_count'] = couch_count
            if 'swift' in roles():
                swift_count = __salt__['cmd.run']("ps -efT | grep swift | wc -l",python_shell=True)
		swift_count = int(swift_count)
                ret6['swift_count'] = swift_count
            if 'message' in roles():
                message_count = __salt__['cmd.run']("ss -s | head -n 1 |awk -F' ' '{print $2}'",python_shell=True)
                message_count = int(message_count)
                ret6['message_count'] = message_count
            if 'wowza' in roles():
                wowza_count = __salt__['cmd.run']("ps -efT | grep wowz[a] -c",python_shell=True)
                wowza_count = int(wowza_count)
                ret6['wowza_count'] = wowza_count
            if 'ffmpeg' in roles():
                ffmpeg_count = __salt__['cmd.run']("ps -ef | grep ffmpe[g] -c",python_shell=True)
                ffmpeg_count = int(ffmpeg_count)
                ret6['ffmpeg_count'] = ffmpeg_count
            if 'lighttpdcount' in roles():
                lighttpdcount_count = __salt__['cmd.run']("curl -s http://localhost/server-status?auto | grep 'BusyServers' | awk '{print $2}'",python_shell=True)
                lighttpdcount_count = int(lighttpdcount_count)
                ret6['lighttpdcount_count'] = lighttpdcount_count
            if 'totaldb' in roles():
                totaldb_count = __salt__['cmd.run']("mysql -u root -p'admin' -e 'select count(*) from checkdb.work_recv_allowblock' | grep -v - | grep -v count",python_shell=True)
                totaldb_count = int(totaldb_count)
                ret6['row_totaldb_count'] = totaldb_count

    sockstat = __salt__['cmd.run']("ss -s | grep \"^TCP\:\" | awk '{print $2}'",python_shell=True)
    ret2['sockstat'] = int(sockstat)

    sendmail_dir = "/var/spool/mqueue/"
    postfix_dir = "/var/spool/postfix/maildrop/"
    if os.path.isdir("%s" % sendmail_dir):
           ret2['sendmail_count'] = int(os.popen("ls %s -r | wc -l" % sendmail_dir).read())
    if os.path.isdir("%s" % postfix_dir):
           ret2['postfix_count'] = int(os.popen("ls %s -r | wc -l" % postfix_dir).read())

    ret['count'] = ret2
    ret['service_count'] = ret6

    match =re.search('None',lvs)
    if not match:
            lvs = lvs.split("&")
            for i in lvs:
                info = {}
                #ret4[i] = __salt__['ps.pgrep'](i)
                res = i.split(":")
                ip = res[0]
                port = res[1]
                a = __salt__['cmd.run']("ipvsadm -l -n --rate -t %s:%s|grep '%s:%s' | awk '{print $6}'" % (ip,port,ip,port),python_shell=True)
                info['InBPS'] = a
                b = __salt__['cmd.run']("ipvsadm -l -n --rate -t %s:%s|grep ':%s' | grep -v '%s:%s' | wc -l" % (ip,port,port,ip,port),python_shell=True)
                info['realserver'] = b
                # ipvsadm -l -n --rate -t 10.10.10.2:1358 | grep "1358" | grep -v "10.10.10.2:1358" | wc -l
                #w = __salt__['cmd.run']("ipvsadm -l -n --rate -t 10.10.10.2:1358")
                ret5[i] =  info
                # return __salt__['cmd.run']('ls %s' % list)
            ret['lvs'] = ret5

    return ret

def process():
    ret4 = {}
    process = __grains__.get('process')
    process = str(process)
    process = process.replace("['","")
    process = process.replace("']","")
    match =re.search('None',process)
    if not match:
            process = process.split("&")
            for i in process:
                if i == 'sendmail':
                    w = __salt__['cmd.run']("ps -ef | egrep -c 'sendmail: accepting connection[s]|sendmail: Queue runner@[0]'",python_shell=True)
                    w = int(w)
                    if w > 1:
                        ret4[i] = 1
                    else:
                        ret4[i] = -1
                elif i == "replication":
                        w = __salt__['cmd.run']("mysql --login-path=/root -e 'SHOW SLAVE STATUS \G' 2>>/dev/null | grep _Running: | awk '{ if ($2 == \"Yes\") n=1; else n=0; print n}' | tr '\n' ' '",python_shell=True)
                        if w == "1 1":
                                ret4[i] = 1
                        else:
                                ret4[i] = 0
                else:
                    #ret4[i] = __salt__['ps.pgrep'](i)
                    w = __salt__['cmd.run']("ps -eo command|grep -v grep |grep %s|wc -l" % i,python_shell=True)
                    w = int(w)
                    if w > 0:
                        ret4[i] = 1
                    else:
                        ret4[i] = -1
                    # return __salt__['cmd.run']('ls %s' % list)
    return ret4

def serviced():
    ret3 = {}
    serviced = __grains__.get('serviced')
    serviced = str(serviced)
    serviced = serviced.replace("['","")
    serviced = serviced.replace("']","")

    match = re.search('None',serviced)
    if not match:
            serviced = serviced.split("&")
            for i in serviced:
                if i == 'httpd':
                    httpd_count = __salt__['cmd.run']("ps -u nobody | grep -c httpd",python_shell=True)
                    httpd_count = int(httpd_count)
                    if httpd_count == 0:
                        ret3[i] = 0
                    else:
                        ret3[i] = 1
                else:
                    ret3[i] = __salt__['service.status'](i)
                    ret3[i] = int(ret3[i])
    return ret3


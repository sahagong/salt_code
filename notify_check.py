#!/usr/bin/python

import pyinotify
import os
import sys,socket
import requests
import commands
import json
import urllib2
import urllib
import re
import psutil
import hashlib
import time
import logging
import signal
from pyinotify import WatchManager
from pyinotify import Notifier
from pyinotify import ALL_EVENTS

date_cur = time.ctime()
pid='/var/run/pyinotify.pid'
direc='/root/gabia_mon/'

status, stdin_lines = commands.getstatusoutput("cat " + direc +"notify_dir")
dir_list = stdin_lines.split('\n')



## host name
def get_hostname():
        hostname = socket.gethostname()
        return hostname

## Logging
def send_init(event):
	watch_data = {}
        send_data = {}
	def get_hostname():
            hostname = socket.gethostname()
            return hostname

	def logger_init(event):

      	   file_log=open('/var/log/inotify.log','a')
	   data_log=(date_cur, str(event), '\n')
   

           if str(event.maskname) == "IN_CREATE" \
              or str(event.maskname) == "IN_CREATE|IN_ISDIR" \
              or str(event.maskname) == "IN_DELETE|IN_ISDIR" \
              or str(event.maskname) == "IN_DELETE" \
              or str(event.maskname) == "IN_MOVED_FROM" \
              or str(event.maskname) == "IN_MOVED_TO":
           

              if str(event.dir) == "False":
		event_type="file"
                watch_data['type'] = event_type
                watch_data['name'] = str(event.pathname)
		watch_data['action'] = str(event.maskname)
	      elif str(event.dir) == "True":
		event_type="directory"
                watch_data['type'] = event_type
                watch_data['name'] = str(event.pathname)
		watch_data['action'] = str(event.maskname)
              else:
                event_type="etc"
                watch_data['type'] = event_type
                watch_data['name'] = str(event.pathname)
		watch_data['action'] = str(event.maskname)

              file_w=open( direc + 'watch','a')
              data_w=(str(watch_data), '\n')

              file_log.writelines(data_log)
              file_log.close()

              file_w.writelines(data_w)
              file_w.close()


	#watch_data['date'] = date_cur
        #watch_data['makename'] = str(event.maskname)
	#watch_data['name'] = str(event.name)
	#watch_data['path'] = str(event.path)
	#watch_data['pathname'] = str(event.pathname)

        #send_data={"watch":{"001":["1","2"]},"title":"test"}
  
	if (str(event.maskname)):
          data = urllib.urlencode(send_data)

          try:	
		logger_init(event)
  
          except IOError as err:
                print "access error watch" % err
                sys.exit()

 
# Instanciate a new WatchManager (will be used to store watches).
wm = pyinotify.WatchManager()
# Associate this WatchManager with a Notifier (will be used to report and
# process events).
notifier = pyinotify.Notifier(wm, default_proc_fun=send_init)
# Add a new watch on "/root/gabia_mon/watch" directory for ALL_EVENTS.
for path_r in dir_list:
     match = re.search('^#',path_r)
     if not match:
        if(path_r):
	      wm.add_watch(path_r, mask=pyinotify.IN_MODIFY|\
  				      pyinotify.IN_ATTRIB|\
				      pyinotify.IN_CLOSE_WRITE|\
				      pyinotify.IN_MOVED_FROM|\
				      pyinotify.IN_MOVED_TO|\
				      pyinotify.IN_CREATE|\
				      pyinotify.IN_DELETE|\
				      pyinotify.IN_DELETE_SELF|\
			              pyinotify.IN_MOVE_SELF\
				     , rec=True, auto_add=True)

# Loop forever and handle events.
if len(sys.argv) == 2:
  if 'start' == sys.argv[1]:
       if os.path.exists(pid):
          message = "pidfile %s exist. Daemon is running?\n"
          sys.stderr.write(message % pid)
       else: 
         try:
	    print "iwatch start..OK"
            notifier.loop(daemonize=True, pid_file=pid, stderr='/var/log/messages')

         except OSError as err:
            print "start fail" % err

  elif "stop" == sys.argv[1]:
       if not os.path.isfile(pid):
          message = "pidfile %s does not exist. Daemon not running?\n"
	  sys.stderr.write(message % pid)
       else:
	 try:
            if os.path.exists(pid):
               pf = open(pid,'r')
               w_pid = int(pf.read().strip())
               os.kill(w_pid, signal.SIGTERM)
               time.sleep(0.1)
               os.remove(pid)
	       print "iwatch stop.. OK"
         except OSError as err:
            print "start fail" % err
  else:
      print "stop or start"
else:
  print "stop or start"


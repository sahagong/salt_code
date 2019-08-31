# -*- coding: utf-8 -*-

import sys, os, time, re
import salt.utils

__opts__ = {}
def __virtual__():
        kernel = __grains__.get('kernel')
        if kernel == "Linux":
                return 'gabia_message'
        else:
                return (False, 'This module is only available running Linux only')
def stat():
        #Pattern delimiter is "%%"
        #logfile_pattern = {'filename':'pattern1%%pattern2%%pattern3','filename2':pattern1%%pattern2'}
        #logfile_pattern = {'/var/log/messages':'kernel:&&i/o error%%kernel:&&Over temperature%%fs error%%kernel: linux version%%Too many open files%%task abort:'}
	dev  = __salt__['cmd.run']("find /dev/ -type b | grep -v ram | grep -v loop | awk -F/ '{print $3}'",python_shell=True)
        dev = dev.split('\n')
        devpatten = ""
        for devline in dev:
                devpatten = devpatten + 'kernel:&&' + devline + "%%"
        devpatten = devpatten + 'kernel:&&i/o error%%kernel:&&Over temperature%%fs error%%kernel: linux version%%Too many open files%%task abort:'
        logfile_pattern = {'/var/log/messages':devpatten , '/var/log/httpd/office.hiworks.com_error_log':'crit]' , '/var/log/httpd/error_log':'crit]'}

        ret = {}
        c=check(logfile_pattern)

        if len(c) > 0:
                c_ = c.lower()
                m = re.search("kernel: linux version", c_)
                if m:
                        ret['mon'] = "G-M-R"
                else:

                        ret['mon'] = "G-M-A"
                ret['mess'] =  c

        return ret

def check(logfile_pattern):
        string = ""
	line_string = ""
        for keys,values in logfile_pattern.items():
                logfile = keys
                #string = string + logfile + " ::"
                pattern = values.split("%%")
                if os.path.isfile(logfile):
                        f = open(logfile,'r')
                else:
                        continue
                posfile = "/var/log/pos_" + os.path.basename(logfile)
                (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(logfile)

                if os.path.isfile(posfile):
                        if os.path.getsize(posfile) != 0:
                                ff = open(posfile,'r')
                                line = ff.readline()
                                #(file, p, mtime, ssize, iino) = line.split(" ")
                                (file, p, mtime, ssize) = line.split(" ")

                                #if str(p) > str(size) or logfile != file or str(iino) != str(ino):
                                if str(p) > str(size) or logfile != file:
                                        p = 0
                                else:
                                        p = int(p)
                                ff.close()
                        else:
                                p = size
                                p = int(p)

                else:
                        p = size
                        p = int(p)


                n = 0
                while True:
                    #os.sleep(1)
                    f.seek(p)
                    latest_data = f.readline()
                    p = f.tell()
                    if not latest_data:
                        break

                    for word in pattern:
                        word = word.lower()

                        #print word
                        m = re.search("&&",word)
                        latest_data_ = latest_data.lower()

                        if m:
                                (p1,p2) = word.split("&&")
                                m1 = re.search(p1, latest_data_)
                                m2 = re.search(p2, latest_data_)
                                if m1 and m2:
                                        latest_data = latest_data.strip('\n')
                                        line_string += latest_data + " || "
                                        #print line_string
                                        n = n + 1


                        m = re.search(word, latest_data_)
                        if m:
                                latest_data = latest_data.strip('\n')
                                line_string += latest_data + " || "
                                #print line_string
                                n = n + 1
                if ( n > 0 ):
                        line_string = logfile + ": " + line_string

                f.close()

                tmpf = open(posfile, "w")
                tmpf.write("%s %s %s %s" % (logfile,str(p),mtime,size))
                tmpf.close()

        string = string + line_string
        return string


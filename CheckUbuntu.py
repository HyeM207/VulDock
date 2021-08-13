#!/usr/bin/env python
# -*- coding: utf-8 -*
import argparse
import docker
import requests
from bs4 import BeautifulSoup
from subprocess import PIPE, Popen
import subprocess
import time
import os


def changeToDigit(priv) :
        result = 0
        if 'r' in priv:
            result += 4
        if 'w' in priv:
            result += 2
        if 'x' in priv:
            result += 1
        return result 


def checkVersion() : # Check Version of Linux
    url = 'https://ubuntu.com/download/desktop'
    response = requests.get(url)
    if response.status_code == 200 :    
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        target = soup.find('div', {'id':'main-content'})
        info_list = target.findAll('h2')
        version_list = info_list[0:2]

        for i in range(len(version_list)):
            version_list[i] = str(version_list[i])
            version_list[i] = version_list[i].replace('<h2>', '')
            version_list[i] = version_list[i].replace('</h2>', '')


    cmd1 = container.exec_run('cat /etc/issue')
    if(version_list[0] in cmd1.output or version_list[1] in cmd1.output):
        print('Your Ubuntu Version is Latest')

    else :
        print('Your Ubuntu Version is Not Latest')
        print('Latest Verion is %s or %s' %(version_list[0], version_list[1]))


def check_vul1() : # Check Vul 1-1
    title = 'Check that the system policy applies the root account\'s remote terminal access blocking settings' 
    check1_1 = 0
    cmd1 = "grep 'pam_securetty.so' /etc/pam.d/login"
    res1 = container.exec_run(cmd1)

    if('auth [success=ok new_authtok_reqd=ok ignore=ignore user_unknown=bad default=die] pam_securetty.so' in res1.output 
         or 'auth required /lib/security/pam_securetty.so' in res1.output):
        if ('# auth' not in res1.output) :
            check1_1 += 1

    cmd2 = container.exec_run("grep 'pts/' /etc/securetty")

    if(cmd2.output == ''):
        check1_1 += 1

    if(check1_1 == 2):
        return [title, 'Safe']
    else: 
        return [title, 'Vulnerable' ] 


def check_vul2() : # Check Vul 1-4
    title = 'Check that the user account password is encrypted and stored in /etc/password'  
    check = 0   
    lens = 0
    cmd1 = container.exec_run('cat /etc/passwd')
  
    for i in cmd1.output.split('\n'):
        if (i != ''):
            lens += 1
            if(i.split(':')[1] == 'x') :
                check += 1
    
    if(check == lens):
        return [title, 'Safe'] 
    else : 
        return [title, 'Vulnerable' ] 


def check_vul3() : # Check Vul 2-1
    title = 'Check that the PATH environment variable in the root account contains \'.\''
    cmd1 = container.exec_run("bash -c 'echo $PATH'")
    
    if('.' in cmd1.output or '::' in cmd1.output) :
        return [title, 'Vulnerable' ] 
    else :
        return [title, 'Safe']  


def check_vul4() : #Check Vul 2-2
    title = 'Check whether files or directories that are unclear to the owner exist'
    is_safe1 = True
    is_safe2 = True
    cmd1 = container.exec_run('find / -nouser -print')
    cmd2 = container.exec_run('find / -nogroup -print')

    for i in cmd1.output.split('\n'):
        if (i != ''):
            if ('No such file or directory' not in i):
                is_safe1 = False
                break 

    for i in cmd2.output.split('\n'):
        if ( i != ''):
            if ('No such file or directory' not in i):
                is_safe2 = False
                break

    if (is_safe1 == True and is_safe2 == True) :
        return [title, 'Safe']
    else : 
        return [title, 'Vulnerable' ] 


def check_vul5() : #Check Vul 2-3
    title = 'Check /etc/passwd file permissions adequacy'
    cmd1 = container.exec_run('ls -l /etc/passwd')
    owner = cmd1.output.split(' ')[0][1:4]
    group = cmd1.output.split(' ')[0][4:7]
    etc = cmd1.output.split(' ')[0][7:]
    owner = changeToDigit(owner)
    group = changeToDigit(group)
    etc = changeToDigit(etc)
    if(cmd1.output.split(' ')[2] == 'root' and owner <= 6 and group <= 4 and etc <= 4) :
        return [title, 'Safe']  
    else :
        return [title, 'Vulnerable' ] 


def check_vul6() : #Check Vul 2-4
    title = 'Check /etc/shadow file permissions adequacy'
    cmd1 = container.exec_run('ls -l /etc/shdow')
    owner = cmd1.output.split(' ')[0][1:4]
    group = cmd1.output.split(' ')[0][4:7]
    etc = cmd1.output.split(' ')[0][7:]
    if('r--' in owner and '---' in group and '---' in etc and cmd1.output.split(' ')[2] == 'root') :
        return [title, 'Safe'] 
    else :
        return [title, 'Vulnerable' ]


def check_vul7() : #Check Vul 2-5
    title = 'Check /etc/hosts file permissions adequacy'
    cmd1 = container.exec_run('ls -l /etc/hosts')
    owner = cmd1.output.split(' ')[0][1:4]
    group = cmd1.output.split(' ')[0][4:7]
    etc = cmd1.output.split(' ')[0][7:]
    if('rw-' in owner and '---' in group and '---' in etc and cmd1.output.split(' ')[2] == 'root') :
        return [title, 'Safe']  
    else :
        return [title, 'Vulnerable' ] 

        
def check_vul8() : #Check Vul 2-6 
    title = 'Check /etc/inetd.conf file permissions adequacy'
    cmd1 = container.exec_run('ls -l /etc/inetd.conf')
    if('No such file or directory' in cmd1.output) :
        return [title, 'Safe'] # No file
    else :
        owner = cmd1.output.split(' ')[0][1:4]
        group = cmd1.output.split(' ')[0][4:7]
        etc = cmd1.output.split(' ')[0][7:]
        if('rw-' in owner and '---' in group and '---' in etc and cmd1.output.split(' ')[2] == 'root') :
            return [title, 'Safe']  
        else :
            return [title, 'Vulnerable' ] 


def check_vul9() : #Check Vul 2-7 
    title = 'Check /etc/syslog.conf file permissions adequacy'
    cmd1 = container.exec_run('ls -l /etc/syslog.conf')
    if('No such file or directory' in cmd1.output) :
        return [title, 'Safe'] # No file
    else :
        owner = cmd1.output.split(' ')[0][1:4]
        group = cmd1.output.split(' ')[0][4:7]
        etc = cmd1.output.split(' ')[0][7:]
        if('rw-' in owner and 'r--' in group and 'r--' in etc and cmd1.output.split(' ')[2] == 'root') :
            return [title, 'Safe']  
        else :
            return [title, 'Vulnerable' ] 


def check_vul10() : #Check Vul 2-8
    title = 'Check /etc/services file permissions adequacy'# /etc/services 파일 권한 적절성 점검
    cmd1 = container.exec_run('ls -l /etc/services')
    if('No such file or directory' in cmd1.output) :
        return [title, 'Check Later...']  
    else :
        owner = cmd1.output.split(' ')[0][1:4]
        group = cmd1.output.split(' ')[0][4:7]
        etc = cmd1.output.split(' ')[0][7:]
        if('rw-' in owner and 'r--' in group and 'r--' in etc and cmd1.output.split(' ')[2] == 'root') :
            return [title, 'Safe'] 
        else :
            return [title, 'Vulnerable' ] 


def check_vul11() : #Check Vul 2-9
    title = 'Check for SUID, SGID settings for unnecessary or malicious files' #불필요하거나 악의적인 파일에 SUID, SGID 설정 여부 점검
    cnt_unsafe = 0 
    cnt_safe = 0 
    no_exist=[]   
    SUID_list = []
    UID_list = []
    file_list = ['/sbin/dump', '/sbin/restore', '/usr/bin/newgrp', '/sbin/unix_chkpwd', '/usr/bin/lpq-lpd', '/usr/bin/lpr', '/usr/sbin/lpc', '/usr/bin/lpr-lpd', '/usr/sbin/lpc-lpd', '/usr/bin/lpq', '/usr/bin/lprm-lpd', '/usr/bin/lprm', '/usr/bin/at', '/usr/sbin/traceroute']
    
    for i in file_list:
        cmd1 = container.exec_run('ls -l {}'.format(i))
        if('No such file or directory' in cmd1.output) :
            no_exist.append(i)
        else :
            owner = cmd1.output.split(' ')[0][1:4]
            group = cmd1.output.split(' ')[0][4:7]
            if('s' in owner or 's' in group) :     
                SUID_list.append(i)
            else :
                UID_list.append(i)

    for i in SUID_list :
        cnt_unsafe += 1
   
    for i in UID_list :
        cnt_safe += 1
  
    if cnt_unsafe == 0:
        return [title, 'Safe' ] 
    else :
        return [title, 'Vulnerable (Unsafe file num : %d)' %(cnt_unsafe) ] 
    

def check_vul12() : #Check Vul 2-10
    title = 'Check that the owner and access rights to environment variable files within the home directory are set to Administrator or their account'
    env_list = ['.profile', '.kshrc', '.cshrc', '.bashrc', '.bash_profile', '.login', '.exrc', '.netrc']

    cnt_safe = 0
    cnt_unsafe = 0 
    cnt_pass = 0

    for env in env_list:
        cmd1  = container.exec_run('printenv HOME')
        cmd2 = container.exec_run('ls -al' + cmd1.output.split('\n')[0] +'/'+ env)
        cmd3 = container.exec_run('logname')
        owner = cmd2.output.split(' ')[0][1:4]
        group = cmd2.output.split(' ')[0][4:7]
        etc = cmd2.output.split(' ')[0][7:]

        #print(cmd2.output)
        if('No such file or directory' in cmd2.output) :
            cnt_pass += 1
        else : 
            if (cmd2.output.split(' ')[2] == 'root' or cmd2.output.split(' ')[2] == cmd3.output) :
                if ('w' not in group and 'w' not in etc ):
                    cnt_safe += 1 
                else: 
                    cnt_unsafe += 1
            else: 
                cnt_unsafe += 1

    if cnt_unsafe == 0:
        return [title, 'Safe' ] 
    else :
        return [title, 'Vulnerable (Unsafe file num : %d)' %(cnt_unsafe) ] 


def check_vul13() : #Check Vul 2-11
    title = 'Check existence of unnecessary world writable files'  
    cmd1=container.exec_run('find / -type f -perm -2 -exec ls -l {} \;')
    result=cmd1.output.split('\n')
    del result[-1]  #last yoso is gongbaek so i delete last inde

    cnt_unsafe = 0  #the number of unsafe files

    for i in result:
        if 'No such file' in i:
            continue       
        else:
            owner = i.split(' ')[0][1:4]
            group = i.split(' ')[0][4:7]
            etc = i.split(' ')[0][7:]
            if ('w' in etc) :
                cnt_unsafe += 1
    
    if cnt_unsafe == 0:
        return [title, 'Safe' ] 
    else :
        return [title, 'Vulnerable (Unsafe file num : %d)' %(cnt_unsafe) ] 


def check_vul14(): #Check Vul 3-2
    title = 'Check anonymous FTP access allowed' #익명 FTP 접속 허용 여부 점검
    cmd1 = container.exec_run("grep 'ftp' /etc/passwd")
    if (cmd1.output == ''):
        return [title, 'Safe' ] 
    else :
        return [title, 'Vulnerable' ]


def check_vul15(): #Check Vul 3-4
    title = 'Check permission adequacy of Cron-related files' # Cron  관련 파일의 권한 적절성 점검
    file_list = ['cron.allow', 'cron.deny']
    for f in file_list:
        cmd1 = container.exec_run('ls -al /etc/%s' %(f))
        if('No such file or directory' in cmd1.output) :
            return [title, 'Safe' ] 
        else : 
            owner = cmd1.output.split(' ')[0][1:4]
            group = cmd1.output.split(' ')[0][4:7]
            etc = cmd1.output.split(' ')[0][7:]
            owner = changeToDigit(owner)
            group = changeToDigit(group)
            etc = changeToDigit(etc)
            if(cmd1.output.split(' ')[2] == 'root' and owner <= 6 and group <=4 and owner <= 0) :
                return [title, 'Safe' ] 
            else :
                return [title, 'Vulnerable' ]


def check_vul16(): #Check Vul 3-5 & 3-9
    title = 'Check whether services vulnerable to unused DOS attacks are running and whether unnecessary RPC services are running'
    cmd1 = container.exec_run('ls /etc/xinetd.d')
    services = cmd1.output.split('\n')
    del services[-1]
    cnt_safe = 0  #the number of safe files
    cnt_unsafe = 0
    if ('No such file' in cmd1.output):
        return [title, 'Safe'] # No file
    else:
        for i in services:
            cmd2 = container.exec_run('cat /etc/xinetd.d/%s' %(i))
            result = cmd2.output.split('\n')
            for j in result:
                if 'disable' in j:
                    if 'yes' in j:
                        cnt_safe += 1         
                        break
    
        cnt_unsafe = len(services) - cnt_safe
        if cnt_unsafe == 0:
            return [title, 'Safe' ] 
        else :
            return [title, 'Vulnerable (Unsafe file num : %d)' %(cnt_unsafe) ] 


def check_vul17(): #Check Vul 3-11
    title = 'Check whether services such as ftp, tftp, telnet, talk, etc. are enabled or vulnerabilities are published.'
    cmd1 = container.exec_run('ls /etc/xinetd.d')
    services = cmd1.output.split('\n')
    service_list = []
    cnt_safe = 0
    cnt_unsafe = 0
    if 'tftp' in services:
        service_list.append('tftp')
    if 'talk' in services:
        service_list.append('talk')
    if 'ntalk' in services:
        service_list.append('ntalk')

    if len(service_list) == 0:
        return [title, 'Safe'] # No file
    else:
        for i in service_list:
            cmd2 = container.exec_run('cat /etc/xinetd.d/talks')
            result = cmd2.output.split('\n')
            for j in result:
                if 'disable' in j:
                    if 'yes' in j:
                        cnt_safe += 1
                        break
        
        cnt_unsafe = len(service_list) - cnt_safe

        if cnt_unsafe == 0:
            return [title, 'Safe' ] 
        else :
            return [title, 'Vulnerable (Unsafe file num : %d)' %(cnt_unsafe) ]


def check_vul18(): #Check Vul 3-12
    title = 'Check vulnerable version of Sendmail service availability' #취약한 버전의 Sendmail 서비스 이용 여부 점검
    proc1 = subprocess.Popen(['ps', '-ef'], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', 'sendmail'], stdin=proc1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc1.stdout.close()
    out, err = proc2.communicate()

    proc1 = subprocess.Popen(['apt-cache', 'show', 'sendmail'], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', 'Version'], stdin=proc1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc1.stdout.close()
    out2, err = proc2.communicate()

    list = []

    for i in out.split('\n') :
        if ('grep' not in i and i != ''):
            list.append(i)

    if (len(list) > 0):
        pass 

    else :    
        return [title, 'Safe' ] # 'Vul3-12 is Safe(not using sendmail Service)'
    url = 'https://www.proofpoint.com/us/products/email-protection/open-source-email-solution'
    response = requests.get(url)
    if response.status_code == 200 :
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        target = soup.find('div', {'class':'block-text-cols__body list-in-article'})
        td = target.find_all('p')
        p = str(td[0]).split('</a>')[0]
       
        return [title, 'Recommend Version : ' + p[3:].split('<')[0] + p[3:].split('>')[1]]     


def check_vul19(): #Check Vul 3-13
    title = 'Check for relay limitations on SMTP servers' #SMTP 서버의 릴레이 기능 제한 여부 점검
    proc1 = subprocess.Popen(['ps', '-ef'], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', 'sendmail'], stdin=proc1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc1.stdout.close()
    out, err = proc2.communicate()
    list = []
    for i in out.split('\n') :
        if ('grep' not in i and i != ''):
            list.append(i)
    if (len(list) > 0):
        return [title, 'Safe' ]
    else :
        #print('using SMTP')
        cmd1 = container.exec_run("grep '550 Relaying denied' /etc/mail/sendmail.cf").output.split('\n')[0]
        if(cmd1[0] == '#') :
            return [title, 'Vulnerable' ] 
        else :
            return [title, 'Safe' ]


def check_vul20(): #Check Vul 3-15
    title = 'Check for latest BIND version usage and periodic security patch security' # BIND 최신버전 사용 유무 및 주기적 보안 패치 보안 여부 점검
    cmd1 = container.exec_run('named -V')
    if (cmd1.output == '' or 'not found' in cmd1.output):
        return [title, 'Safe' ] 
    else :
        version = cmd1.output.split('\n')[0]
      
    url = 'https://www.isc.org/download/'
    response = requests.get(url)
    if response.status_code == 200 :
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        target = soup.find('table', {'class':'table table-download table-borderless rounded text-left mb-5'})
        td = target.find_all('td')

        return [title, 'Recommend Version : ' + td[0].text, ] 


def check_vul21(): #Check Vul 3-17
    title = 'Check for activation of Apache Directory Search feature' #Apache 디렉토리 검색 기능의 활성화 여부 점검
    cmd1 = container.exec_run('cat /etc/apache2/apache2.conf')
    cmd2 = container.exec_run('cat /etc/apache2/httpd.conf')
    check = True

    #if os is ubuntu
    if('No such file or directory' in cmd1.output and 'No such file or directory' in cmd2.output) :
        return [title, 'Safe' ] 
    elif('No such file or directory' in cmd2.output):
        result = cmd1.output.split('\n')

        #find 'Indexes' option
        for i in result:
            if 'Indexes' in i and '#' not in i:
                check = False
        
        if check == True:
            return [title, 'Safe' ]
        elif check == False:
            return [title, 'Vulnerable' ]
          

    #if os is not ubuntu
    elif('No such file or directory' in cmd1.output):
        result = cmd2.output.split('\n')

        #find 'Indexes' option
        for i in result:
            if 'Indexes' in i and '#' not in i:
                check = False

        
        if check == True:
            return [title, 'Safe' ] 
        elif check == False:
            return [title, 'Vulnerable' ] 
            


def check_vul22(): #Check Vul 3-18
    title = 'Check whether Apache daemon is running with root privileges' #Apache 데몬이 root 권한으로 구동되는지 여부 점검
    cmd1 = container.exec_run("grep 'export APACHE_RUN_USER' /etc/apache2/envvars") # ubuntu
    cmd2 = container.exec_run("grep 'export APACHE_RUN_GROUP' /etc/apache2/envvars") # ubuntu
    is_safe1 = True
    is_safe2 = True
    
    #check APACHE_RUN_USER
    if('' == cmd1.output or 'No such file' in cmd1.output ) :
        pass
    else : 
        privilege = cmd1.output.split('=')[1]
        if (privilege != 'root'):
            pass
        else : 
            is_safe1 = False

    #check APACHE_RUN_USER
    if('' == cmd2.output) :
        pass
    else : 
        privilege = cmd2.output.split('=')[1]
        if (privilege != 'root'):
            pass
        else : 
            is_safe2 = False

    if (is_safe1 == True and is_safe2 == True) :
        return [title, 'Safe']
    else : 
        return [title, 'Vulnerable' ] 
    

def check_vul23(): #Check Vul 3-19
    title = 'Check whether the Apache parent path can be moved due to the use of characters' # 문자 사용으로 인한 Apache 상위 경로로 이동이 가능한지 여부 점검
    cmd1 = container.exec_run("grep 'AllowOverride' /etc/apache2/httpd.conf")
    cmd2 = container.exec_run("grep 'AllowOverride' /etc/apache2/apache2.conf")
    check = True

    if('No such file or directory' in cmd1.output and 'No such file or directory' in cmd2.output) :
        return [title, 'Safe' ] 
    elif('No such file or directory' in cmd2.output):
        result = cmd1.output.split('\n')

        #find 'None' option -> Not Safe
        for i in result:
            if 'None' in i and '#' not in i:
                check = False
                break

        if check == True:
            return [title, 'Safe' ] 
        elif check == False:
            return [title, 'Vulnerable' ] 
            

    #if os is not ubuntu
    elif('No such file or directory' in cmd1.output):
        result = cmd2.output.split('\n')

        #find 'Indexes' option
        for i in result:
            if 'None' in i and '#' not in i:
                check = False
                break
        
        if check == True:
            return [title, 'Safe' ] 
        elif check == False:
            return [title, 'Vulnerable' ] 
            


def check_vul24(): #Check Vul 3-21
    title = 'Symbolic links, checking alias for restrictions on use' # 심볼릭 링크, aliases 사용 제한 여부 점검
    cmd1 = container.exec_run('cat /etc/apache2/apache2.conf')
    cmd2 = container.exec_run('cat /etc/apache2/httpd.conf')
    check = True

    #if os is ubuntu
    if('No such file or directory' in cmd1.output and 'No such file or directory' in cmd2.output) :
        return [title, 'Safe' ] 
    elif('No such file or directory' in cmd2.output):
        result = cmd1.output.split('\n')

        #find 'Indexes' option
        for i in result:
            if 'FollowSymLinks' in i and '#' not in i:
                check = False
        
        if check == True:
            return [title, 'Safe' ] 
        elif check == False:
            return [title, 'Vulnerable' ] 


    #if os is not ubuntu
    elif('No such file or directory' in cmd1.output):
        result = cmd2.output.split('\n')

        #find 'Indexes' option
        for i in result:
            if 'FollowSymLinks' in i and '#' not in i:
                check = False
        
        if check == True:
           return [title, 'Safe' ] 
        elif check == False:
            return [title, 'Vulnerable' ] 
          


def make_container(service, version):
    global container
    global cli
    global image
    # pull images and run container
    cli = docker.from_env()
    image = service + ':' + version
    print('docker image_name %s' %(image))
    cli.images.pull(image)
    container = cli.containers.run(image,detach=True, tty=True)
    print(cli.containers.list())


def remove_container():
    container.stop()
    container.remove()
    cli.images.remove(image,force=True)
    print(cli.containers.list())


def main_func(service, version):
    make_container(service, version)

    vul_name = []
    vul_name.append('vul_name')

    status = []
    status.append('status')

    for i in range(1, 25):
        multi_list = []
        multi_list = eval('check_vul'+str(i))()
        vul_name.append(multi_list[0])
        status.append(multi_list[1])
        

    result = [vul_name, status]
    print(result)
    remove_container()

main_func('ubuntu', '18.04')

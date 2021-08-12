import argparse
import docker
import requests
from bs4 import BeautifulSoup
from subprocess import PIPE, Popen
import time
import os

cli = docker.from_env()
# title list 

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
    title = '' 
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
        return [title, 'Safe']  # safe
    else: 
        return [title, 'Vulnerable' ] #vulnerable


def check_vul2() : # Check Vul 1-4
    title = ''  
    check = 0   
    lens = 0
    cmd1 = container.exec_run('cat /etc/passwd')
  
    for i in cmd1.output.split('\n'):
        if (i != ''):
            lens += 1
            if(i.split(':')[1] == 'x') :
                check += 1
    
    if(check == lens):
        return [title, 'Safe']  # safe
    else : 
        return [title, 'Vulnerable' ] #vulnerable


def check_vul3() : # Check Vul 2-1
    title = ''
    cmd1 = container.exec_run("bash -c 'echo $PATH'")
    
    if('.' in cmd1.output or '::' in cmd1.output) :
        return [title, 'Vulnerable' ] #vulnerable
    else :
        return [title, 'Safe']  # safe


def check_vul4() : #Check Vul 2-2
    title = ''
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
    title = ''
    cmd1 = container.exec_run('ls -l /etc/passwd')
    owner = cmd1.output.split(' ')[0][1:4]
    group = cmd1.output.split(' ')[0][4:7]
    etc = cmd1.output.split(' ')[0][7:]
    owner = changeToDigit(owner)
    group = changeToDigit(group)
    etc = changeToDigit(etc)
    print(cmd1.output.split(' ')[2])
    if(cmd1.output.split(' ')[2] == 'root' and owner <= 6 and group <= 4 and etc <= 4) :
        return [title, 'Safe']  # Safe
    else :
        return [title, 'Vulnerable' ] # Vulnerable


def check_vul6() : #Check Vul 2-4
    title = ''
    cmd1 = container.exec_run('ls -l /etc/shdow')
    owner = cmd1.output.split(' ')[0][1:4]
    group = cmd1.output.split(' ')[0][4:7]
    etc = cmd1.output.split(' ')[0][7:]
    if('r--' in owner and '---' in group and '---' in etc and cmd1.output.split(' ')[2] == 'root') :
        return [title, 'Safe']  # Safe
    else :
        return [title, 'Vulnerable' ] # Vulnerable


def check_vul7() : #Check Vul 2-5
    title = ''
    cmd1 = container.exec_run('ls -l /etc/hosts')
    owner = cmd1.output.split(' ')[0][1:4]
    group = cmd1.output.split(' ')[0][4:7]
    etc = cmd1.output.split(' ')[0][7:]
    if('rw-' in owner and '---' in group and '---' in etc and cmd1.output.split(' ')[2] == 'root') :
        return [title, 'Safe']  # Safe
    else :
        return [title, 'Vulnerable' ] # Vulnerable

        
def check_vul8() : #Check Vul 2-6 
    title = ''
    cmd1 = container.exec_run('ls -l /etc/inetd.conf')
    if('No such file or directory' in cmd1.output) :
        return [title, 'Check Later...']  
    else :
        owner = cmd1.output.split(' ')[0][1:4]
        group = cmd1.output.split(' ')[0][4:7]
        etc = cmd1.output.split(' ')[0][7:]
        if('rw-' in owner and '---' in group and '---' in etc and cmd1.output.split(' ')[2] == 'root') :
            return [title, 'Safe']  # Safe
        else :
            return [title, 'Vulnerable' ] # Vulnerable


def check_vul9() : #Check Vul 2-7 
    title = ''
    cmd1 = container.exec_run('ls -l /etc/syslog.conf')
    if('No such file or directory' in cmd1.output) :
        return [title, 'Check Later...']  
    else :
        owner = cmd1.output.split(' ')[0][1:4]
        group = cmd1.output.split(' ')[0][4:7]
        etc = cmd1.output.split(' ')[0][7:]
        if('rw-' in owner and 'r--' in group and 'r--' in etc and cmd1.output.split(' ')[2] == 'root') :
            return [title, 'Safe']  # Safe
        else :
            return [title, 'Vulnerable' ] # Vulnerable


def check_vul10() : #Check Vul 2-8
    title = ''
    cmd1 = container.exec_run('ls -l /etc/services')
    if('No such file or directory' in cmd1.output) :
        return [title, 'Check Later...']  
    else :
        owner = cmd1.output.split(' ')[0][1:4]
        group = cmd1.output.split(' ')[0][4:7]
        etc = cmd1.output.split(' ')[0][7:]
        if('rw-' in owner and 'r--' in group and 'r--' in etc and cmd1.output.split(' ')[2] == 'root') :
            return [title, 'Safe']  # Safe
        else :
            return [title, 'Vulnerable' ] # Vulnerable


def check_vul11() : #Check Vul 2-9
    title = ''
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

    # print('\n')
    # print('[-] this file has SUID/SGID(NOT SAFE)\n')
    for i in SUID_list :
        # print(' -' + i + '\n')
        cnt_unsafe += 1
    # print('\n')
    # print("[+] this file hasn't SUID/SGID(SAFE)\n")
    for i in UID_list :
        # print(' -' + i + '\n')
        cnt_safe += 1
    # print('\n')
    # print('[*] this file is not existed\n')
    # for i in no_exist :
    #     print(' -' + i + '\n')
    # print('\n')

    if cnt_unsafe == 0:
        return [title, 'Safe' ] # Safe
    else :
        return [title, 'Vulnerable (Unsafe file num : %d)' %(cnt_unsafe) ] # Vulnerable
    

def check_vul12() : #Check Vul 2-12
    title = ''
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
        return [title, 'Safe' ] # Safe
    else :
        return [title, 'Vulnerable (Unsafe file num : %d)' %(cnt_unsafe) ] # Vulnerable

def check_vul13() : #Check Vul 2-11
    title = ''  
    cmd1=container.exec_run('find / -type f -perm -2 -exec ls -l {} \;')
    result=cmd1.output.split('\n')
    del result[-1]  #last yoso is gongbaek so i delete last inde

    cnt_unsafe = 0  #the number of unsafe files

    for i in result:
        if 'No such file' in i:
            continue        # print('no file')
        else:
            owner = i.split(' ')[0][1:4]
            group = i.split(' ')[0][4:7]
            etc = i.split(' ')[0][7:]
            if ('w' in etc) :
                cnt_unsafe += 1
    
    if cnt_unsafe == 0:
        return [title, 'Safe' ] # Safe
    else :
        return [title, 'Vulnerable (Unsafe file num : %d)' %(cnt_unsafe) ] # Vulnerable 


def check_vul14(): #Check Vul 3-2
    title = ''
    cmd1 = container.exec_run("grep 'ftp' /etc/passwd")
    if (cmd1.output == ''):
        return [title, 'Safe' ] # Safe
    else :
        return [title, 'Vulnerable' ] #Vulnerable


def check_vul15(): #Check Vul 3-4
    title = ''
    file_list = ['cron.allow', 'cron.deny']
    for f in file_list:
        cmd1 = container.exec_run('ls -al /etc/%s' %(f))
        if('No such file or directory' in cmd1.output) :
            print('Vul3-4 pass ( %s NO BIND )' %(f))
        else : 
            owner = cmd1.output.split(' ')[0][1:4]
            group = cmd1.output.split(' ')[0][4:7]
            etc = cmd1.output.split(' ')[0][7:]
            owner = changeToDigit(owner)
            group = changeToDigit(group)
            etc = changeToDigit(etc)
            if(cmd1.output.split(' ')[2] == 'root' and owner <= 6 and group <=4 and owner <= 0) :
                return [title, 'Safe' ] # Safe
            else :
                return [title, 'Vulnerable' ] #Vulnerable


def check_vul16(): #Check Vul 3-5 & 3-9
    title = ''
    cmd1 = container.exec_run('ls /etc/xinetd.d')
    services = cmd1.output.split('\n')
    del services[-1]
    cnt_safe = 0  #the number of safe files
    cnt_unsafe = 0
    if ('No such file' in cmd1.output):
        return [title, 'Check Later...']  #  print('No xinetd.d file')
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
            return [title, 'Safe' ] # Safe
        else :
            return [title, 'Vulnerable (Unsafe file num : %d)' %(cnt_unsafe) ] # Vulnerable 


def check_vul17(): #Check Vul 3-11
    title = ''
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
        return [title, 'Check Later...']  # print('[Vul 3-11] No File')
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
            return [title, 'Safe' ] # Safe
        else :
            return [title, 'Vulnerable (Unsafe file num : %d)' %(cnt_unsafe) ] # Vulnerable 


def check_vul18(): #Check Vul 3-12
    print('==== Check Vul 3-12 ====')
    proc1 = subprocess.Popen(['ps', '-ef'], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', 'sendmail'], stdin=proc1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc1.stdout.close()
    out, err = proc2.communicate()
    # print('out: {0}'.format(out))
    # print('err: {0}'.format(err))
    proc1 = subprocess.Popen(['apt-cache', 'show', 'sendmail'], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', 'Version'], stdin=proc1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc1.stdout.close()
    out2, err = proc2.communicate()

    list = []

    for i in out.split('\n') :
        if ('grep' not in i and i != ''):
            list.append(i)

    if (len(list) > 0):
        print('using SMTP(Checking your Version)')

    else :    
        print('Vul3-12 is Safe(not using sendmail Service)')
    url = 'https://www.proofpoint.com/us/products/email-protection/open-source-email-solution'
    response = requests.get(url)
    if response.status_code == 200 :
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        target = soup.find('div', {'class':'block-text-cols__body list-in-article'})
        td = target.find_all('p')
        p = str(td[0]).split('</a>')[0]
        print('Your Verson : ' + out2)
        print('**Recommended Latest Version**')
        print(p[3:].split('<')[0] + p[3:].split('>')[1])    


def check_vul19(): #Check Vul 3-13
    title = ''
    print('==== Check Vul 3-13 ====')
    proc1 = subprocess.Popen(['ps', '-ef'], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', 'sendmail'], stdin=proc1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc1.stdout.close()
    out, err = proc2.communicate()
    list = []
    for i in out.split('\n') :
        if ('grep' not in i and i != ''):
            list.append(i)
    if (len(list) > 0):
        print('Vul3-13 is Safe(not using SMTP)')
    else :
        #print('using SMTP')
        cmd1 = container.exec_run("grep '550 Relaying denied' /etc/mail/sendmail.cf").output.split('\n')[0]
        if(cmd1[0] == '#') :
            return [title, 'Vulnerable' ] #Vulnerable
        else :
            return [title, 'Safe' ] #Safe


def check_vul20(): #Check Vul 3-15
    title = 'Check for latest BIND version usage and periodic security patch security' # BIND 최신버전 사용 유무 및 주기적 보안 패치 보안 여부 점검
    print('==== Check Vul 3-15 ====')
    cmd1 = container.exec_run('named -V')
    if (cmd1.output == '' or 'not found' in cmd1.output):
        print('Vul3-15 is Safe( NO BIND )')
    else :
        version = cmd1.output.split('\n')[0]
        print('YOUR BIND VERSION : ' + version.split('-')[0].split(' ')[1])
        print('[*] ' + cmd1.output.split('\n')[0] + '\n')
    print('REcommended Latest Version')
    url = 'https://www.isc.org/download/'
    response = requests.get(url)
    if response.status_code == 200 :
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        target = soup.find('table', {'class':'table table-download table-borderless rounded text-left mb-5'})
        td = target.find_all('td')
        print('[ VERSION ]   [ RELEASE DATE ]   [ STATUS ]')
        print('  ' + td[0].text + '        ' + td[3].text + '       ' + td[1]['title'])
        print('  ' + td[6].text + '        ' + td[9].text + '       ' + td[7]['title'])
        print('  ' + td[12].text + '        ' + td[15].text + '       ' + td[13]['title'])


def check_vul21(): #Check Vul 3-17
    title = 'Check for activation of Apache Directory Search feature' #Apache 디렉토리 검색 기능의 활성화 여부 점검
    cmd1 = container.exec_run('cat /etc/apache2/apache2.conf')
    cmd2 = container.exec_run('cat /etc/apache2/httpd.conf')
    check = True

    #if os is ubuntu
    if('No such file or directory' in cmd1.output and 'No such file or directory' in cmd2.output) :
        return [title, 'Safe' ] #Safe
    elif('No such file or directory' in cmd2.output):
        result = cmd1.output.split('\n')

        #find 'Indexes' option
        for i in result:
            if 'Indexes' in i and '#' not in i:
                check = False
        
        if check == True:
            return [title, 'Safe' ] #Safe
        elif check == False:
            return [title, 'Vulnerable' ] #Vulnerable
            #print('You should remove "Indexes" option in apache2.conf file')

    #if os is not ubuntu
    elif('No such file or directory' in cmd1.output):
        result = cmd2.output.split('\n')

        #find 'Indexes' option
        for i in result:
            if 'Indexes' in i and '#' not in i:
                check = False

        
        if check == True:
            return [title, 'Safe' ] #Safe
        elif check == False:
            return [title, 'Vulnerable' ] #Vulnerable
            #print("You should remove 'Indexes' option in apache2.conf file")


def check_vul22(): #Check Vul 3-18
    title = 'Check whether Apache daemon is running with root privileges' #Apache 데몬이 root 권한으로 구동되는지 여부 점검
    cmd1 = container.exec_run("grep 'export APACHE_RUN_USER' /etc/apache2/envvars") # ubuntu
    cmd2 = container.exec_run("grep 'export APACHE_RUN_GROUP' /etc/apache2/envvars") # ubuntu
    check = True
    
    #check APACHE_RUN_USER
    if('' == cmd1.output) :
        return [title, 'Safe' ] #'[Vul 3-18] No File or Directory'
    else : 
        privilege = cmd1.output.split('=')[1]
        if (privilege != 'root'):
            return [title, 'Safe' ] #Vul 3-18 (User) is safe
        else : 
            return [title, 'Vulnerable' ] #Vul 3-18 (User) is not safe

    #check APACHE_RUN_USER
    if('' == cmd2.output) :
        print('[Vul 3-18] No File or Directory')
    else : 
        privilege = cmd2.output.split('=')[1]
        if (privilege != 'root'):
            return [title, 'Safe' ] #Vul 3-18 (Group) is safe
        else : 
            return [title, 'Vulnerable' ] #Vul 3-18 (Group) is not safe
    

def check_vul23(): #Check Vul 3-19
    title = 'Check whether the Apache parent path can be moved due to the use of characters' # 문자 사용으로 인한 Apache 상위 경로로 이동이 가능한지 여부 점검
    cmd1 = container.exec_run("grep 'AllowOverride' /etc/apache2/httpd.conf")
    cmd2 = container.exec_run("grep 'AllowOverride' /etc/apache2/apache2.conf")
    check = True

    if('No such file or directory' in cmd1.output and 'No such file or directory' in cmd2.output) :
        #print('[Vul 3-19] No File or Directory')
        return [title, 'Safe' ] #Safe
    elif('No such file or directory' in cmd2.output):
        result = cmd1.output.split('\n')

        #find 'None' option -> Not Safe
        for i in result:
            if 'None' in i and '#' not in i:
                check = False
                break

        if check == True:
            return [title, 'Safe' ] #Safe
        elif check == False:
            return [title, 'Vulnerable' ] #Vulnerable
            #print("You should Change 'None' Option to 'AutoConfig' in httpd.conf file")

    #if os is not ubuntu
    elif('No such file or directory' in cmd1.output):
        result = cmd2.output.split('\n')

        #find 'Indexes' option
        for i in result:
            if 'None' in i and '#' not in i:
                check = False
                break
        
        if check == True:
            return [title, 'Safe' ] #Safe
        elif check == False:
            return [title, 'Vulnerable' ] #Vulnerable
            #print("You should Change 'None' Option to 'AutoConfig' in httpd.conf file")


def check_vul24(): #Check Vul 3-21
    title = 'Symbolic links, checking alias for restrictions on use' # 심볼릭 링크, aliases 사용 제한 여부 점검
    cmd1 = container.exec_run('cat /etc/apache2/apache2.conf')
    cmd2 = container.exec_run('cat /etc/apache2/httpd.conf')
    check = True

    #if os is ubuntu
    if('No such file or directory' in cmd1.output and 'No such file or directory' in cmd2.output) :
        #print('[Vul 3-21] No File or Directory')
        return [title, 'Safe' ] #Safe
    elif('No such file or directory' in cmd2.output):
        result = cmd1.output.split('\n')

        #find 'Indexes' option
        for i in result:
            if 'FollowSymLinks' in i and '#' not in i:
                check = False
        
        if check == True:
            return [title, 'Safe' ] #Safe
        elif check == False:
            return [title, 'Vulnerable' ] #Vulnerable
            #print("You should remove 'FollowSymLinks' option in apache2.conf file")

    #if os is not ubuntu
    elif('No such file or directory' in cmd1.output):
        result = cmd2.output.split('\n')

        #find 'Indexes' option
        for i in result:
            if 'FollowSymLinks' in i and '#' not in i:
                check = False
        
        if check == True:
           return [title, 'Safe' ] #Safe
        elif check == False:
            return [title, 'Vulnerable' ] #Vulnerable
            #print("You should remove 'FollowSymLinks' option in apache2.conf file")


def make_container(service, version):
    # pull images and run container
    image = service + ':' + version
    print('docker image_name %s' %(iamge))
    cli.images.pull(image)
    container = cli.containers.run(image,detach=True, tty=True)


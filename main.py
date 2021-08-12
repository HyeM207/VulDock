from __future__ import print_function
import json
import argparse
import os
from posix import listdir
import requests
import commands
from bs4 import BeautifulSoup
import subprocess
import re
import getopt
import sys
#import CheckUbuntu as chenkU


# def official_image()
def find_compose(image_name):
    cmd = commands.getoutput(
        'find / -name ' + image_name + ' 2> /dev/null').split('\n')
    #print(cmd1)

    if cmd[0] == '':
        return False

    for i in range(len(cmd)):
        num = i + 1
        print('%d. %s' %(num, cmd[i]))

    select = int(input('Enter number of your path : '))

    return cmd[select - 1]


def findVer_image(compose_path): 
    cmd = commands.getoutput('grep image ' + compose_path)
    images= cmd.replace('image: ', '').split('\n')
    
    services = dict()

    for image in images:
        if cmd=='':
            return False

        else:
            i_name = ''
            i_ver = ''
            image = image.replace(' ', '')

            if ':' in image :
                i_name = image.split(':')[0]
                i_ver = image.split(':')[1]
                services[i_name] = i_ver

            if i_ver == 'latest' or ':' not in image:
                i_name = image
                i_ver = 'latest'
                    
                url = 'https://github.com/docker-library/official-images/tree/master/library/' + i_name
                response = requests.get(url)

                if response.status_code == 200 :
                    html = response.text
                    soup = BeautifulSoup(html, 'html.parser')
                    target = soup.find('table', {'class':'highlight tab-size js-file-line-container'}).get_text().split('\n')
                    tags = []

                    for line in target:
                        if i_ver in line :
                            line = str(line)
                            tags = line.replace('Tags:', '')
                            tags = tags.replace(' ', '')
                            tags = tags.split(',')
                            tags.remove('latest')
                            i_ver = tags[0]
                            services[i_name] = i_ver
                            break
                            
    return services    


def findVer_package(dir_path, compose_path):

    if os.path.isfile(compose_path) == True:
        os.chdir(dir_path)
        cmd1=commands.getoutput('cat docker-compose.yaml').split('\n')
        not_build = True

        for i in cmd1:
            if 'build' in i:
                build = i
                build = build.replace(' ', '')
                build = build.split(':')[1]
                not_build = False
                break
            else:
                not_build = True

    if not_build == False:
        os.chdir('{}'.format(build))
        json_path = os.getcwd()
        if os.path.isfile(json_path+'/package.json')==True:
            file = open('package.json')
            jsonString = json.load(file)
            #make dictionary
            services = dict()
            services_list=jsonString.get('dependencies').keys()
            for s in services_list :
                services[str(s)] = ''
 
            for s in services_list:
                str_s=str(s)
                tmp=jsonString['dependencies'][str_s].replace('^','')
                services[s] = str(tmp)
     
            if len(services)>0:
                return services

        else:
            print('package.json is not exited')
            return False
            

    elif not_build == True:
        print('no build')
        return False


def findVer_env(dir_path, compose_path):
    env_path = dir_path + '/.env'

    cmd1 = commands.getoutput('grep -n build ' + compose_path).split('\n')
    cmd2 = commands.getoutput("grep '\$' " + compose_path).split('\n')
    
    if cmd2[0] == '':
        return False

    services = dict()

    # find service name in compose file
    for c in cmd1:
        if c != '':
            service_line = int(c.split(':')[0]) - 1
            service_name = cmd1 = os.popen(
                'sed -n ' + str(service_line) + 'p ' + compose_path).read().split(':')[0].lstrip()
            services[service_name] = ''

    # the dictionary of variables // {key : value} = {var_name : var_value}
    variables = dict()

    # find variable in compose file
    for c, service in zip(cmd2, services) :
        if c != '':
            variables[c.split('$')[1]] = 'none'
            services[service] = c.split('$')[1]    

    # get variable_value in .env
    cmd3 =  commands.getoutput('cat ' + env_path).split('\n')
    for c in cmd3:
        if c != '':
            var_name = c.split('=')[0]
            var_value = c.split('=')[1]
            variables[var_name] = var_value

    # put service_version into services list
    for service in services:
        val = services[service]
        services[service] = variables[val]

    return services


def findVer_dockerfile(dir_path, compose_path):
    cmd1 = commands.getoutput('grep -n build ' + compose_path).split('\n')
    
    if cmd1[0] == '' :
        return False

    services = dict()

    # find service name in compose file
    for c in cmd1 :
        service_name = c.replace(' ', '').split(':')[2]
        dockerfile_path = dir_path + '/' +  service_name + '/Dockerfile'

        # find detail services in Dockerfile 
        cmd2 = commands.getoutput('grep FROM ' + dockerfile_path).split('\n')
     
        for c in cmd2 : 
            d_service = c.split(' ')[1].replace(':',' ').split('-')[0]
            d_service_name = d_service.split(' ')[0]
            d_service_ver = d_service.split(' ')[1]
            services[d_service_name] = d_service_ver

    return services


def draw_line(long):
    print('+', end = "")
    for i in range(0, long) :
        print("-", end = "")
    for i in range(0, 32) :
        print("-", end = "")
    print('+')


def getLong(list):
    tmp=[]
    for i in list:
        tmp.append(len(i))
    max_len=max(tmp)
    return max_len


def default_exploit(service): #only service name
    title = []
    url_list = []
    title_list = []
    cve_list = []
    cmd1 = commands.getoutput('searchsploit -jtw ' + service + ' > test1.json')
    file = open('test1.json')
    jsonObject = json.load(file)
    result = jsonObject.get("RESULTS_EXPLOIT")
    for list in result:
        #print(list.get("Title"))
        title.append(list.get("Title"))
        url_list.append(list.get("URL"))

    os.remove('test1.json')

    v = re.compile('[0-9]')
    cnt = 0

    for i in title:
        cnt += 1
    
        if(str(i).split(" ")[0] == 'MySQL' or str(i).split(" ")[0] == 'Oracle') :
            if v.search(i) == None:
                title_list.append(i)
                url = url_list[cnt-1]
                try :
                    response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    if response.status_code == 200 :
                        html = response.text
                        soup = BeautifulSoup(html, 'html.parser')
                        #print("connect")
                        target = soup.find_all('div', {'class':'col-6 text-center'})
                        try :
                            cve = target[1].find('a', {'target':'_blank'}).text.strip()
                            #print("CVE : " + cve)
                            cve_list.append(cve)
                        except :
                            #print("N/A")
                            cve_list.append("N/A")
                            
                except Exception as ex:
                    print(ex)
        else :
            
            if v.search(i) == None:
                title_list.append(i)
                url = url_list[cnt-1]
                try :
                    response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    if response.status_code == 200 :
                        html = response.text
                        soup = BeautifulSoup(html, 'html.parser')
                        #print("connect")
                        target = soup.find_all('div', {'class':'col-6 text-center'})
                        try :
                            cve = target[1].find('a', {'target':'_blank'}).text.strip()
                            #print("CVE : " + cve)
                            cve_list.append(cve)
                        except :
                            #print("N/A")
                            cve_list.append("N/A")
                            
                except Exception as ex:
                    print(ex)

    return title_list, cve_list, url_list  


def find_exploit(services):

    for service, version in services.items():  
        titles = []
        cve_list = []
        url_list = []     
        
        cmd = commands.getoutput('searchsploit -jtw ' +  service + ' ' + str(version) + ' > test.json') 
        file = open('test.json')
        jsonObject = json.load(file)
        result = jsonObject.get("RESULTS_EXPLOIT")
        default_titles, default_cves, default_url = default_exploit(service)
        os.remove('test.json')
        
        
        for list in result:
            
            title = list.get("Title")
            url = list.get("URL")
            
            match = ' ' + str(version)
                        
            if(title.split(' ')[0].lower() == service and match in title) :
                titles.append(str(title))
                url_list.append(str(url))
                try :
                    response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    if response.status_code == 200 :
                        html = response.text
                        soup = BeautifulSoup(html, 'html.parser')
                        #print("connect")
                        target = soup.find_all('div', {'class':'col-6 text-center'})
                        try :
                            cve = target[1].find('a', {'target':'_blank'}).text.strip()
                            #print("CVE : " + cve)
                            cve_list.append(cve)
                        except :
                            #print("N/A")
                            cve_list.append("N/A")
                            
                except Exception as ex:
                    print(ex)
        
        titles = titles + default_titles
        cve_list = cve_list + default_cves
        url_list = url_list + default_url
    
    return titles, cve_list, url_list
        
        # print('\n\033[1m\033[46m [ %s ] \033[0m' %(service))
        # max_len=getLong(titles)
        # #first line
        # draw_line(max_len)
        # #item name
        # print("  Title", end="")
        # for i in range(0, max_len-5) :
        #     print(" ", end = "")
        # print(' |  status')
        # #second line
        # draw_line(max_len)
        # #print title & cve
        # for i in range(0,len(titles)):
        #     print('| '+ titles[i], end='')
        #     for j in range(0, max_len-len(titles[i])):
        #         print(' ',end='')
        #     print(' | ', end='')
        #     print('\033[91m'+"CVE-"+cve_list[i]+'\033[0m', end='')
        #     for k in range(0, 30-len(cve_list[i])-6):
        #         print(' ',end='')
        #     print('|')
        # #end line
        # draw_line(max_len)

  
# def print_table(info_list):



  

if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], 'hosnctl', ['options'])

    if len(args) != 1:
        print("You Wrong")

    else:
        if opts == []:
            opts = [('-t', ''), ('-c', '')]

        print(opts)
        
        for option, arg in opts:
            if '-o' == option:
                print("You enter option Check Official Image " + arg)
            
            elif '-s' == option:
                print("You enter option Check Service Version " + arg)
            
            elif '-n' == option:
                print("You enter option Check num Exploit " + arg)

            elif '-c' == option or '-t' == option or '-l' == option:
                if '-t' == option:
                    print("You enter option Print Title " + arg)

                elif '-c' == option:
                    print("You enter option Print CVE " + arg)

                elif '-l' == option:
                    print("You enter option Print Link " + arg)
    

    # if dir_path == False:
    #     print("You Don't Have that folder or file")

    # print('Folder Path : %s' %(dir_path))

    # compose_path = commands.getoutput('find ' + dir_path + ' -name docker-compose.y*')

    # print('\nfindVer_image')
    # findVer_image = findVer_image(compose_path)
    # if findVer_image == False:
    #     print('findVer_image X')
    
    # else :
    #     print(findVer_image)
    #     dic_services = findVer_image.copy()
    
    # print('\nfindVer_package')
    # findVer_package = findVer_package(dir_path, compose_path)
    # if findVer_package == False:
    #     print('findVer_package X')
    
    # else :
    #     print(findVer_package)
    #     dic_services.update(findVer_package)
        
    # print('\nfindVer_env')
    # findVer_env = findVer_env(dir_path, compose_path)
    # if findVer_env == False:
    #     print('findVer_env X')
    
    # else :
    #     print(findVer_env)
    #     dic_services.update(findVer_env)

    # print('\nfindVer_dockerfile')
    # findVer_dockerfile = findVer_dockerfile(dir_path, compose_path)
    # if findVer_dockerfile == False:
    #     print('findVer_dockerfile X')
    
    # else :
    #     print(findVer_dockerfile)
    #     dic_services.update(findVer_dockerfile)

    # find_exploit(dic_services)




   
    # titles = []
    # cve = []
    # titles2 = []
    # cve2 = []
    # titles, cve = find_exploit(dic_services)
    # titles2, cve2 = default_exploit(dic_services)
    # titles = titles + titles2
    # cve = cve + cve2
    # max_len=getLong(titles)

    # #first line
    # draw_line(max_len)
    # #item name
    # print("  Title", end="")
    # for i in range(0, max_len-5) :
    #     print(" ", end = "")
    # print('|  status')
    # #second line
    # draw_line(max_len)
    # #print title & cve
    # for i in range(0,len(titles)):
    #     print('| '+ titles[i], end='')
    #     for j in range(0, max_len-len(titles[i])):
    #         print(' ',end='')
    #     print('| ', end='')
    #     print('\033[91m'+"CVE-"+cve[i]+'\033[0m', end='')
    #     for k in range(0, 30-len(cve[i])-5):
    #         print(' ',end='')
    #     print('|')
    # #end line
    # draw_line(max_len)


 
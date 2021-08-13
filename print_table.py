from __future__ import print_function
import os

def draw_line(terminal_size):
    #draw line
    print('+', end = "")
    for num in range(0, terminal_size-2):
        print("-", end = "")
    print('+')

def get_scale(info_list):
    rows, terminal_size = os.popen('stty size', 'r').read().split()
    terminal_size=int(terminal_size)
    print(terminal_size)

    # title, cve, url
    name_list = []
    column_num = len(info_list)


    if column_num == 3:
        for info in info_list:
            name_list.append(info[0])
        scale_title = 5.0
        scale_cve = 2.0
        scale_url = 3.0
        scale_all = scale_title + scale_cve + scale_url
        scale_list = [int(terminal_size*(scale_title/scale_all)), int(terminal_size*(scale_cve/scale_all)), int(terminal_size*(scale_url/scale_all))]
        return scale_list
        
    elif column_num == 2:
        for info in info_list:
            name_list.append(info[0])

        if 'Title' in name_list and 'CVE' in name_list:
            scale_title = 5.0
            scale_cve = 2.0
            scale_url = 0.0
            scale_all = scale_title + scale_cve + scale_url            
            scale_list = [int(terminal_size*(scale_title/scale_all)), int(terminal_size*(scale_cve/scale_all)), 0]

        elif 'Vul Title' in name_list and 'Status' in name_list:
            scale_vulname=7.0
            scale_status=3.0
            scale_all=10.0
            scale_list = [int(terminal_size*(scale_vulname/scale_all)), int(terminal_size*(scale_status/scale_all))]

        elif 'Title' in name_list and 'URL' in name_list:
            scale_title = 5.0
            scale_cve = 0.0
            scale_url = 3.0
            scale_all = scale_title + scale_cve + scale_url            
            scale_list = [int(terminal_size*(scale_title/scale_all)), 0, int(terminal_size*(scale_url/scale_all))]
            
        elif 'CVE' in name_list and 'URL' in name_list:
            scale_title = 0.0
            scale_cve = 2.0
            scale_url = 3.0
            scale_all = scale_title + scale_cve + scale_url
            scale_list = [0, int(terminal_size*(scale_cve/scale_all)), int(terminal_size*(scale_url/scale_all))]
        
        return scale_list


    elif column_num == 1:
        for info in info_list:
            name_list.append(info[0])

        if 'Title' in name_list:
            scale_title = 5.0
            scale_cve = 0.0
            scale_url = 0.0
            scale_all = scale_title + scale_cve + scale_url
            scale_list = [terminal_size*(scale_title/scale_all), 0, 0] 
        elif 'CVE' in name_list:
            scale_title = 0.0
            scale_cve = 2.0
            scale_url = 0.0
            scale_all = scale_title + scale_cve + scale_url
            scale_list = [0, terminal_size*(scale_cve/scale_all), 0] 
        elif 'URL' in name_list:
            scale_title = 0.0
            scale_cve = 0.0
            scale_url = 3.0
            scale_all = scale_title + scale_cve + scale_url
            scale_list = [0, 0, terminal_size*(scale_url/scale_all)] 
        
        return scale_list

    
    else:
        print("no info")

        return 0
    



def print_table(info_list):
    rows, terminal_size = os.popen('stty size', 'r').read().split()
    terminal_size = int(terminal_size)
    column_list = ['Title', 'CVE', 'URL']
    column_ubuntu_list=['Vul Title', 'Status']
    title_list = []
    cve_list = []
    url_list = []

    vul_list = []
    status_list = []
    repeat_num = 0

    for index, lst in enumerate(info_list):
        if column_list[0] in lst:
            title_list = info_list[index]
            repeat_num = len(title_list)

        if column_list[1] in lst:
            cve_list = info_list[index]
            repeat_num = len(cve_list)

        if column_list[2] in lst:
            url_list = info_list[index]
            repeat_num = len(url_list) 

        if column_ubuntu_list[0] in lst:
            vul_list = info_list[index]
            repeat_num =  len(vul_list)

        if column_ubuntu_list[1] in lst:
            status_list = info_list[index]
            repeat_num =  len(status_list)
    
    scale_list = get_scale(info_list)
    size_title = 0
    size_cve = 0
    size_url = 0

    #to print ubuntu table
    size_vulname = 0
    size_status = 0
    
    draw_line(terminal_size)

    if len(scale_list) == 2:
        size_vulname = int(scale_list[0])
        size_status = int(scale_list[1])
    
    else:
        if scale_list[0] != 0:
            size_title = int(scale_list[0])

        if scale_list[1] != 0:
            size_cve = int(scale_list[1])

        if scale_list[2] != 0:
            size_url = int(scale_list[2])
    


    #print column name
    if size_title != 0:
        print('| %s' %column_list[0][0:size_title], end = '')
        if size_title-7 > 0:

            for i in range(0, size_title-7) :
                print(' ', end = '')

    if size_cve != 0:
        print('| \033[91m%s\033[0m' %column_list[1][0:size_cve], end = '')
        if size_cve-5 > 0:
            for i in range(0, size_cve-5) :
                print(' ', end = '')
                
    if size_url != 0:
        print('| %s' %column_list[2][0:size_url], end = '')
        if size_url-5 > 0:
            for i in range(0, size_url-5) :
                print(' ', end = '')

    if size_vulname != 0:
        print('| %s' %column_ubuntu_list[0][0:size_vulname], end = '')
        if size_vulname-10 > 0:
            for i in range(0, size_vulname-10) :
                print(' ', end = '')

    if size_status != 0:
        print('| %s' %column_ubuntu_list[1][0:size_status], end = '')
        if size_status-8 > 0:
            for i in range(0, size_status-8) :
                print(' ', end = '')

    
    
    print('\n', end='')
    draw_line(terminal_size)



    for i in range(0, repeat_num):
        if size_title != 0:
            if len(title_list) < i+2:
                break

            if len(title_list[i+1]) >= size_title:
                print('| %s' %title_list[i+1][0:size_title-2], end = '')
            
            #len(title_list[i+1]) < size_title
            else: 
                print('| %s' %title_list[i+1], end = '')
                for j in range(0, size_title - len(title_list[i+1]) - 2) :
                    print(' ', end = '')
            
        if size_cve != 0:
            if len(cve_list) < i+2:
                break

            if len(cve_list[i+1]) >= size_cve:
                print('| \033[91m%s\033[0m' %cve_list[i+1][0:size_cve-2], end = '')

            else:
                print('| \033[91m%s\033[0m' %cve_list[i+1], end = '')
                for j in range(0, size_cve - len(cve_list[i+1]) - 2) :
                    print(' ', end = '')

        if size_url != 0:
            if len(url_list) < i+2:
                break

            if len(url_list[i+1]) >= size_url:
                print('| %s' %url_list[i+1][0:size_url-2], end = '')

            else:
                print('| %s' %url_list[i+1], end = '')
                for j in range(0, size_url - len(url_list[i+1]) - 2) :
                    print(' ', end = '')

        if size_vulname != 0:
            
            if len(vul_list) < i+2:
                
                break

            if len(vul_list[i+1]) >= size_vulname:
                print('| %s' %vul_list[i+1][0:size_vulname-2], end = '')

            else:
                print('| %s' %vul_list[i+1], end = '')
                for j in range(0, size_vulname - len(vul_list[i+1]) - 2) :
                    print(' ', end = '')
        
        print('\n', end='')

        if size_status != 0:
            if len(status_list) < i+2:
                break

            if len(status_list[i+1]) >= size_status:
                print('| %s' %status_list[i+1][0:size_status-2], end = '')

            else:
                print('| %s' %status_list[i+1], end = '')
                for j in range(0, size_status - len(status_list[i+1]) - 2) :
                    print(' ', end = '')
        
        print('\n', end='')




    draw_line(terminal_size)


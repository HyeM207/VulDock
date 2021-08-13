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
    title_list = []
    cve_list = []
    url_list = []
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
    
    scale_list = get_scale(info_list)
    size_title = 0
    size_cve = 0
    size_url = 0


    draw_line(terminal_size)


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
        
        print('\n', end='')





    draw_line(terminal_size)

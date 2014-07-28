#! /usr/bin/env python3
# -*- coding: utf-8 -*-

''' 
    PDF IP WHOIS info file generator using LaTeX

    Copyright (C) 2014  Babken Vardanyan

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import subprocess
import os
import shutil
import datetime
import sys
import ipwhois
import pprint


ORIGINAL_REPORT_FILE_NAME = 'report.pdf'
BACKUP_DIR_NAME = 'report_backups'
WHOIS_FILE_NAME = 'whois.txt'
IP_FILE_NAME = 'ip.txt'
LATEX_COMMAND = 'xelatex'
PDF_VIEWER_COMMAND = 'sumatrapdf'


def write_whois_info_to_file(ip_address, file_name):
    ''' Writes whois info about given IP address to file_name.

        Whois info is formatted using pprint.

        lookup_rws() can bypass some firewall on my setup,
        while lookup() can't. Feel free to change this to lookup().
    '''
    query_result = ipwhois.IPWhois(ip_address).lookup_rws()

    whois_file = open(file_name, 'w')

    pprint.pprint(query_result, whois_file)

    whois_file.close()


print('ip-whois-pdf-latex-report  Copyright (C) 2014  Babken Vardanyan\n'\
      'This program comes with ABSOLUTELY NO WARRANTY;'\
      'for details see LICENSE\n'\
      'This is free software, and you are welcome to redistribute it\n'\
      'under certain conditions; see LICENSE for details.\n')
IP = input('Enter IP: ')

IP_FILE = open(IP_FILE_NAME, 'w')

IP_FILE.write(IP)

IP_FILE.close()

write_whois_info_to_file(IP, WHOIS_FILE_NAME)

if subprocess.call([LATEX_COMMAND, 'report.tex']) != 0:
    print('Could not execute ' + LATEX_COMMAND + '!!!')
    input()
    exit()


os.makedirs(BACKUP_DIR_NAME, exist_ok=True)
shutil.copy(ORIGINAL_REPORT_FILE_NAME, BACKUP_DIR_NAME)
os.chdir(BACKUP_DIR_NAME)

CURRENT_DATE_TIME = datetime.datetime.now().strftime('%y-%m-%d_%H-%M')
RESULT_FILE_NAME = CURRENT_DATE_TIME + \
                   '__' + \
                   IP + \
                   '__' + \
                   ORIGINAL_REPORT_FILE_NAME

os.rename(ORIGINAL_REPORT_FILE_NAME, RESULT_FILE_NAME)

if sys.platform.startswith('linux'):
    subprocess.call(['xdg-open', RESULT_FILE_NAME])
else:
    os.startfile(RESULT_FILE_NAME)


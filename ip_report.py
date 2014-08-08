#! /usr/bin/env python
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

from __future__ import print_function
import subprocess
import os
import shutil
import time
import sys
from ipwhois import IPWhois
from ipwhois.utils import get_countries


# 2 & 3 compat
try:
    input = raw_input
except NameError:
    pass


def create_backup(filename, ip_address):
    ''' Copies filename into backup directory and returns full path of it
    '''
    backup_dir = 'backups'

    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)

    backup_filename = time.strftime('%d.%m.%Y_%H.%M.%S') +\
                      '__' +\
                      ip_address +\
                      '__' +\
                      filename
    backup_full_path = os.path.join(backup_dir, backup_filename)
    shutil.copy2(filename, backup_full_path)

    return backup_full_path


def get_string(data_structure, index):
    ''' Tries to retreive the value with index from data_structure.
        If the value doesn't exist, retruns empty string.
    '''
    inf = data_structure[index]
    if inf is not None:
        return inf.replace('\n', ', ')
    else:
        return ''


def get_whois_info(ip_address):
    ''' Returns WHOIS info about given ip_address as a string '''
    ip_info = IPWhois(ip_address).lookup_rws()

    country_string = get_countries()[ip_info['asn_country_code']]

    whois_string =\
        'IP address: ' + ip_address + '\n' +\
        'ASN (Autonomous System number): ' + get_string(ip_info, 'asn') +\
        '\n' +\
        'ASN CIDR: ' + get_string(ip_info, 'asn_cidr') + '\n' +\
        'ASN Country: ' + country_string + '\n' +\
        'ASN Registry: ' + get_string(ip_info, 'asn_registry') + '\n'

    for net in ip_info['nets']:
        country_string = get_countries()[ip_info['asn_country_code']]

        whois_string += '==== ' + get_string(net, 'name') + ' ====' + '\n' +\
            get_string(net, 'description') + ':\n' +\
            '    CIDR: ' + get_string(net, 'cidr') + '\n' +\
            '    Created: ' + get_string(net, 'created') + '\n' +\
            '    Updated: ' + get_string(net, 'updated') + '\n' +\
            '    ==== Geographic Data ====' + '\n' +\
            '    Country: ' + country_string + '\n' +\
            '    State: ' + get_string(net, 'state') + '\n' +\
            '    City: ' + get_string(net, 'city') + '\n' +\
            '    Address: ' + get_string(net, 'address') + '\n' +\
            '    Postal Code: ' + get_string(net, 'postal_code') + '\n' +\
            '    ==== Emails ====' + '\n' +\
            '    Abuse Email: ' + get_string(net, 'abuse_emails') + '\n' +\
            '    Tech Email: ' + get_string(net, 'tech_emails') + '\n' +\
            '    Misc Email: ' + get_string(net, 'misc_emails') + '\n'

    return whois_string


def compile_latex(filename_tex):
    ''' Compiles the filename_tex to PDF using xelatex
        LaTeX distribution is first searched in $PATH.
        If not found, it looks for a local miktex_portable directory.
    '''
    try:
        subprocess.call(['xelatex', filename_tex])
    except FileNotFoundError:
        print('Did not find xelatex in $PATH, looking for dir miktex_porable')
        try:
            subprocess.call(['miktex_portable\\miktex\\bin\\xelatex.exe',
                             filename_tex])
        except FileNotFoundError:
            print('Could not find local porable directory either. Aborting')
            sys.exit(1)


def view_file(filename):
    ''' Opens a file in OS's default file viewer '''
    if sys.platform.startswith('linux'):
        subprocess.call(['xdg-open', filename])
    else:
        os.startfile(filename)


def main():
    ''' Main function '''
    ip_address = input('Enter IP:')

    with open('ip.txt', 'w') as file_ip:
        file_ip.write(ip_address)

    with open('report.txt', 'w') as file_report:
        whois_info = get_whois_info(ip_address)
        file_report.write(whois_info)

    compile_latex('report.tex')

    report_pdf = create_backup('report.pdf', ip_address)

    view_file(report_pdf)


if __name__ == '__main__':
    main()


#!/usr/bin/env python

from collections import defaultdict
from xml.etree.ElementTree import *
import ConfigParser
import binascii
import datetime
import email
import getopt
import imaplib
import os
import re
import socket
import sys
import zipfile

from dns import resolver, reversename


DEBUG = 0
conf_file = '/etc/dmarc-parser/config.ini'
# a list of reports
reports = []
do_imap = False

# define globally, with a proper timeout
dns_resolver = resolver.Resolver()
dns_resolver.lifetime = 2


def usage():
    print '''
dmarc-parser.py: parse a dmarc XML report
    <-f>        DMARC XML report file
    <-c>        configuration file (default: /etc/dmarc-parser/config.ini)
    <--imap>    Pull UNSEEN emails from IMAP server (as configured in config.ini)
    <-D>        debug mode (more verbose)
    <-h>        help
'''


def log(msg):
    if DEBUG == 1:
        print msg


def ret_val(node, path):
    if node.find(path) is None:
        return '[none specified]'
    return str(node.find(path).text)


def unzip(filename):
    """ Unzip the members of a zipfile into report_dir
        only if their filename matched the regexes in PARSED_REPORTS
        and return the member name
    """
    zf = zipfile.ZipFile(filename, 'r')
    if zf:
        for member in zf.namelist():
            for report_re in PARSED_REPORTS:
                if re.match(report_re, member):
                    zf.extract(member, report_dir)
                    return member
    # delete zip file
    # os.delete(filename)
    return False


def imap_fetch_latest_reports():
    """ Connect to the IMAP dmarc mailbox
        dowload the latests reports
        and store them on the local disk
    """
    ziplist = []
    # create an imap ssl connection
    log('initializing connection to %s:%s' % (imap_server, imap_port))
    imap = imaplib.IMAP4_SSL(imap_server, imap_port)
    imap.login(imap_user, imap_passwd)

    # select the imap folder
    imap.select(dmarc_folder)

    # perform a search that returns a list of messages with
    # the UNSEEN flag set
    typ, message_number = imap.search(None, 'UNSEEN')

    # iterate through the list on messages
    for number in message_number[0].split():
        log('found unread email #%s' % (number,))
        # fetch the current message
        typ, data = imap.fetch(number, '(RFC822)')

        message = email.message_from_string(data[0][1])

        # loop over the attachments
        for part in message.walk():
            attach_name = part.get_filename()
            if attach_name:
                if not attach_name.endswith('.zip'):
                    log('ignoring non-zip attachment "{0}"'.format(attach_name))
                    continue

                log('extracting attachment')
                # extract the attachment from the email
                attach_dest = zip_dir + attach_name
                try:
                    attach_data = email.base64mime.decode(part.get_payload())
                except binascii.Error:
                    log('could not decode attachment "{0}"'.format(attach_name))
                    continue
                with open(attach_dest, "wb") as fd:
                    fd.write(attach_data)
                ziplist.append(attach_dest)

    imap.close()
    imap.logout()
    for zipped_report in ziplist:
        log('unzipping report %s' % (zipped_report,))
        report = unzip(zipped_report)
        if report:
            reports.append(report_dir + report)
    return reports


def dmarc_parse_record(record):
    """ Take a record in XML format and return
        a human readable line
    """
    hits = ret_val(record.node, 'row/count') + ' hits'
    dmarc_line = hits.ljust(10)

    reason = ''
    if ret_val(record.node, 'row/policy_evaluated/reason/type') != '[none specified]':
        reason += (
            '(policy_evaluated/reason = ' +
            ret_val(record.node, 'row/policy_evaluated/reason/type') + ')'
        )

    if ret_val(record.node, 'row/policy_evaluated/disposition') not in [
            '[none specified]', 'none']:
        reason += (
            '(policy_evaluated/disposition = ' +
            ret_val(record.node, 'row/policy_evaluated/disposition') + ')'
        )

    if ret_val(record.node, 'auth_results/dkim/result') != 'pass':
        if reason:
            reason += ' and '
        reason += (
            "(auth_results/dkim = fail, domain '" +
            ret_val(record.node, 'auth_results/dkim/domain') + "')"
        )
    if ret_val(record.node, 'auth_results/spf/result') != 'pass':
        if reason:
            reason += ' and '
        reason += (
            '(auth_results/spf = ' +
            ret_val(record.node, 'auth_results/spf/result') + ", domain '" +
            ret_val(record.node, 'auth_results/spf/domain') + "')"
        )

    if not reason:
        reason += 'no reason'

    dmarc_line += ' From: ' + ret_val(record.node, 'identities/header_from').ljust(15)

    dmarc_line += ' Reason: ' + reason

    return dmarc_line


def ptr_lookup(ip):
    log('PTR lookup for %s' % ip)
    # reverse DNS lookup
    rev_ip = reversename.from_address(ip)
    try:
        return str(dns_resolver.query(rev_ip, 'PTR')[0])
    except (resolver.NXDOMAIN,
            resolver.Timeout,
            resolver.NoAnswer,
            IndexError):
        return '<no ptr record found>'


def record_failures(record, type_):
    if ret_val(record, 'auth_results/dkim/result') != 'pass':
        dkim_fail[type_] += int(ret_val(record, 'row/count'))
    if ret_val(record, 'auth_results/spf/result') != 'pass':
        spf_fail[type_] += int(ret_val(record, 'row/count'))


def make_graphite_metrics(report, type_):
    dkim_metric = 'mail.dmarc.{0}.{1}.dkim {2} {3}\n'.format(
        report.find('report_metadata/org_name').text.replace('.', '_'),
        type_,
        dkim_fail[type_],
        report.find('report_metadata/date_range/end').text
    )
    spf_metric = 'mail.dmarc.{0}.{1}.spf {2} {3}\n'.format(
        report.find('report_metadata/org_name').text.replace('.', '_'),
        type_,
        spf_fail[type_],
        report.find('report_metadata/date_range/end').text
    )
    return '{0}{1}'.format(dkim_metric, spf_metric)


class Record:
    def __init__(self):
        self.is_owned = 0
        self.is_mx = 0
        self.ip = '0.0.0.0'
        self.count = 0
        self.body = ''


args_list, remainder = getopt.getopt(sys.argv[1:],
    'f:c:D', ['imap', ])

for argument, value in args_list:
    if argument in ('-f'):
        reports.append(value)
    if argument in ('--imap'):
        do_imap = True
    elif argument in ('-c'):
        conf_file = value
    elif argument in ('-D'):
        DEBUG = 1
    elif argument in ('-h'):
        usage()
        sys.exit()

'''Read configuration file'''
config = ConfigParser.ConfigParser()
config.read(conf_file)

PARSED_REPORTS = []
report_items = config.items('PARSED_REPORTS_REGEXES')
for key, report in report_items:
    PARSED_REPORTS.append(report)

OWNED_IPS = []
ip_items = config.items('OWNED_IPS_REGEXES')
for key, ip in ip_items:
    OWNED_IPS.append(ip)

MX_IPS = []
ip_items = config.items('MX_IPS')
for key, ip in ip_items:
    MX_IPS.append(ip)

if do_imap:
    imap_server = config.get('IMAP', 'server')
    imap_port = int(config.get('IMAP', 'port'))
    imap_user = config.get('IMAP', 'user')
    imap_passwd = config.get('IMAP', 'passwd')
    dmarc_folder = config.get('IMAP', 'dmarc_folder')
    report_dir = config.get('DIRS', 'report')
    zip_dir = config.get('DIRS', 'zip')

txt_record = config.get('DNS', 'txt_record')

''' Call the imap server to download the latest unseen emails '''
if do_imap:
    reports = imap_fetch_latest_reports()

if len(reports) < 1:
    print('\nNo report to process\n')
    usage()
    sys.exit()

for report_file in reports:
    # a dictionnary of owned ips
    is_owned = defaultdict(int)
    # a dictionnary of owned MX ips
    is_mx = defaultdict(int)
    # a dictionnary for IPs not owned
    is_other = defaultdict(int)
    # a dictionnary of records
    records = defaultdict(int)
    #some counters
    records_owned = 0
    records_owned_mx = 0
    records_other = 0
    hits_owned = 0
    hits_owned_mx = 0
    hits_other = 0
    dkim_fail = {
        'mx': 0,
        'owned': 0,
        'other': 0,
    }
    spf_fail = {
        'mx': 0,
        'owned': 0,
        'other': 0,
    }
    tree = ElementTree()
    try:
        report = tree.parse(report_file)
    except IOError:
        print("Can't open %s. IOError" % report_file)
        continue

    print('''Parsing DMARC report %s from %s\nperiod starts %s ends %s''' % (
        report.find('report_metadata/report_id').text,
        report.find('report_metadata/org_name').text,
        datetime.datetime.fromtimestamp(
            int(report.find('report_metadata/date_range/begin').text)
        ).strftime('%Y-%m-%d %H:%M:%S'),
        datetime.datetime.fromtimestamp(
            int(report.find('report_metadata/date_range/end').text)
        ).strftime('%Y-%m-%d %H:%M:%S'),
    ))

    print('\nTXT record: %s\n' %
        str(dns_resolver.query(txt_record, 'TXT')[0]))

    print('''Policy detected:
        domain: %s
        adkim:  %s (dkim identifier alignment {relaxed|strict})
        aspf:   %s (spf identified alignment {relaxed|strict})
        p:      %s (policy {none|quarantine|reject})
        sp:     %s (subdomains policy {none|quarantine|reject})
        pct:    %s {%% of mails DMARC was applied to}
        errors: %s
        ''' % (
            ret_val(report, 'policy_published/domain'),
            ret_val(report, 'policy_published/adkim'),
            ret_val(report, 'policy_published/aspf'),
            ret_val(report, 'policy_published/p'),
            ret_val(report, 'policy_published/sp'),
            ret_val(report, 'policy_published/pct'),
            ret_val(report, 'policy_published/error'),
        ))

    records_list = report.findall('record')
    counter = 0
    for current_record in records_list:
        ip = current_record.find('row/source_ip').text
        # test if the current IP belongs to owned ones or not
        records[counter] = Record()
        records[counter].ip = ip
        for aw_ip in OWNED_IPS:
            if re.match(aw_ip, ip):
                records[counter].is_owned = 1
                if not is_owned[ip]:
                    is_owned[ip] = []
                if counter not in is_owned[ip]:
                    is_owned[ip].append(counter)
                    records_owned += 1
                    hits_owned += int(ret_val(current_record, 'row/count'))
        if ip in MX_IPS:
            records[counter].is_mx = 1
            if not is_mx[ip]:
                is_mx[ip] = []
            if counter not in is_mx[ip]:
                is_mx[ip].append(counter)
                records_owned_mx += 1
                hits_owned_mx += int(ret_val(current_record, 'row/count'))
            record_failures(current_record, 'mx')
        elif records[counter].is_owned:
            record_failures(current_record, 'owned')
        else:
            if not is_other[ip]:
                is_other[ip] = []
            if counter not in is_other[ip]:
                is_other[ip].append(counter)
                records_other += 1
                hits_other += int(ret_val(current_record, 'row/count'))
            record_failures(current_record, 'other')
        records[counter].node = current_record
        counter += 1

    print('''Totals:
        %s hits
        %s records
        %s IPs
        %s DKIM failures from MX nodes
        %s SPF (soft)fail from MX nodes
        %s DKIM failures from owned nodes
        %s SPF (soft)fail from owned nodes
        %s DKIM failures from other nodes
        %s SPF (soft)fail from other nodes''' % (
            hits_owned + hits_other,
            records_owned + records_other,
            len(is_owned) + len(is_other),
            dkim_fail['mx'], spf_fail['mx'],
            dkim_fail['owned'], spf_fail['owned'],
            dkim_fail['other'], spf_fail['other'],
        ))

    print('\n\n===== Owned Non-MX IPs: %s hits in %s records from %s IPs =====\n' %
        (hits_owned - hits_owned_mx,
        records_owned - records_owned_mx,
        len(is_owned) - len(is_mx)))
    for ip in is_owned:
        if not ip in is_mx:
            print('%s [%s] %s records' % (ip, ptr_lookup(ip), len(is_owned[ip])))
            for counter in is_owned[ip]:
                print('\t* %s' % dmarc_parse_record(records[counter]))
            print

    print('\n\n===== Owned MX IPs: %s hits in %s records from %s IPs =====\n' %
        (hits_owned_mx, records_owned_mx, len(is_mx)))
    for ip in is_mx:
        print('%s [%s] %s records' % (ip, ptr_lookup(ip), len(is_mx[ip])))
        for counter in is_mx[ip]:
            print('\t* %s' % dmarc_parse_record(records[counter]))
        print

    print('\n\n===== Other IPs: %s hits from %s records in %s IPs =====\n' %
        (hits_other, records_other, len(is_other)))
    for ip in is_other:
        print('%s [%s] %s records' % (ip, ptr_lookup(ip), len(is_other[ip])))
        for counter in is_other[ip]:
            print('\t* %s' % dmarc_parse_record(records[counter]))
        print

    sock = None
    port = config.get('GRAPHITE', 'port')
    host = config.get('GRAPHITE', 'host')
    try:
        sock = socket.create_connection((host, port), timeout=0.5)
    except socket.error:
        log('Failed to connect to graphite server at {0}:{1}'.format(
            host, port))

    if sock:
        metrics = [make_graphite_metrics(report, ip_type) for ip_type in dkim_fail]
        sock.sendall(''.join(metrics))
        sock.close()

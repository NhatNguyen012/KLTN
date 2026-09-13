#!/usr/bin/env python3

import sys
import time
import argparse
import re
import time
import gzip
import json

from datetime import timedelta
from datetime import datetime

def is_present(new_m, desc_malicious, margins):
    for m in desc_malicious:
        if (m['hostname'] == new_m['hostname'] and \
                m['pid'] == new_m['pid']):
            return True
    return False


def is_malicious_event(json_line, desc_malicious, margins, verbose):
    margins_timedelta = timedelta(seconds=margins)
    for m in desc_malicious:
        #print(m['timestamp'] + ' ' + m['hostname'] + ' ' + m['pid'])
#        if (json_line['pid'] == m['pid']):
#            print(json_line['timestamp'] + ' ' + json_line['hostname'] + ' ' + \
#            str(json_line['pid']))

        hostname_re = re.compile(m['hostname'], re.I)
        if (hostname_re.match(json_line['hostname']) != None and \
                json_line['pid'] == m['pid'] and \
                json_line['timestamp'] >= m['timestamp'] - margins_timedelta):
            # found a possible malicous event
            # has to check if the agent should be still alive
            if (m['timestamp_end'] != 'Infinity' and json_line['timestamp'] <= m['timestamp_end'] + margins_timedelta):
                return True
            elif (m['timestamp_end'] == 'Infinity'):
                #look for the terminate of the process
                if (json_line['action'] == 'TERMINATE' and json_line['object'] == 'PROCESS' and json_line['actorID'] == json_line['objectID']):
                    #found a TERMINATE PROCESS
                    #update the malicious behavior desc
                    if verbose:
                        print('LOG: found a TERMINATE PROCESS')
                        print('LOG: new timestamp_end: ' + str(json_line['timestamp']) + ' for pid: ' + str(json_line['pid']))
                    m['timestamp_end'] = json_line['timestamp']
                    return True
                else:
                    #json_line['comment_label'] = 'event from an Infinity process'
                    return True
        #look for a CREATE PROCESS
        elif (hostname_re.match(json_line['hostname']) != None and \
                json_line['action'] == 'CREATE' and \
                json_line['object'] == 'PROCESS' and \
                json_line['ppid'] == m['pid'] and \
                json_line['timestamp'] >= m['timestamp'] - margins_timedelta):
            # found a potential creation of a child of a malicious process
            # need to check the date of the CREATE
            if (m['timestamp_end'] != 'Infinity' and json_line['timestamp'] <= m['timestamp_end'] + margins_timedelta):
                # need to add the child to the list of processes if not present
                if verbose:
                    print('LOG: Found a child')
                new_m = {}
                new_m['hostname'] = m['hostname']
                new_m['pid'] = json_line['pid']
                new_m['timestamp'] = json_line['timestamp']
                new_m['timestamp_end'] = 'Infinity'
                if (not is_present(new_m, desc_malicious, margins)):
                    desc_malicious.append(new_m)
                    if verbose:
                        print('LOG: ' + str(new_m))
                return True
            elif (m['timestamp_end'] == 'Infinity'):
                # add the child to the list of malicious processes
                # it is not sure that the parent is malicious...
                # thanks Infinity!
                if verbose:
                    print('LOG: found a potential child')
                new_m = {}
                new_m['hostname'] = m['hostname']
                new_m['pid'] = json_line['pid']
                new_m['timestamp'] = json_line['timestamp']
                new_m['timestamp_end'] = 'Infinity'
                if (not is_present(new_m, desc_malicious, margins)):
                    desc_malicious.append(new_m)
                    if verbose:
                        print('LOG: ' + str(new_m))
                return True
    return False

def transform_date(json_event, datetimeisoformat1_re, datetimeisoformat2_re):
    if (datetimeisoformat1_re.search(json_event['timestamp'])):
        json_event['timestamp'] = datetime.fromisoformat(re.sub(r'(\.\d)(-04)', r'\g<1>00-04', json_event['timestamp']))
    elif (datetimeisoformat2_re.search(json_event['timestamp'])):
        json_event['timestamp'] = datetime.fromisoformat(re.sub(r'(\.\d\d)(-04)', r'\g<1>0-04', json_event['timestamp']))
    else:
        json_event['timestamp'] = datetime.fromisoformat(json_event['timestamp'])
    return json_event



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Find the malicious event ids')
    parser.add_argument('-f', '--file', dest='file', action='store', default='', help="json or json gziped file containing ecar" )
    parser.add_argument('-d', '--description-file', dest='description_file', action='store', default='')
    parser.add_argument('-o', '--output-file', dest='output_file', action='store', default='')
    parser.add_argument('-m', '--margins', dest='margins', action='store', \
            default=10, type=int, help="Margins from the timestamp in seconds")
    parser.add_argument('-c', '--compact', dest='compact', action='store', \
            default=False, type=bool, help="compact=True means that the input json file is on one line and the events are in a array")
    #parser.add_argument('-p', '--print-malicious-processes', dest='print_malicious_processes', action='store', default=False, type=bool, help="print-malicious-processes: if True, print a small recap of all the malicious processes")
    #parser.add_argument('-v', '--csv-malicious-processes', dest='csv_malicious_processes', action='store', default=False, type=bool, help="csv-malicious-processes: if True, print a small recap of all the malicious processes in csv style")
    #parser.add_argument('-s', '--print-malicious-events', dest='print_malicious_events', action='store', default=True, type=bool, help="print-malicious-events: if True, print all the malicious events")
    parser.add_argument('-v', '--verbose', dest='verbose', action=argparse.BooleanOptionalAction, default=False, help="verbose: if True, print some logs")
    parser.add_argument('-p', '--print-malicious-processes', dest='print_malicious_processes', action=argparse.BooleanOptionalAction, default=False, help="print-malicious-processes: if True, print a small recap of all the malicious processes")
    parser.add_argument('-e', '--print-malicious-events', dest='print_malicious_events', action=argparse.BooleanOptionalAction, default=True, help="print-malicious-events: if True, print all the malicious events")
    parser.add_argument('-s', '--csv-malicious-processes', dest='csv_malicious_processes', action=argparse.BooleanOptionalAction, default=False, help="csv-malicious-processes: if True, print a small recap of all the malicious processes in csv style")

    args = parser.parse_args()

    
    # Read the description file
    try:
        desc_file = open(args.description_file, 'r')
    except:
        print("Error: cannot open the description file: " + args.description_file)
        exit(1)
    
    # Construct the table containing the tuples (hostname, pid, timestamp)
    desc_malicious = []
    for line in desc_file:
        if (not line.startswith('#')):
            m = {}
            (m['hostname'], m['pid'], m['timestamp'], m['timestamp_end']) = line.strip().split(',')
            m['pid'] = int(m['pid'])
            m['timestamp'] = datetime.fromisoformat(m['timestamp'])
            if (m['timestamp_end'] != 'Infinity'):
                m['timestamp_end'] = datetime.fromisoformat(m['timestamp_end'])
            desc_malicious.append(m)

    compact = args.compact
    # Read the log file
    try:
        if args.file.endswith('.gz'):
            log_file = gzip.open(args.file, 'r')
        else:
            log_file = open(args.file, 'r')
    except:
        print("Error: cannot open the log file: " + args.file)
        exit(2)

    datetimeisoformat1_re = re.compile(r'(\.\d)(-04)')
    datetimeisoformat2_re = re.compile(r'(\.\d\d)(-04)')

    for line in log_file:
        json_line = json.loads(line)
        if (compact == False):
            json_event = transform_date(json_line, datetimeisoformat1_re, datetimeisoformat2_re)
            if (is_malicious_event(json_event, desc_malicious, args.margins, args.verbose)):
                if (args.print_malicious_events):
                    json_event['timestamp'] = json_event['timestamp'].isoformat(sep='T', timespec='milliseconds')
                    json_event_str = json.dumps(json_event)
                    print(json_event_str)
        else:
            for json_event in json_line:
                json_event = transform_date(json_event, datetimeisoformat1_re, datetimeisoformat2_re)
                if (is_malicious_event(json_event, desc_malicious, args.margins, args.verbose)):
                    if (args.print_malicious_events):
                        json_event['timestamp'] = json_event['timestamp'].isoformat(sep='T', timespec='milliseconds')
                        json_event_str = json.dumps(json_event)
                        print(json_event_str)


    if (args.print_malicious_processes):
        for m in desc_malicious:
            if (args.csv_malicious_processes):
                if (m['timestamp_end'] == 'Infinity'):
                    end_timestamp = 'Infinity'
                else:
                    end_timestamp = m['timestamp_end'].isoformat(sep='T', timespec='milliseconds')
                print(str(m['hostname']) + ',' + str(m['pid']) + ',' + m['timestamp'].isoformat(sep='T', timespec='milliseconds') + ',' + end_timestamp)
            else:
                print(m)



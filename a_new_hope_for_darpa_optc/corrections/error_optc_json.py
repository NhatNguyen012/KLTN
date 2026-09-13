import json
import pickle
import os
import gzip
from datetime import datetime, timedelta
import argparse
import sys
import gzip,json
import pandas as pd
from itertools import islice
from typing import Any, Dict, Iterator, List, Optional, Union


def export_json_gzip(outdir, name, machine, data):
    data = [{k: v} for k, v in data.items()]
    with gzip.open(outdir + name + machine + '.json.gzip', 'w') as h:
        for txt in data:
            if txt is not None:
                h.write((json.dumps(txt) + '\n').encode('utf-8'))

def optc_terminate_check(benign_root, eval_root, outdir, key):
    """
    This function outputs three dictionnaries in order to monitor OpTC errors. In particular, it aims to find the following
    case : a PROCESS with objectID x is TERMINATED at timestamp t. If a log with the same objectID or actorID x appears
    after the timestamp t+1second, then we consider this is a mistake, that the ID x is not correct. Errors_counts
    associates each false x to the number of logs concerned by the mistakes, errors_start associates x to the start of
    the mistake and errors_end associates x to the end of the mistake.
    :return: None
    """

    # filelist = sorted([os.path.join(root, name) for root, dirs, files in os.walk(benign_root) for name in files if
    #                    name.endswith(('.gz'))])
    # filelist += sorted([os.path.join(root, name) for root, dirs, files in os.walk(eval_root) for name in files if
    #                     name.endswith(('.gz')) and 'labeled2' in name])
    #


    filelist = sorted([os.path.join(root, name) for root, dirs, files in os.walk(benign_root) for name in files if 'SysClient' in name]) # to remive
    filelist += sorted([os.path.join(root, name) for root, dirs, files in os.walk(eval_root) for name in files if 'SysClient' in name]) # to remove

    f = sorted(list([[fl.split('/')[-1].split('AIA-')[1].split('.')[0],fl.split('SysClient')[1].split('.')[0]] for fl in filelist]))
    f = pd.DataFrame(f, columns= ['group','machine'])
    f = f.drop_duplicates().sort_values(['machine'])
    f = f.reset_index(drop=True)

    #f = sorted(list(set([fl.split('/')[-1].split('.')[0] for fl in filelist])))

    #list_affected = ['0201', '0402', '0660', '0104', '0205', '0321', '0255', '0355', '0503', '0462', '0559', '0419', '0609', '0771', '0955', '0874', '0170', '0501', '0811', '0010', '0069', '0203', '0358', '0618', '0851', '0051', '0351']
    #machine = list_affected[key-1]
    #group = f[f['machine']==machine]['group'].iloc[0]

    machine = f.iloc[key-1]['machine']
    group = f.iloc[key-1]['group']


    sys.stdout.flush()
    filelist = [f for f in filelist if machine in f]


    actor_ID = {}
    several_create_id = {}
    actor_ID_last_event = {}  # dictionary with [uid_process]= first time it's terminated
    process_not_terminated = []
    pid = {}
    errors_counts_actorID = {}
    errors_counts_objectID = {}
    errors_count_not_create_ID = {}
    errors_counts_actorID_of_terminated_objectID = {}
    errors_start_actorID = {}
    errors_end_actorID = {}
    error_tgt_pid_uuid = {}
    error_task_process_uuid = {}
    error_terminated_thread = {}
    error_terminated_session = {}

    thread = {}
    user_seesion = {}

    for file in filelist:
        with gzip.open(file, 'rt') as f:
            for l, line in enumerate(f):
                # if l >1000000: # to remove
                #     break # to remove
                # else : # to remove
                val_line = json.loads(line)
                if type(val_line)==str:
                    val_line=json.loads(val_line)
                #if val_line['id']=="6eadb402-114e-43c0-b076-e5913dca1e75":
                # if 'benign' in file:
                #     val_line = json.loads(val_line)

                # if this log actorID is already terminated, check if its timestamp is more than the previously
                # terminated timestamp + 1 second. If yes, means there is a mistake about this actorID (it should be
                # terminated while its not)
                try:
                    date_timestamp = datetime.strptime(val_line['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z')
                    str_timestamp = val_line['timestamp']
                except:
                    timestamp = datetime.strptime(val_line['timestamp'], '%Y-%m-%dT%H:%M:%S%z')
                    date_timestamp = timestamp + timedelta(milliseconds=00000)
                    str_timestamp = timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')

                # process envent != create : add last event of process in last event actor id dict or add process to actor ID if create not seen

                # if val_line['actorID']=='53a99386-af05-49bb-9940-838cd115cd4a' and val_line['hostname']=='SysClient0018.systemia.com':
                #     print(val_line)
                # if ('properties' in val_line.keys()) and val_line['object']=='THREAD':
                #     if val_line['properties']['tgt_pid_uuid']=='53a99386-af05-49bb-9940-838cd115cd4a' and val_line['hostname']=='SysClient0018.systemia.com':
                #         print(val_line)
                # if ('properties' in val_line.keys()) and val_line['object'] == 'TASK':
                #     print(val_line)
                #     if val_line['properties']['task_process_uuid'] == '53a99386-af05-49bb-9940-838cd115cd4a' and val_line[
                #         'hostname'] == 'SysClient0018.systemia.com':
                #         print(val_line)


                if val_line['object'] == 'PROCESS' and val_line['action'] not in ['CREATE', 'TERMINATE']:
                    if val_line['actorID']+","+val_line['hostname'] in actor_ID:
                        actor_ID_last_event[val_line['actorID']+","+val_line['hostname']] = str_timestamp
                        actor_ID[val_line['actorID']+","+val_line['hostname']][2] += 1


                    else:
                        actor_ID[val_line['actorID']+","+val_line['hostname']] = [str(val_line['pid']), [[val_line['action'],val_line['object']]], 1, val_line['ppid'], 'image_path', 'command_line','principal','user','sid','parent_image_path', str_timestamp]
                        if ('image_path' in val_line['properties']) :
                            actor_ID[val_line['actorID']+","+val_line['hostname']][4]=val_line['properties']['image_path']
                        if ('command_line' in val_line['properties']):
                            actor_ID[val_line['actorID']+","+val_line['hostname']][5] = val_line['properties']['command_line']
                        if ('user' in val_line['properties']):
                            actor_ID[val_line['actorID'] + "," + val_line['hostname']][7] = val_line['properties']['user']
                        if ('sid' in val_line['properties']):
                            actor_ID[val_line['actorID'] + "," + val_line['hostname']][8] = val_line['properties']['sid']
                        if ('parent_image_path' in val_line['properties']):
                            actor_ID[val_line['actorID'] + "," + val_line['hostname']][9] = val_line['properties']['parent_image_path']
                        if 'principal' in val_line:
                            actor_ID[val_line['actorID']+","+val_line['hostname']][6] = val_line['principal']


                        actor_ID_last_event[val_line['actorID']+","+val_line['hostname']] = str_timestamp

                        if str(val_line['pid'])+","+val_line['hostname'] in pid :
                            if len(actor_ID[pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']]) < 12:
                                actor_ID[pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']].append((datetime.strptime(actor_ID_last_event[pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']], '%Y-%m-%dT%H:%M:%S.%f%z')+ timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%S.%f%z'))
                                actor_ID[pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']][2] += 1
                                actor_ID[pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']][1].append([val_line['action'],val_line['object']])
                                process_not_terminated.append(pid[str(val_line['pid'])+","+val_line['hostname']][-1][0])
                            pid[str(val_line['pid'])+","+val_line['hostname']].append([val_line['actorID'], str_timestamp])
                        else:
                            pid[str(val_line['pid'])+","+val_line['hostname']] = [[val_line['actorID'], str_timestamp]]

                if val_line['object'] != 'PROCESS' and val_line['object'] not in ['THREAD','TASK']:
                    if val_line['actorID']+","+val_line['hostname'] in actor_ID:
                        actor_ID_last_event[val_line['actorID']+","+val_line['hostname']] = str_timestamp
                        actor_ID[val_line['actorID']+","+val_line['hostname']][2] += 1


                    else:
                        actor_ID[val_line['actorID']+","+val_line['hostname']] = [str(val_line['pid']), [[val_line['action'],val_line['object']]], 1, val_line['ppid'], 'image_path', 'command_line','principal', 'user','sid','parent_image_path',str_timestamp]

                        if ('image_path' in val_line['properties']) :
                            actor_ID[val_line['actorID']+","+val_line['hostname']][4]=val_line['properties']['image_path']
                        if('command_line' in val_line['properties']):
                            actor_ID[val_line['actorID']+","+val_line['hostname']][5] = val_line['properties']['command_line']
                        if ('user' in val_line['properties']):
                            actor_ID[val_line['actorID'] + "," + val_line['hostname']][7] = val_line['properties']['user']
                        if ('sid' in val_line['properties']):
                            actor_ID[val_line['actorID'] + "," + val_line['hostname']][8] = val_line['properties'][ 'sid']
                        if ('parent_image_path' in val_line['properties']):
                            actor_ID[val_line['actorID'] + "," + val_line['hostname']][9] = val_line['properties'][ 'parent_image_path']
                        if 'principal' in val_line:
                            actor_ID[val_line['actorID']+","+val_line['hostname']][6] = val_line['principal']


                        actor_ID_last_event[val_line['actorID']+","+val_line['hostname']] = str_timestamp

                        if str(val_line['pid'])+","+val_line['hostname'] in pid :
                            if len(actor_ID[pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']]) < 12:
                                actor_ID[pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']].append((datetime.strptime(actor_ID_last_event[pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']], '%Y-%m-%dT%H:%M:%S.%f%z')+ timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%S.%f%z'))
                                actor_ID[pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']][2] += 1
                                actor_ID[pid[str(val_line['pid']) + "," + val_line['hostname']][-1][0] + "," + val_line['hostname']][1].append([val_line['action'],val_line['object']])
                                process_not_terminated.append(pid[str(val_line['pid'])+","+val_line['hostname']][-1][0])
                            pid[str(val_line['pid'])+","+val_line['hostname']].append([val_line['actorID'], str_timestamp])
                        else:
                            pid[str(val_line['pid'])+","+val_line['hostname']] = [[val_line['actorID'], str_timestamp]]



                if val_line['object'] in ['THREAD','TASK'] :
                    if 'tgt_pid_uuid' in list(val_line['properties'].keys()):
                        if val_line['properties']['tgt_pid_uuid']+","+val_line['hostname'] in actor_ID:
                            actor_ID_last_event[val_line['properties']['tgt_pid_uuid']+","+val_line['hostname']] = str_timestamp
                            actor_ID[val_line['properties']['tgt_pid_uuid']+","+val_line['hostname']][2] += 1
                        else:
                            actor_ID[val_line['properties']['tgt_pid_uuid']+","+val_line['hostname']] = [int(val_line['properties']['tgt_pid']), [[val_line['action'],val_line['object']]], 1, val_line['ppid'],'image_path', 'command_line','principal', 'user','sid','parent_image_path', str_timestamp]
                            if 'image_path' in val_line['properties']: actor_ID[val_line['properties']['tgt_pid_uuid']+","+val_line['hostname']][4] = val_line['properties']['image_path']
                            if 'command_line' in val_line['properties']:actor_ID[val_line['properties']['tgt_pid_uuid']+","+val_line['hostname']][5] = val_line['properties']['command_line']
                            if ('user' in val_line['properties']):actor_ID[val_line['properties']['tgt_pid_uuid'] + "," + val_line['hostname']][7] = val_line['properties']['user']
                            if ('sid' in val_line['properties']):actor_ID[val_line['properties']['tgt_pid_uuid'] + "," + val_line['hostname']][8] = val_line['properties']['sid']
                            if ('parent_image_path' in val_line['properties']):actor_ID[val_line['properties']['tgt_pid_uuid'] + "," + val_line['hostname']][9] = val_line['properties']['parent_image_path']
                            if 'principal' in val_line : actor_ID[val_line['properties']['tgt_pid_uuid']+","+val_line['hostname']][6] = val_line['principal']

                            actor_ID_last_event[val_line['properties']['tgt_pid_uuid']+","+val_line['hostname']] = str_timestamp
                            if str(val_line['properties']['tgt_pid'])+","+val_line['hostname'] in pid:
                                if len(actor_ID[pid[str(val_line['properties']['tgt_pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']]) < 12:
                                    actor_ID[pid[str(val_line['properties']['tgt_pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']].append((datetime.strptime(actor_ID_last_event[pid[str(val_line['properties']['tgt_pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']], '%Y-%m-%dT%H:%M:%S.%f%z')+ timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%S.%f%z'))
                                    actor_ID[pid[str(val_line['properties']['tgt_pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']][2] += 1
                                    actor_ID[pid[str(val_line['properties']['tgt_pid']) + "," + val_line['hostname']][-1][0] + "," + val_line['hostname']][1].append([val_line['action'],val_line['object']])
                                    process_not_terminated.append(pid[str(val_line['properties']['tgt_pid'])+","+val_line['hostname']][-1][0])
                                pid[str(val_line['properties']['tgt_pid'])+","+val_line['hostname']].append([val_line['properties']['tgt_pid_uuid'], str_timestamp])
                            else :
                                pid[str(val_line['properties']['tgt_pid'])+","+val_line['hostname']] = [[val_line['properties']['tgt_pid_uuid'], str_timestamp]]





                    if 'task_process_uuid' in list(val_line['properties'].keys()):
                        if val_line['properties']['task_process_uuid']+","+val_line['hostname'] in actor_ID:
                            actor_ID_last_event[val_line['properties']['task_process_uuid']+","+val_line['hostname']] = str_timestamp
                            actor_ID[val_line['properties']['task_process_uuid']+","+val_line['hostname'] ][2] += 1

                        else:
                            actor_ID[val_line['properties']['task_process_uuid']+","+val_line['hostname']] = [str(val_line['properties']['task_pid']),[[val_line['action'],val_line['object']]], 1, val_line['ppid'],'image_path', 'command_line','principal', 'user','sid','parent_image_path',str_timestamp]
                            if 'image_path' in val_line['properties']:
                                actor_ID[(val_line['properties']['task_process_uuid']+","+val_line['hostname'])][4] = val_line['properties']['image_path']
                            if 'command_line' in val_line['properties'] :
                                actor_ID[(val_line['properties']['task_process_uuid']+","+val_line['hostname'])][5] = val_line['properties']['command_line']
                            if ('user' in val_line['properties']):
                                actor_ID[val_line['properties']['task_process_uuid'] + "," + val_line['hostname']][7] = val_line['properties']['user']
                            if ('sid' in val_line['properties']):
                                actor_ID[val_line['properties']['task_process_uuid'] + "," + val_line['hostname']][8] = val_line['properties']['sid']
                            if ('parent_image_path' in val_line['properties']):
                                actor_ID[val_line['properties']['task_process_uuid'] + "," + val_line['hostname']][9] = val_line['properties']['parent_image_path']
                            if 'principal' in val_line :
                                actor_ID[(val_line['properties']['task_process_uuid']+","+val_line['hostname'])][6] = val_line['principal']



                            actor_ID_last_event[val_line['properties']['task_process_uuid']+','+val_line['hostname']] = str_timestamp
                            if str(val_line['properties']['task_pid'])+","+val_line['hostname'] in pid:
                                if len(actor_ID[pid[str(val_line['properties']['task_pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']]) < 12:
                                    actor_ID[pid[str(val_line['properties']['task_pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']].append((datetime.strptime(actor_ID_last_event[pid[val_line['properties']['task_pid']+","+val_line['hostname']][-1][0]+","+ val_line['hostname']], '%Y-%m-%dT%H:%M:%S.%f%z')+ timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%S.%f%z'))
                                    actor_ID[pid[str(val_line['properties']['task_pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']][2] += 1
                                    actor_ID[pid[str(val_line['properties']['task_pid']) + "," + val_line['hostname']][-1][0] + "," + val_line['hostname']][1].append([val_line['action'],val_line['object']])
                                    process_not_terminated.append(pid[str(val_line['properties']['task_pid'])+","+val_line['hostname']][-1][0])
                                pid[str(val_line['properties']['task_pid'])+","+val_line['hostname']].append([val_line['properties']['task_process_uuid'], str_timestamp])
                            else :
                                pid[str(val_line['properties']['task_pid'])+","+val_line['hostname']] = [[val_line['properties']['task_process_uuid'], str_timestamp]]

                    # else:
                    #     if 'task_pid' in list(val_line['properties'].keys()):# gestion absence de tgt_pid_uuid
                    #         pid[(str(val_line['properties']['task_pid']), val_line['hostname'])] = [['Unknown', str_timestamp]]
                    #     elif 'tgt_pid' in list(val_line['properties'].keys()):
                    #         pid[(str(val_line['properties']['tgt_pid']), val_line['hostname'])] = [['Unknown', str_timestamp]]


                    # if (str(val_line['pid']), val_line['hostname']) not in pid:
                    #     pid[(str(val_line['pid']), val_line['hostname'])] = [[val_line['actorID'], str_timestamp]]

                # create process

                if val_line['object'] == 'PROCESS' and val_line['action'] == 'CREATE':
                    # check if actorID already create : if yes, add in several create id
                    if val_line['objectID']+","+val_line['hostname'] in actor_ID:
                        if val_line['objectID']+","+val_line['hostname'] in several_create_id:
                            several_create_id[val_line['objectID']+","+val_line['hostname']].append(str_timestamp)
                        else:
                            several_create_id[val_line['objectID']+","+val_line['hostname']] = [str_timestamp]

                    # Add to actor_ID

                    actor_ID[val_line['objectID'] + "," + val_line['hostname']] = [str(val_line['pid']), [[val_line['action'], val_line['object']]], 1, val_line['ppid'], 'image_path', 'command_line','principal', 'user', 'sid','parent_image_path', str_timestamp]

                    if 'image_path' in val_line['properties']:
                        actor_ID[val_line['objectID']+","+val_line['hostname']][4] = val_line['properties']['image_path']
                    if 'command_line' in ['properties']:
                        actor_ID[val_line['objectID']+","+val_line['hostname']][5] = val_line['properties']['command_line']
                    if ('user' in val_line['properties']):
                        actor_ID[val_line['objectID'] + "," + val_line['hostname']][7] = val_line['properties'][
                            'user']
                    if ('sid' in val_line['properties']):
                        actor_ID[val_line['objectID'] + "," + val_line['hostname']][8] = val_line['properties'][
                            'sid']
                    if ('parent_image_path' in val_line['properties']):
                        actor_ID[val_line['objectID'] + "," + val_line['hostname']][9] = val_line['properties'][
                            'parent_image_path']
                    if 'principal' in val_line:
                        actor_ID[val_line['objectID']+","+val_line['hostname']][6] = val_line['principal']

                    actor_ID_last_event[val_line['objectID']+","+val_line['hostname']] = str_timestamp

                    # check if pid reuse for this create
                    if str(val_line['pid'])+","+val_line['hostname'] in pid :
                        # if yes, check if last process of this pid is terminated : if not terminated it using last event of the process and add to processes not terminated

                        if pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname'] != val_line['objectID']+","+val_line['hostname']:

                            if len(actor_ID[pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']]) <12:
                                actor_ID[pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']].append((datetime.strptime(actor_ID_last_event[pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']], '%Y-%m-%dT%H:%M:%S.%f%z')+ timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%S.%f%z'))
                                actor_ID[pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']][2] +=1
                                actor_ID[pid[str(val_line['pid']) + "," + val_line['hostname']][-1][0] + "," + val_line['hostname']][1].append([val_line['action'],val_line['object']])
                                process_not_terminated.append(pid[str(val_line['pid'])+","+val_line['hostname']][-1][0])


                            # Add new process create with this pid in pid dict
                            pid[str(val_line['pid'])+","+val_line['hostname']].append([val_line['objectID'], str_timestamp])
                        else :
                            pid[str(val_line['pid'])+","+val_line['hostname']][-1]=[val_line['objectID'], str_timestamp]
                    # if new pid, add it to pid dict
                    else:
                        pid[str(val_line['pid'])+","+val_line['hostname']] = [[val_line['objectID'], str_timestamp]]

                # terminate process
                if val_line['object'] == 'PROCESS' and val_line['action'] == 'TERMINATE':
                    if val_line['actorID']+","+val_line['hostname'] in actor_ID:
                        actor_ID[val_line['actorID']+","+val_line['hostname']].append((datetime.strptime(str_timestamp, '%Y-%m-%dT%H:%M:%S.%f%z') + timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%S.%f%z'))
                        actor_ID[val_line['actorID']+","+val_line['hostname']][2] +=1
                        actor_ID[val_line['actorID'] + "," + val_line['hostname']][1].append([val_line['action'],val_line['object']])
                    else:
                        actor_ID[val_line['actorID']+","+val_line['hostname']] = [str(val_line['pid']), [[val_line['action'],val_line['object']]], 1,val_line['ppid'], 'image_path','command_line','principal','user','sid','parent_image_path', -1, (datetime.strptime(str_timestamp, '%Y-%m-%dT%H:%M:%S.%f%z') + timedelta(seconds=1)).strftime( '%Y-%m-%dT%H:%M:%S.%f%z')]

                        if ('image_path' in val_line['properties']) :
                            actor_ID[val_line['actorID']+","+val_line['hostname']][4] = val_line['properties']['image_path']
                        if ('command_line' in val_line['properties']):
                            actor_ID[val_line['actorID']+","+val_line['hostname']][5] = val_line['properties']['command_line']
                        if ('user' in val_line['properties']):
                            actor_ID[val_line['actorID'] + "," + val_line['hostname']][7] = val_line['properties'][ 'user']
                        if ('sid' in val_line['properties']):
                            actor_ID[val_line['actorID'] + "," + val_line['hostname']][8] = val_line['properties'][
                                'sid']
                        if ('parent_image_path' in val_line['properties']):
                            actor_ID[val_line['actorID'] + "," + val_line['hostname']][9] = val_line['properties'][
                                'parent_image_path']
                        if 'principal' in val_line:
                            actor_ID[val_line['actorID']+","+val_line['hostname']][6] = val_line['principal']


                        actor_ID_last_event[val_line['actorID']+","+val_line['hostname']]=str_timestamp
                        if str(str(val_line['pid']))+","+val_line['hostname'] in pid:
                            if len(actor_ID[pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']]) < 12:
                                actor_ID[pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+","+val_line['hostname']].append((datetime.strptime(actor_ID_last_event[pid[str(val_line['pid'])+','+val_line['hostname']][-1][0]+','+val_line['hostname']], '%Y-%m-%dT%H:%M:%S.%f%z')+ timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%S.%f%z'))
                                actor_ID[pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]+','+val_line['hostname']][2] += 1
                                actor_ID[pid[str(val_line['pid']) + "," + val_line['hostname']][-1][0] + ',' + val_line['hostname']][1].append([val_line['action'],val_line['object']])
                                process_not_terminated.append(pid[str(val_line['pid'])+","+val_line['hostname']][-1][0])
                        else :
                            pid[str(val_line['pid'])+","+val_line['hostname']] = [[val_line['actorID'], str_timestamp]]

                # identify objectID open before create
                if val_line['object'] == 'PROCESS' and val_line['action'] == 'OPEN' and val_line['objectID']+","+val_line['hostname'] not in actor_ID:
                    if val_line['objectID']+","+val_line['hostname'] in errors_count_not_create_ID:
                        errors_count_not_create_ID[val_line['objectID']+","+val_line['hostname']].append(str_timestamp)
                    else:
                        errors_count_not_create_ID[val_line['objectID']+","+val_line['hostname']] = [str_timestamp]

                # identify terminated actorID
                if (val_line['actorID']+","+val_line['hostname'] in actor_ID):
                    if  len(actor_ID[val_line['actorID']+","+val_line['hostname']])  >  12 and  val_line['action']=='TERMINATE' and val_line['object']=='PROCESS':
                            if datetime.strptime(actor_ID[val_line['actorID']+","+val_line['hostname']][-1],'%Y-%m-%dT%H:%M:%S.%f%z') == (datetime.strptime(str_timestamp, '%Y-%m-%dT%H:%M:%S.%f%z') + timedelta(seconds=1)):
                                if val_line['actorID']+","+val_line['hostname'] in errors_counts_actorID:  # if we have already flag this actorID has malicious, increase the number of concerned logs
                                    errors_counts_actorID[val_line['actorID']+","+val_line['hostname']][0] += 1
                                    errors_counts_actorID[val_line['actorID']+","+val_line['hostname']][1].append([str(val_line['pid']),val_line['id'], val_line['action'],val_line['object'],str_timestamp, pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]])
                                else:  # first time we observe the wrong UID, set the number of logs to 1 and create the start time
                                    errors_counts_actorID[val_line['actorID']+","+val_line['hostname']] = [1, [[str(val_line['pid']),val_line['id'], val_line['action'],val_line['object'], str_timestamp, pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]]]]
                                    errors_start_actorID[val_line['actorID']+","+val_line['hostname']] = str_timestamp
                    elif len(actor_ID[val_line['actorID']+","+val_line['hostname']])  >=  12  :
                        if date_timestamp > (datetime.strptime(actor_ID[val_line['actorID']+","+val_line['hostname']][-1],'%Y-%m-%dT%H:%M:%S.%f%z')) :
                            if val_line['actorID']+","+val_line['hostname'] in errors_counts_actorID:  # if we have already flag this actorID has malicious, increase the number of concerned logs
                                errors_counts_actorID[val_line['actorID']+","+val_line['hostname']][0] += 1
                                try:
                                    aa = pid[str(val_line['pid'])+","+val_line['hostname']]
                                except:
                                    print('error')
                                errors_counts_actorID[val_line['actorID']+","+val_line['hostname']][1].append([str(val_line['pid']),val_line['id'], val_line['action'],val_line['object'],str_timestamp, pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]])
                            else:  # first time we observe the wrong UID, set the number of logs to 1 and create the start time
                                errors_counts_actorID[val_line['actorID']+","+val_line['hostname']] = [1, [[str(val_line['pid']),val_line['id'], val_line['action'],val_line['object'], str_timestamp, pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]]]]
                                errors_start_actorID[val_line['actorID']+","+val_line['hostname']] = str_timestamp


                # identify terminated objectID
                if val_line['objectID']+","+val_line['hostname'] in actor_ID:
                    if len(actor_ID[val_line['objectID']+","+val_line['hostname']]) >  12 and  val_line['action']=='TERMINATE' and val_line['object']=='PROCESS' :
                            if  (datetime.strptime(actor_ID[val_line['objectID']+","+val_line['hostname']][-1],'%Y-%m-%dT%H:%M:%S.%f%z')) == (datetime.strptime(str_timestamp, '%Y-%m-%dT%H:%M:%S.%f%z') + timedelta(seconds=1)):
                                if val_line['objectID']+","+val_line['hostname'] in errors_counts_objectID:  # if we have already flag this actorID has malicious, increase the number of concerned logs
                                    errors_counts_objectID[val_line['objectID']+","+val_line['hostname']][0] += 1
                                    errors_counts_objectID[val_line['objectID']+","+val_line['hostname']][1].append([str(val_line['pid']),val_line['id'], val_line['action'],val_line['object'],str_timestamp, pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]])
                                else:  # first time we observe the wrong UID, set the number of logs to 1 and create the start time
                                    errors_counts_objectID[val_line['objectID']+","+val_line['hostname']] = [1, [[str(val_line['pid']),val_line['id'], val_line['action'],val_line['object'], str_timestamp, pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]]]]

                                if val_line['actorID']+","+val_line['hostname'] in errors_counts_actorID_of_terminated_objectID:  # if we have already flag this actorID has malicious, increase the number of concerned logs
                                    errors_counts_actorID_of_terminated_objectID[val_line['actorID']+","+val_line['hostname']][ 0] += 1
                                    errors_counts_actorID_of_terminated_objectID[val_line['actorID']+","+val_line['hostname']][1].append([val_line['id'],val_line['action'],val_line['object'],str_timestamp])
                                else:  # first time we observe the wrong UID, set the number of logs to 1 and create the start time
                                    errors_counts_actorID_of_terminated_objectID[val_line['actorID']+","+val_line['hostname']] = [1, [[val_line['id'],val_line['action'],val_line['object'],str_timestamp]]]


                    elif len(actor_ID[val_line['objectID']+","+val_line['hostname']]) >=  12:
                        if date_timestamp > (datetime.strptime(actor_ID[val_line['objectID']+","+val_line['hostname']][-1],'%Y-%m-%dT%H:%M:%S.%f%z')) and val_line['action']!='TERMINATE' and val_line['object']!='PROCESS':
                            if val_line['objectID']+","+val_line['hostname'] in errors_counts_objectID:  # if we have already flag this actorID has malicious, increase the number of concerned logs
                                errors_counts_objectID[val_line['objectID']+","+val_line['hostname']][0] += 1
                                errors_counts_objectID[val_line['objectID']+","+val_line['hostname']][1].append([str(val_line['pid']),val_line['id'], val_line['action'],val_line['object'],str_timestamp, pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]])
                            else:  # first time we observe the wrong UID, set the number of logs to 1 and create the start time
                                errors_counts_objectID[val_line['objectID']+","+val_line['hostname']] = [1, [[str(val_line['pid']),val_line['id'], val_line['action'],val_line['object'], str_timestamp, pid[str(val_line['pid'])+","+val_line['hostname']][-1][0]]]]

                            if val_line['actorID']+","+val_line['hostname'] in errors_counts_actorID_of_terminated_objectID:  # if we have already flag this actorID has malicious, increase the number of concerned logs
                                errors_counts_actorID_of_terminated_objectID[val_line['actorID']+","+val_line['hostname']][ 0] += 1
                                errors_counts_actorID_of_terminated_objectID[val_line['actorID']+","+val_line['hostname']][1].append([val_line['id'],val_line['action'],val_line['object'],str_timestamp])
                            else:  # first time we observe the wrong UID, set the number of logs to 1 and create the start time
                                errors_counts_actorID_of_terminated_objectID[val_line['actorID']+","+val_line['hostname']] = [1, [[val_line['id'],val_line['action'],val_line['object'],str_timestamp]]]


                # check process in thread and task properties

                if (val_line['object'] == 'THREAD') and ('tgt_pid_uuid' in list(val_line['properties'].keys())):
                    if len(actor_ID[val_line['properties']['tgt_pid_uuid']+","+val_line['hostname']]) >= 12 and date_timestamp > (datetime.strptime(actor_ID[val_line['properties']['tgt_pid_uuid']+","+val_line['hostname']][-1], '%Y-%m-%dT%H:%M:%S.%f%z')):
                        if val_line['properties']['tgt_pid_uuid']+","+val_line['hostname'] in error_tgt_pid_uuid:
                            error_tgt_pid_uuid[val_line['properties']['tgt_pid_uuid']+","+val_line['hostname']][0] += 1
                            error_tgt_pid_uuid[val_line['properties']['tgt_pid_uuid']+","+val_line['hostname']][1].append([int(val_line['properties']['tgt_pid']),val_line['id'], val_line['action'],val_line['object'],str_timestamp, pid[str(val_line['properties']['tgt_pid'])+","+val_line['hostname']][-1][0]])

                        else:
                            error_tgt_pid_uuid[val_line['properties']['tgt_pid_uuid']+","+val_line['hostname']] = [1, [[int(val_line['properties']['tgt_pid']),val_line['id'], val_line['action'],val_line['object'],str_timestamp, pid[str(val_line['properties']['tgt_pid'])+","+val_line['hostname']][-1][0]]]]

                if (val_line['object'] == 'TASK') and ('task_process_uuid' in list(val_line['properties'].keys())):
                    if len(actor_ID[val_line['properties']['task_process_uuid']+","+val_line['hostname']]) >= 12 and date_timestamp > (datetime.strptime(actor_ID[val_line['properties']['task_process_uuid']+","+val_line['hostname']][-1],'%Y-%m-%dT%H:%M:%S.%f%z')):
                        if val_line['properties']['task_process_uuid']+","+val_line['hostname'] in error_task_process_uuid:
                            error_task_process_uuid[val_line['properties']['task_process_uuid']+","+val_line['hostname']][0] += 1
                            error_task_process_uuid[val_line['properties']['task_process_uuid']+","+val_line['hostname']][1].append([int(val_line['properties']['task_pid']),val_line['id'], val_line['action'],val_line['object'],str_timestamp, pid[str(val_line['properties']['task_pid'])+","+val_line['hostname']][-1][0]])

                        else:
                            error_task_process_uuid[val_line['properties']['task_process_uuid']+","+val_line['hostname']] = [1, [[int(val_line['properties']['task_pid']), val_line['id'],val_line['action'],val_line['object'],str_timestamp, pid[str(val_line['properties']['task_pid'])+","+val_line['hostname']][-1][0]]]]



                # check object ID thread & user session
                if (val_line['object'] == 'THREAD'):
                    if val_line['action'] in ['CREATE']:
                        thread[val_line['objectID']+","+val_line['hostname']] = [str_timestamp]
                    elif val_line['action'] == 'REMOTE_CREATE':
                        if val_line['objectID']+","+val_line['hostname'] not in thread:
                            thread[val_line['objectID']+","+val_line['hostname']] = [str_timestamp]
                    else:
                        if val_line['objectID']+","+val_line['hostname'] not in thread:
                            thread[val_line['objectID']+","+val_line['hostname']] = [-1, str_timestamp]
                        else:
                            thread[val_line['objectID']+","+val_line['hostname']].append(str_timestamp)

                    if val_line['action'] == 'REMOTE_CREATE' and len(thread[val_line['objectID']+","+val_line['hostname']])==2:
                        if val_line['objectID']+","+val_line['hostname'] not in error_terminated_thread:
                            error_terminated_thread[val_line['objectID']+","+val_line['hostname']] = [1, [str_timestamp]]
                        else:
                            error_terminated_thread[val_line['objectID']+","+val_line['hostname']][0] += 1
                            error_terminated_thread[val_line['objectID']+","+val_line['hostname']][1].append(str_timestamp)

                if (val_line['object'] == 'USER_SESSION'):
                    if val_line['action'] in ['LOGIN']:
                        user_seesion[val_line['objectID']+","+val_line['hostname']] = [str_timestamp]
                    elif val_line['action'] != 'LOGOUT':
                        if val_line['objectID']+","+val_line['hostname'] not in user_seesion:
                            user_seesion[val_line['objectID']+","+val_line['hostname']] = [str_timestamp]
                    else:
                        if val_line['objectID']+","+val_line['hostname'] not in user_seesion:
                            user_seesion[val_line['objectID']+","+val_line['hostname']] = [-1, str_timestamp]
                        else:
                            user_seesion[val_line['objectID']+","+val_line['hostname']].append(str_timestamp)

                    if val_line[ 'action'] not in ['CREATE','DELETE'] and len(user_seesion[val_line['objectID']+","+val_line['hostname']])==2:
                        if val_line['objectID']+","+val_line['hostname'] not in error_terminated_session:
                            error_terminated_session[val_line['objectID']+","+val_line['hostname']] = [1, [str_timestamp]]
                        else:
                            error_terminated_session[val_line['objectID']+","+val_line['hostname']][0] += 1
                            error_terminated_session[val_line['objectID']+","+val_line['hostname']][1].append(str_timestamp)

    outputdir = params.outdir + '{}_SysClient{}/'.format(group, machine)
    if not os.path.isdir(outputdir):
        os.mkdir(outputdir)

    export_json_gzip(outputdir,'actor_ID_',machine,actor_ID)
    export_json_gzip(outputdir,'user_session_',machine,user_seesion)
    export_json_gzip(outputdir,'error_terminated_user_session_',machine,error_terminated_session)
    export_json_gzip(outputdir, 'thread_', machine, thread)
    export_json_gzip(outputdir,'error_terminated_thread_', machine,error_terminated_thread)
    export_json_gzip(outputdir,'error_thread_uuid_', machine,error_tgt_pid_uuid)
    export_json_gzip(outputdir,'error_task_uuid_', machine,error_task_process_uuid)
    export_json_gzip(outputdir,'errors_counts_actorID_',machine, errors_counts_actorID)
    export_json_gzip(outputdir,'several_create_id_', machine, several_create_id)
    export_json_gzip(outputdir,'errors_counts_object_ID_', machine,errors_counts_objectID)
    export_json_gzip(outputdir,'errors_counts_not_created_ID_', machine,errors_count_not_create_ID)
    export_json_gzip(outputdir,'pid_use_',machine,pid)
    export_json_gzip(outputdir,'errors_counts_actorID_of_terminated_objectID_',machine,errors_counts_actorID_of_terminated_objectID)





if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='optc_errors')
    parser.add_argument('--benign_root', default='/optc/ecar_test_correction/benign/', help='Directory to the sorted benign files')
    parser.add_argument('--eval_root', default='/optc/ecar_test_correction/evaluation/', help='Directory to the evaluation files')
    parser.add_argument('--outdir', default='/optc/ecar_test_correction/error_dict/', help='Output directory')
    parser.add_argument('-k', help='Filtering key',type = int, default=1)
    params = parser.parse_args()

    optc_terminate_check(params.benign_root, params.eval_root, params.outdir,params.k)

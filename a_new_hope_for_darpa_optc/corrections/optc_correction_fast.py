from utils_optc_correction import get_iterator, get_data, write_batch
import sys
from collections import namedtuple
import argparse as ap
import glob as gl
import os
import json
from datetime import datetime, timedelta
import sys
import pandas as pd
import time
from explore_error import get_iterator, get_data
import numpy as np
import joblib


def get_args():
    """
        Get command line input arguments
        :return: parser object
        """
    parser = ap.ArgumentParser()
    parser.add_argument("--input", dest="input", action="store", help="path to the folder containing scans")
    parser.add_argument("--output", dest="output", action="store", help="path to the result folder")
    parser.add_argument("--k", dest="machine", action="store", type=int, help="index of machines group")
    return parser.parse_args()

def correction(parser,optc_dict):
    pp = parser.input + optc_dict + '/'
    PATHS = sorted(gl.glob(os.path.join(pp, "*.json.gzip")))  # error count files
    f = sorted(list([[p.split('/')[-2].split('_')[0], p.split('_')[-1].split('.json')[0]] for p in PATHS]))
    f = pd.DataFrame(f, columns=['group', 'machine'])
    f = f.drop_duplicates().sort_values(['machine'])
    machine_group = f.iloc[0]['machine']
    ma = machine_group
    print(machine_group)
    sys.stdout.flush()
    while ma[0] == '0':
        ma = ma[1:]
    ma = int(ma)
    path_machine = sorted( [p for p in PATHS if machine_group in p])  # error count files associated to target machine group
    dict_error = {}
    nb_error = 100
    while nb_error > 0:
        nb_error = 0
        # if dict_error != {} :
        #     iterator_error_actor_ID =
        #     get_iterator('/optc/ecar_test_correction/201_dict_error.json.gz')
        # else :
        #     iterator_error_actor_ID = get_iterator(path_machine[5])  # error count actor ID file of target machine group
        # data = get_data(iterator_error_actor_ID,4932)
        cpt_no = 0
        cpt_3 = 0

        cpt_3_no = 0
        list_corrected = []
        file_path_old = 0
        objectid = get_data(get_iterator(path_machine[8]))
        threadid = get_data(get_iterator(path_machine[4]))
        taskid = get_data(get_iterator(path_machine[1]))
        # date_file = pd.read_csv('/optc/ecar_test_correction/timestamp_file.csv')
        # date_file = date_file[date_file['machine'] == ma]
        # date_file['end'] = pd.to_datetime(date_file['end'], format='%Y-%m-%dT%H:%M:%S.%f%z')
        # date_file = date_file.sort_values(['end'])
        cpt = 0
        # file_machine = pd.read_csv('/optc/ecar_test_correction/list_of_file.csv')
        # file_machine = file_machine[file_machine['machine']==int(machine_group)]
        # file_machine = file_machine.sort_values(['path'])

        timestamp = pd.read_csv('/optc/ecar_test_correction/timestamp_files/timestamp_file_SysClient{}.csv'.format(machine_group))

        for file_path in list(timestamp['path']):
            list_corrected = []
            date_begin = todate(list(timestamp[timestamp['path'] == file_path]['begining'])[0])
            date_end = todate(list(timestamp[timestamp['path'] == file_path]['end'])[0])
            i_event = 0
            i_event_old = 0
            print('reading file : {}'.format(file_path))
            line_content = get_data(get_iterator(file_path))
            line_content = [json.loads(event) if type(event) == str else event for event in line_content]
            iterator_actorID = get_iterator(path_machine[0])
            actor_full = get_data(iterator_actorID)
            iterator_pid = get_iterator(path_machine[9])
            pid_full = get_data(iterator_pid)  # get pid infos
            iterator_error_actor_ID = get_iterator(path_machine[5])
            for batch_error in iterator_error_actor_ID:  # iter over id in default
                cpt += 1

                key_error = list(batch_error.keys())[0]
                if "SysClient" in key_error : #SysClient" in key_error: #"096219d-e9ae-4657-bb0b-26d58c0ac784 REMOTE CREATE THREAD
                    object = [o for o in objectid if list(o.keys())[0] == key_error]
                    thread = [o for o in threadid if list(o.keys())[0] == key_error]
                    task = [o for o in taskid if list(o.keys())[0] == key_error]
                    df_error = pd.DataFrame(batch_error[key_error][1],columns=['pid', 'id', 'action', 'object', 'timestamp', 'last_id'])
                    df_error['type'] = ['actorid'] * len(df_error)
                    if object != []:
                        df_object = pd.DataFrame(object[0][key_error][1], columns=['pid', 'id', 'action', 'object', 'timestamp', 'last_id'])
                        df_object['type'] = ['object'] * len(df_object)
                        df_error = pd.concat([df_object, df_error])
                    if thread != []:
                        df_thread = pd.DataFrame(thread[0][key_error][1], columns=['pid', 'id', 'action', 'object', 'timestamp', 'last_id'])
                        df_thread['type'] = ['thread'] * len(df_thread)
                        df_error = pd.concat([df_thread, df_error])
                    if task != []:
                        df_task = pd.DataFrame(task[0][key_error][1],columns=['pid', 'id', 'action', 'object', 'timestamp', 'last_id'])
                        df_task['type'] = ['task'] * len(df_task)
                        df_error = pd.concat([df_task, df_error])

                    df_error['timestamp'] = pd.to_datetime(df_error['timestamp'], format='%Y-%m-%dT%H:%M:%S.%f%z')
                    df_error = df_error.sort_values(['timestamp'], ascending=True)
                    df_error['timestamp'] = [str(date) for date in df_error['timestamp']]
                    batch_error[key_error][1] = df_error.values.tolist()

                    machine = key_error.split(',')[1]
                    if batch_error[key_error][1][0] not in ['0', '4']:  # check if not pid 0 or 4

                        date = todate(df_error['timestamp'].iloc[0])
                        date_batch_end = todate(df_error['timestamp'].iloc[-1])

                        if (date >= date_begin and date <= date_end) or (date_batch_end >= date_begin and date_batch_end <= date_end):

                            actor = [a for a in actor_full if key_error in a][0]  # extract actorID in default

                            if len(actor[key_error]) == 12:  # check if not 3 timestamps
                                if actor[key_error][1][-1] == ['TERMINATE', 'PROCESS']:

                                    for i_error in range(len(df_error)):
                                        error = list(df_error.iloc[i_error])
                                        if todate(error[4]) >= date_begin and todate(error[4]) <= date_end and todate(error[4]) > todate(actor[key_error][-1]):

                                            sys.stdout.flush()

                                            id_correction = error[5]
                                            print('EVENT : timeline 1 :', key_error, 'id_ corection', id_correction)

                                            actor_correction = [a for a in actor_full if id_correction + ',' + key_error.split(',')[1] in a][0]
                                            key_actor_correction = list(actor_correction.keys())[0]
                                            if actor_correction[key_actor_correction][1][0] == ['CREATE', 'PROCESS']:  # check if the new id has been create correctly

                                                id = error[1]

                                                for i in range(i_event_old, len(line_content)):
                                                    if line_content[i]['id'] == id:
                                                        i_event = i
                                                        break

                                                if i_event==i_event_old :
                                                    for i in range(len(line_content)):
                                                        if line_content[i]['id'] == id:
                                                            i_event = i
                                                            break



                                                event = line_content[i_event]
                                                if error[-1] == "actorid":
                                                    event['actorID'] = id_correction
                                                    event['ppid'] = actor_correction[key_actor_correction][3]
                                                    event['principal'] = actor_correction[key_actor_correction][6]
                                                    if 'image_path' in event['properties']:
                                                        event['properties']['image_path'] = actor_correction[key_actor_correction][4]
                                                    if 'parent_image_path' in event['properties']:
                                                        event['properties']['parent_image_path'] = actor_correction[key_actor_correction][9]
                                                    if 'user' in event['properties']:
                                                        event['properties']['user'] = actor_correction[key_actor_correction][7]
                                                    if 'sid' in event['properties']:
                                                        event['properties']['sid'] = actor_correction[key_actor_correction][8]
                                                    if event['action'] == 'TERMINATE' and event['object'] == 'PROCESS': event['command_line'] = actor_correction[key_actor_correction][5]

                                                    line_content[i_event] = event
                                                    list_corrected.append(
                                                        {'id': id, 'actorID': key_error.split(',')[0], 'host': machine, 'path': file_path, 'timeline': 1})

                                                else :

                                                    if event['object'] == 'THREAD' and ('tgt_pid_uuid' in list(event['properties'].keys())):
                                                        event['properties']['tgt_pid_uuid'] = id_correction
                                                    elif event['object'] == 'TASK' and ('task_process_uuid' in list(event['properties'].keys())):
                                                        event['properties']['task_process_uuid'] = id_correction
                                                    elif error[-1] == "object":
                                                        event['objectID'] = id_correction

                                                        line_content[i_event] = event
                                                        list_corrected.append(
                                                            {'id': id, 'actorID': key_error.split(',')[0], 'host': machine, 'path': file_path, 'timeline': 1})
                                                i_event_old = i_event
                                                # else:
                                                #
                                                #     line_content[i_event] = event
                                                #     list_corrected.append( {'id': id, 'actorID': key_error.split(',')[0], 'host': machine,'path': file_path, 'timeline': 1})

                                            else:
                                                print('EVENT : No create process of id correction', key_error)

                                        else:
                                            # nb_error += 1
                                            break

                                else:
                                    print('No terminate process', key_error)
                                    cpt_no += 1
                                    continue


                            else:  # timeline 2
                                if actor[key_error][1][0] == ['CREATE', 'PROCESS'] and actor[key_error][1][-1] == ['TERMINATE', 'PROCESS'] and len(actor[key_error][1]) == 3:
                                    pid = [p for p in pid_full if str(actor[key_error][0]) + ',' + key_error.split(',')[1] in list(p.keys())][0][str(actor[key_error][0]) + ',' + key_error.split(',')[1]]

                                    error_pid_index = [g for g in range(len(pid)) if pid[g][0] == key_error.split(',Sys')[0]][0]
                                    if len(pid) > error_pid_index + 1:
                                        id_correction = pid[error_pid_index + 1][0]
                                    else:
                                        id_correction = pid[error_pid_index][0]

                                    actor_correction = [a for a in actor_full if id_correction + ',' + machine in a][0]

                                    if len(actor_correction[id_correction + ',' + machine][1]) == 2:
                                        if actor_correction[id_correction + ',' + machine][1][0] != ['CREATE',
                                                                                                     'PROCESS'] and \
                                                actor_correction[id_correction + ',' + machine][1][1] != ['TERMINATE',
                                                                                                          'PROCESS']:
                                            # write_batch(parser.output + machine_group + '.json.gz', list_corrected,True)
                                            sys.stdout.flush()

                                            error_begin = todate(actor[key_error][10])
                                            if error_begin >= date_begin and error_begin <= date_end:  # error must begin in previous file
                                                current_date = error_begin
                                            else:
                                                current_date = date_begin
                                            error_end = todate(actor[key_error][-1])
                                            print('timeline 2 : ', key_error, error_begin, 'id correction',
                                                  id_correction)

                                            error_continu = False
                                            for i in range(len(line_content)):
                                                date_line = todate(line_content[i]['timestamp'])

                                                if date_line == current_date:
                                                    i_event = i
                                                    if error_begin == current_date:
                                                        i_event_old = i
                                                    break

                                            actor_hash = key_error.split(',')[0]

                                            while current_date <= error_end:

                                                event = line_content[i_event]
                                                if event['actorID'] == id_correction:
                                                    event['actorID'] = actor_hash
                                                    list_corrected.append(
                                                        {'id': event['id'], 'actorID': actor_hash, 'host': machine,
                                                         'path': file_path, 'timeline': 2})
                                                if event['objectID'] == id_correction:
                                                    event['objectID'] = actor_hash
                                                    list_corrected.append(
                                                        {'id': event['id'], 'actorID': actor_hash, 'host': machine,
                                                         'path': file_path, 'timeline': 2})
                                                if event['object'] == 'THREAD' and ('tgt_pid_uuid' in list(event['properties'].keys())):
                                                    if event['properties']['tgt_pid_uuid'] == id_correction:
                                                        event['properties']['tgt_pid_uuid'] = actor_hash
                                                        list_corrected.append(
                                                            {'id': event['id'], 'actorID': actor_hash, 'host': machine,
                                                             'path': file_path, 'timeline': 2})
                                                if event['object'] == 'TASK' and ('task_process_uuid' in list(event['properties'].keys())):
                                                    if event['properties']['task_process_uuid'] == id_correction:
                                                        event['properties']['task_process_uuid'] = actor_hash
                                                        list_corrected.append(
                                                            {'id': event['id'], 'actorID': actor_hash, 'host': machine,
                                                             'path': file_path, 'timeline': 2})

                                                line_content[i_event] = event

                                                if i_event + 1 == len(line_content):  # if error continue on next file
                                                    # nb_error += 1
                                                    break
                                                    error_continu = True
                                                else:
                                                    i_event += 1
                                                    current_date = todate(line_content[i_event]['timestamp'])

                                            if error_continu == False:
                                                actor_index = [a for a in range(len(actor_full)) if
                                                               key_error in actor_full[a].keys()][0]
                                                actor_full[actor_index][key_error][1] = [
                                                    actor_full[actor_index][key_error][1][0],
                                                    actor_full[actor_index][key_error][1][2]]
                                                for n in range(len(actor_full[actor_index][key_error]) - 12):
                                                    del actor_full[actor_index][key_error][-2]



                                        else:
                                            cpt_3_no += 1
                                            print('id correction not well created/terminated', key_error)
                                    else:
                                        print('id correction with more than 2 life event', key_error)
                                else:
                                    print('actor ID not well crated/terminated', key_error)
                                    cpt_no += 1

                        # else :
                        #     #nb_error +=1

                    else:
                        print('pid 0 or 4', key_error)

                else:
                    cpt_no += 1
                    continue

            print('cpt :', cpt)
            print('cpt_no : ', cpt_no)
            print('cpt_3 : ', cpt_3)
            print('cpt_3_no : ', cpt_3_no)
            #t = time.time() - t0
            # sys.stdout.flush()

            print('end of file {}'.format(file_path))
            write_batch(path_machine[0], actor_full, False)
            write_batch(parser.output + machine_group + '_first_correction.json.gz', list_corrected, True)
            if os.path.isfile(file_path):
                os.system('rm {}'.format(file_path))
            write_batch(file_path, line_content)


def todate(string_date):
    if 'T' in string_date:
        try:
            date = datetime.strptime(string_date, '%Y-%m-%dT%H:%M:%S.%f%z')
        except:
            date = datetime.strptime(string_date, '%Y-%m-%dT%H:%M:%S%z')
            date = date + timedelta(milliseconds=00000)
    else:
        try:
            date = datetime.strptime(string_date, '%Y-%m-%d %H:%M:%S.%f%z')
        except:
            date = datetime.strptime(string_date, '%Y-%m-%d %H:%M:%S%z')
            date = date + timedelta(milliseconds=00000)
    return date

def main():
    if len(sys.argv) > 1:
        # we have argument -> outside pycharm editor
        parser = get_args()

    else:
        Params = namedtuple("Params", ["input", "output", 'machine'])
        parser = Params('/optc/ecar_test_correction/error_dict/',
                        '/optc/ecar_test_correction/correction/', 256)

    t0 = time.time()
    optc_dict = sorted(os.listdir(parser.input))


    # for i in range(50):
    #     pp = parser.input + optc_dict[i] + '/'
    #     PATHS = sorted(gl.glob(os.path.join(pp, "*.json.gzip")))
    #     f = sorted(list([[p.split('/')[-2].split('_')[0], p.split('_')[-1].split('.json')[0]] for p in PATHS]))
    #     f = pd.DataFrame(f, columns=['group', 'machine'])
    #     f = f.drop_duplicates().sort_values(['machine'])
    #     machine_group = f.iloc[0]['machine']
    #     ma = machine_group
    #     path_machine = sorted([p for p in PATHS if machine_group in p])
    #
    #     iterator_actorID = get_iterator(path_machine[0])
    #     actor_full = get_data(iterator_actorID)
    #
    #     iterator_error_actor_ID = get_iterator(path_machine[5])
    #     for batch_error in iterator_error_actor_ID:
    #         key_error = list(batch_error.keys())[0]
    #         try :
    #             actor = [a for a in actor_full if key_error in a][0]
    #         except :
    #             print(key_error)
    #     print('ok')

    #correction(parser, optc_dict[9])

    for i in range(len(optc_dict)):
        correction(parser, optc_dict[i])
    # delayed = (joblib.delayed(correction)(parser,optc_dict[i]) for i in range(50,100))
    # joblib.Parallel(n_jobs=50)(delayed)

    #optc_dict = optc_dict[parser.machine - 1]





if __name__ == "__main__":
    main()

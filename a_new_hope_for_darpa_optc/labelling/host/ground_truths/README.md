# Ground truth for host data of Darpa OpTC

This directory contains the labels for the host data of DARPA OpTC and the
ground truth files that are used in input of the host_darpapy.py script.

When the file name contains "corrected", it means that the file is linked to the
corrected version of the dataset. Otherwise, it means that the file is linked to
the original version of the dataset.

The csv files named ground_truth_sc?.csv and ground_truth_corrected_sc?.csv are
the input files of the host_darpapy.py. The csv files named
ground_truth_sc?_new.csv and ground_truth_corrected_sc?_new.csv are the updated
version of the previous files after running host_darpapy.py to add all the
children of the malicious processes.

The files with the string "evts" in their name contains the events linked to the
malicious processes for each scenario, each host and each version of the
dataset. For example, the file ground_truth_sc2_evts_sysclient0010.json.gz
contains the events that we label as malicious for the second attack scenario,
the host 0010 and the original version of the dataset.

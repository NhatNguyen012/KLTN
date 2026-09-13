# Host labelling of Darpa OpTC

This directory contains the code and the labels of the host data of DARPA OpTC.

The labels are in the ground_truths directory. We provide the labels for the
original version of the dataset and the corrected one. The ground truth files
are also in this directory: they are used as inputs for the script described
below.

The host_darpapy.py script is the main script to label the data. It uses in
input a ground truth file describing which pid is malicious on each host, and
the timestamps of the malicious activity (for each pid and host).

The script can be used for two different tasks. First, it can update the ground
truth file in input by following the creations of processes by the malicious
processes given in input. Secondly, it can output the events associated with a
ground truth file.

The complete_gt_*.sh scripts are used to update the ground truth files for each
scenario and each version of the dataset.

The generate_gt*.sh are used to output the events linked to the malicious
activities for each scenario and each version of the dataset.

# Corrections of the host data of Darpa OpTC

This directory contains the scripts used to fix the errors linked to a mixing of
some unique identifiers in the host data of DARPA OpTC.

The error_optc_json.py script outputs dictionnaries linked to the mixing of the
identifiers. These dictionnaries are used in input of the
optc_correction_fast.py script that fixes the errors.

The error_optc_json.py script takes also in input csv files that describe which
json files should be analyzed and the lower and upper limits on the timestamps
of the events in the json files. The file timestamp_files/timestamp_file_SysClient0163.csv gives an example of this kind of file.

The json files should be sorted by timestamps before running the scripts. It
must be noted that it is not the case of the original files of the DARPA OpTC dataset. You should also split the events by host beforehand.

aia_group () {
  COMP=$1
  let FIRST=($COMP/25)*25+1
  let LAST=$FIRST+24
  echo "AIA-${FIRST}-${LAST}"
}

DATA_PATH="TO_DEFINE"

# Scenario 1
SC="sc1"
DAY_SC="2019-09-23"
LIST_COMP_SC="201 402 660 104 205 321 255 355 503 462 559 419 609 771 955 874 170"
MARGINS=90

GT_FILE_UPDATED="./ground_truths/ground_truth_corrected_${SC}_updated.csv"
GT_EVTS_TMPL="./ground_truths/ground_truth_corrected_${SC}_evts"

for COMPUTER in $LIST_COMP_SC ; do
  GROUP=$(aia_group "$COMPUTER")
  N_COMPUTER=`printf %04d $COMPUTER`
  echo "$COMPUTER"
  python host_darpapy.py -m $MARGINS -d "$GT_FILE_UPDATED" -f ${DATA_PATH}/${DAY_SC}/${GROUP}/${GROUP}.ecar-${DAY_SC}-sysclient${N_COMPUTER}.json.gz -e > "$GT_EVTS_TMPL"_sysclient${N_COMPUTER}.json
done


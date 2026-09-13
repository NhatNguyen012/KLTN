aia_group () {
  COMP=$1
  let FIRST=($COMP/25)*25+1
  let LAST=$FIRST+24
  echo "AIA-${FIRST}-${LAST}"
}

DATA_PATH="TO_DEFINE"

# Scenario 2
SC="sc2"
DAY_SC="2019-09-24"
LIST_COMP_SC="501 811 10 69 203 358 618 851 5 974"
MARGINS=90

GT_FILE_UPDATED="./ground_truths/ground_truth_${SC}_updated.csv"
GT_EVTS_TMPL="./ground_truths/ground_truth_${SC}_evts"

for COMPUTER in $LIST_COMP_SC ; do
  GROUP=$(aia_group "$COMPUTER")
  N_COMPUTER=`printf %04d $COMPUTER`
  echo "$COMPUTER"
  python host_darpapy.py -m $MARGINS -d "$GT_FILE_UPDATED" -f ${DATA_PATH}/${DAY_SC}/${GROUP}/${GROUP}.ecar-${DAY_SC}-sysclient${N_COMPUTER}.json.gz -e > "$GT_EVTS_TMPL"_sysclient${N_COMPUTER}.json
done

DAY_SC="2019-09-25"

for COMPUTER in $LIST_COMP_SC ; do
  GROUP=$(aia_group "$COMPUTER")
  N_COMPUTER=`printf %04d $COMPUTER`
  echo "$COMPUTER"
  python host_darpapy.py -m $MARGINS -d "$GT_FILE_UPDATED" -f ${DATA_PATH}/${DAY_SC}/${GROUP}/${GROUP}.ecar-${DAY_SC}-sysclient${N_COMPUTER}.json.gz -e >> "$GT_EVTS_TMPL"_sysclient${N_COMPUTER}.json
done

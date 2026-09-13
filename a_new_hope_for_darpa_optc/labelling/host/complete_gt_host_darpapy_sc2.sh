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

GT_FILE_ORIG="./ground_truths/ground_truth_${SC}.csv"
GT_FILE_SRC="./ground_truths/ground_truth_${SC}_new.csv"
GT_FILE_UPDATED="./ground_truths/ground_truth_${SC}_updated.csv"

cp "$GT_FILE_ORIG" "$GT_FILE_SRC"

for COMPUTER in $LIST_COMP_SC ; do
  i=1
  GROUP=$(aia_group "$COMPUTER")
  N_COMPUTER=`printf %04d $COMPUTER`
  while true ; do
    echo "$COMPUTER"
    echo "pass: " "$i"
    python host_darpapy.py -m $MARGINS -d "$GT_FILE_SRC" -f ${DATA_PATH}/${DAY_SC}/${GROUP}/${GROUP}.ecar-${DAY_SC}-sysclient${N_COMPUTER}.json.gz -p -s --no-print-malicious-events > "$GT_FILE_UPDATED"
    let i=$i+1
    diff -q "$GT_FILE_SRC" "$GT_FILE_UPDATED"
    if [[ $? == 0 ]] ; then
      break;
    else
      cp "$GT_FILE_UPDATED" "$GT_FILE_SRC"
    fi
  done
done

DAY_SC="2019-09-25"

for COMPUTER in $LIST_COMP_SC ; do
  i=1
  GROUP=$(aia_group "$COMPUTER")
  N_COMPUTER=`printf %04d $COMPUTER`
  while true ; do
    echo "$COMPUTER"
    echo "pass: " "$i"
    python host_darpapy.py -m $MARGINS -d "$GT_FILE_SRC" -f ${DATA_PATH}/${DAY_SC}/${GROUP}/${GROUP}.ecar-${DAY_SC}-sysclient${N_COMPUTER}.json.gz -p -s --no-print-malicious-events > "$GT_FILE_UPDATED"
    let i=$i+1
    diff -q "$GT_FILE_SRC" "$GT_FILE_UPDATED"
    if [[ $? == 0 ]] ; then
      break;
    else
      cp "$GT_FILE_UPDATED" "$GT_FILE_SRC"
    fi
  done
done

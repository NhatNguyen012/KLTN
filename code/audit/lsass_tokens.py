import json

v4_path = '/mnt/SSD_Data/optc/code/output/host_ml_seed02/kaggle_ouput/xgb_kaggle_results/results/diagnostics/test_errors.json'
v4_vocab = json.load(open('/mnt/SSD_Data/optc/code/output/host_ml_seed02/vocab.json'))
v4_rev_vocab = {int(v): k for k, v in v4_vocab.items()}

data = json.load(open(v4_path))
for ex in data['examples']:
    if ex['label'] == 0 and ex['score'] >= 0.5:
        tokens = [v4_rev_vocab[idx] for idx in ex['columns']]
        image = next((t.split('=')[1] for t in tokens if t.startswith('image_path::basename=')), 'unknown')
        if image == 'lsass.exe':
            print("LSASS FP Tokens:")
            for t in tokens:
                print("  " + t)
            break

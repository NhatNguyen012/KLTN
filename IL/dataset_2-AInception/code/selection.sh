# Regex chọn file cho tải từng phần (remote_zip.py get --grep)
SL300_RX='^variant[0-9]+/(readme\.md|attack_log/[^/]+|cyber_terrain/.+|simulated_user_log/.+|logs/(benign_days|attack_day)/(?!suricata|mail\.)[^/]+\.ecslogs|labelled_logs/bnhq[0-9]+/attack/(?!suricata|mail\.)[^/]+\.ecslogs)$'
SL700_RX='(/audit/audit\.log[^/]*$|/gather/attacker/logs/[^/]+$|/gather/[^/]+/facts\.json$|^run_[a-z]_[a-z]/(readme\.md|SL700_infra\.json)$|/gather/(videoserver|corpdns|inetfw|webcam)/logs/log/(auth\.log|syslog)[^/]*$)'

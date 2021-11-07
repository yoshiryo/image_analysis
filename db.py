import glob
from os import replace
import MySQLdb
 
# データベースへの接続とカーソルの生成
connection = MySQLdb.connect(
    host='localhost',
    user='ueoai',
    passwd='ueoai0622',
    db='analysys',
# テーブル内部で日本語を扱うために追加
)
cursor = connection.cursor()

matchPath = glob.glob('/home/ueoai/ubuntu-cve-tracker/active/CVE-*', recursive=True)
#matchPath = glob.glob('/home/ueoai/ubuntu-cve-tracker/active/CVE-*', recursive=True)
matchPath.sort()
id = 1
for pth in matchPath:
    with open(pth) as f:
        lines = f.readlines()
    lines_strip = [line.strip() for line in lines]
    cve_score = "None"
    name_list = []
    for line in lines_strip:
        if 'Candidate:' in line:
            cve_id = line
            cve_id = cve_id.replace("Candidate:", "")
            cve_id = cve_id.replace(" ", "")
        elif 'Priority:' in line:
            priority = line
            priority = priority.replace("Priority:", "")
            priority = priority.replace(" ", "")
        elif 'Patches_' in line:
            name = line
            name = name.replace("Patches_", "")
            name = name.replace(":", "")
            name = name.replace(" ", "")
            name_list.append(name)
        elif 'nvd:' in line:
            cve_score = line
            cve_score = cve_score.replace("nvd: ", "")
            cve_score = cve_score.replace(" ", "")
        else:
            pass
    for n in name_list:
        cursor.execute(f"""INSERT INTO image (id, cve_id, name, cve_score, priority) VALUES ({id}, '{cve_id}', '{n}', '{cve_score}', '{priority}')""")
        id += 1
cursor.close()
connection.commit()
connection.close()

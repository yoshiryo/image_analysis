import glob
from os import replace
from re import T
import MySQLdb
 
# データベースへの接続とカーソルの生成
connection = MySQLdb.connect(
    host='localhost',
    user='',
    passwd='',
    db='analysys',
# テーブル内部で日本語を扱うために追加
)
cursor = connection.cursor()

matchPath = glob.glob('/home/ueoai/ubuntu-cve-tracker/active/CVE-*', recursive=True)
matchPath.sort()
id = 1
for pth in matchPath:
    with open(pth) as f:
        lines = f.readlines()
    lines_strip = [line.strip() for line in lines]
    cve_score = "None"
    name_list = []
    os_ver_list = []
    status_list = []
    p = False
    name_num = 0
    for line in lines_strip:
        if p:
            if len(line) == 0:
                os_ver_list.append(os_l)
                status_list.append(status_l)
                p = False
            else:
                line_split = line.split(":")
                replace_word = "_" + name
                os_ver = line_split[0].replace(replace_word, "")
                status = line_split[1].lstrip().replace("doesn't", "does not")
                os_l.append(os_ver)
                status_l.append(status)
        elif 'Candidate:' in line:
            cve_id = line
            cve_id = cve_id.replace("Candidate:", "")
            cve_id = cve_id.replace(" ", "")
        elif 'Priority:' in line:
            priority = line
            priority = priority.replace("Priority:", "")
            priority = priority.replace(" ", "")
        elif 'nvd:' in line:
            cve_score = line
            cve_score = cve_score.replace("nvd: ", "")
            cve_score = cve_score.replace(" ", "")
        elif 'Patches_' in line:
            name = line
            name = name.replace("Patches_", "")
            name = name.replace(":", "")
            name = name.replace(" ", "")
            name_list.append(name)
            p = True
            os_l = []
            status_l = []
        else:
            pass
    os_ver_list.append(os_l)
    status_list.append(status_l)
    for i in range (len(name_list)):
        for j in range(len(os_ver_list[i])):
            cursor.execute(f"""INSERT INTO image (id, cve_id, name, cve_score, priority, os_version, status) 
                               VALUES ({id}, '{cve_id}', '{name_list[i]}', '{cve_score}', '{priority}', '{os_ver_list[i][j]}', '{status_list[i][j]}')""")
            id += 1
cursor.close()
connection.commit()
connection.close()

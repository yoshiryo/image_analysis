import glob
from os import replace
import MySQLdb
import re
import glob
import tarfile
from collections import Counter
def read_image():
    matchPath = glob.glob('/home/ueoai/image_analysys/image/mysql/**/layer.tar', recursive=True) #mysqlの部分を変えると好きな.tarが取得できる
    matchPath.sort()
    package_path = "/home/ueoai/image_analysys/output/package.txt"
    with open(package_path, mode='w') as f:
        f.write(" ")
    for mpth in matchPath:
        with tarfile.open(mpth, 'r') as tarf:
            # アーカイブに含まれるファイルの目録
            members = tarf.getmembers()
            for member in members:
                if member.name == "var/lib/dpkg/status":
                    # アーカイブに含まれる各ファイルを開く
                    fp = tarf.extractfile(member)
                    # 各ファイルの内容を読み込む
                    body = fp.read()
                    with open(package_path, mode='ab') as f:
                        f.write(body)

def write_package():
    package_path = "/home/ueoai/image_analysys/output/package.txt" #imageから取得したパッケージ情報
    output_path = "/home/ueoai/image_analysys/output/output.txt" #最終的な出力結果
    with open(package_path) as f:
        lines = f.readlines()
    lines_strip = [line.strip() for line in lines]
    #l_XXX = [line for line in lines_strip if 'Package' in line]
    l_XXX = []
    l = []
    for line in lines_strip:
        if 'Package' in line:
            l.append(line)
            cnt = 0
        #if 'Source' in line:
            #l.append(line)
        if 'Version' in line:
            l.append(line)
            cnt = 1
        if cnt == 1:
            l_XXX.append(l)
            l = []

    arr = list(map(list, set(map(tuple, l_XXX))))
    num = 40
    with open(output_path, mode='w') as f:
        for ans in arr:
            if len(ans) == 2 or len(ans) == 3:
                print(ans[1])
                target1 = "Version: "
                target2 = ":"
                target3 = "-"
                target4 = "+"
                target5 = "ubuntu"
                idx = ans[1].find(target1)
                if idx != -1:
                    r = ans[1][idx+len(target1):]

                idx = r.find(target2)
                if idx != -1:
                    r = r[idx+len(target2):]

                idx = r.find(target3)
                if idx != -1:
                    r = r[:idx+len(target3)-1]

                idx = r.find(target4)
                if idx != -1:
                    r = r[:idx+len(target4)-1]

                idx = r.find(target5)
                if idx != -1:
                    r = r[:idx]
                if len(ans) == "3":
                    s = ans[2] + " "*(num - len(ans[2])) + "Version: " + r + "\n"
                else:
                    s = ans[0] + " "*(num - len(ans[0])) + "Version: " + r + "\n"
                f.write(s)
            else:
                continue

def read_cve():
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
    matchPath.sort()
    id = 1
    for pth in matchPath:
        with open(pth) as f:
            lines = f.readlines()
        lines_strip = [line.strip() for line in lines]
        cve_score = "None"
        name_list = []
        p = False
        txt = ""
        for line in lines_strip:
            """
            if p:
                if 'Ubuntu-Description:' in line:
                    p = False
                    ans = re.findall('\d+(?:\.\d+)+', txt)
                    txt = ""
                else:
                    txt += line
            else:
                """
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

            #if 'Description:' in line:
            #    p = True
        for n in name_list:  
            cursor.execute(f"""INSERT INTO image (id, cve_id, name, cve_score, priority) VALUES ({id}, '{cve_id}', '{n}', '{cve_score}', '{priority}')""")
            id += 1
    cursor.close()
    connection.commit()
    connection.close()

def read_cve_version():
    matchPath = glob.glob('/home/ueoai/ubuntu-cve-tracker/active/CVE-*', recursive=True)
    matchPath.sort()
    ver_list = []
    for pth in matchPath:
        with open(pth) as f:
            lines = f.readlines()
        lines_strip = [line.strip() for line in lines]
        p = False
        txt = ""
        for line in lines_strip:
            if p:
                if 'Ubuntu-Description:' in line:
                    p = False
                    ver = list(set(re.findall('\d+(?:\.\d+)+', txt)))
                    ver_list.append(ver)
                    txt = ""
                else:
                    txt += line
            if 'Description:' in line:
                p = True
    id = 0
    w = []
    for pth in matchPath:
        with open(pth) as f:
            lines = f.readlines()
        lines_strip = [line.strip() for line in lines]
        p = False
        txt = ""
        for line in lines_strip:
            if p:
                if 'Ubuntu-Description:' in line:
                    p = False
                    l = txt.split(" ")
                    for i in range(len(l)):
                        if l[i] in ver_list[id]:
                            if l[i-1] == "CVSS":
                                print(cve_id)
                            w.append(l[i-1])
                    id += 1
                    txt = ""
                else:
                    txt += line
            if 'Description:' in line:
                p = True
            if 'Candidate:' in line:
                cve_id = line
    #print(Counter(w))
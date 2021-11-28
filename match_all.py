from collections import Counter
from os import replace
from re import T
import MySQLdb
import glob
 
# データベースへの接続とカーソルの生成
connection = MySQLdb.connect(
    host='localhost',
    user='ueoai',
    passwd='ueoai0622',
    db='analysys',
# テーブル内部で日本語を扱うために追加
)
cursor = connection.cursor()
matchPath = glob.glob("/home/ueoai/image_analysys/output/*.txt", recursive=True)

for mpth in matchPath:
    with open(mpth) as f:
            lines = f.readlines()
    lines_strip = [line.strip() for line in lines]

    cnt = []
    for line in lines_strip:
        pac = line.split(" ")[1].split("-")[0]
        #pac = line.split(" ")[1]
        cursor.execute(f"""select priority from image where name like '{pac}' and status = 'needed' and os_version = 'focal';""") #ubuntu20
        #cursor.execute(f"""select priority from image where name like '{pac}' and status = 'needed' and os_version = 'bionic';""") #ubuntu18
        p = cursor.fetchall()
        for i in p:
            cnt.append(i)
    c = Counter(cnt)
    print(mpth, c)
cursor.close()
connection.close()
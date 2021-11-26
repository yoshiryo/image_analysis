from collections import Counter
from os import replace
from re import T
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

path = "/home/ueoai/image_analysys/output/output.txt"
with open(path) as f:
        lines = f.readlines()
lines_strip = [line.strip() for line in lines]

cnt = []
for line in lines_strip:
    pac = line.split(" ")[1].split("-")[0]
    cursor.execute(f"""select priority from image where name like '%{pac}%' and os_version = 'upstream' and status = 'needed';""")
    p = cursor.fetchall()
    for i in p:
        cnt.append(i)
c = Counter(cnt)
print(c)
cursor.close()
connection.close()
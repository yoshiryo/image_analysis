test = "Version: 10.1ubuntu2.10"


target1 = "Version: "
target2 = ":"
target3 = "-"
target4 = "+"
target5 = "ubuntu"
idx = test.find(target1)
if idx != -1:
    r = test[idx+len(target1):]

idx = r.find(target2)
if idx != -1:
    r = r[idx+len(target2):]

idx = r.find(target3)
if idx != -1:
    r = r[:idx+len(target3)-1]

idx = r.find(target4)
if idx != -1:
    r = r[:idx+len(target4)-1]
print(r)
idx = r.find(target5)
if idx != -1:
    r = r[:idx]
print(r)
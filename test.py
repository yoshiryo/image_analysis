txt = "An issue was discovered in MediaWiki through 1.36.2. A parser functionrelated to loop control allowed for an infinite loop (and php-fpm hang)within the Loops extension because egLoopsCountLimit is mishandled. Thiscould lead to memory exhaustion."
ver_list = ["1.36.2"]
l = txt.split(" ")
for i in range(len(l)):
    if l[i].startswith:
        if l[i-1] == "through":
            print("ok")
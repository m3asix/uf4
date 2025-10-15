# 🐍 uf4. programació per a l'administració de sistemes
Llibreries de Python per a l'Administració de Sistemes.

Aquest document presenta un resum de les **principals llibreries de Python** utilitzades per a tasques d’**administració de sistemes** (sysadmin), amb exemples pràctics i enllaços de referència.

> 📌 Aquest recurs és un resum pràctics per a estudiants de 2n ASIX cursant la UF4 del mòdul M03: programació bàsica, a l'institut Montsià fins al curs 24-25.

---

## 📁 1. `os`, `shutil` i `pathlib` — Gestió del sistema de fitxers

Aquestes llibreries formen part de la **biblioteca estàndard** de Python i permeten interactuar amb directoris, arxius i rutes.

### Exemples

```python
import os
from pathlib import Path
import shutil

# Crear un directori
os.makedirs("proves/directori_nou", exist_ok=True)

# Llistar arxius
for fitxer in os.listdir("."):
    print(fitxer)

# Copiar un fitxer
shutil.copy("fitxer.txt", "copia_fitxer.txt")

# Treballar amb rutes de forma elegant
ruta = Path("proves/directori_nou/fitxer.txt")
print(ruta.parent)     # mostra el directori pare
print(ruta.name)       # mostra el nom del fitxer
```

### 📚 Referències
- [Documentació oficial d'`os`](https://docs.python.org/3/library/os.html)  
- [Documentació oficial de `shutil`](https://docs.python.org/3/library/shutil.html)  
- [Documentació oficial de `pathlib`](https://docs.python.org/3/library/pathlib.html)

---

## 🖥️ 2. `subprocess` — Execució de comandes del sistema

Permet executar **ordres de terminal** des de Python i capturar-ne la sortida.

### Exemple

```python
import subprocess

resultat = subprocess.run(["ls", "-l"], capture_output=True, text=True)
print("Sortida:")
print(resultat.stdout)
```

> ⚠️ Funciona tant en sistemes Unix com en Windows (canviant les comandes).

### 📚 Referències
- [Documentació oficial de `subprocess`](https://docs.python.org/3/library/subprocess.html)

---

## 🧠 3. `psutil` — Monitoratge de recursos i processos

La llibreria [`psutil`](https://pypi.org/project/psutil/) permet obtenir informació sobre **CPU, memòria, processos i discos**, molt útil per scripts de monitoratge.

### Instal·lació
```bash
pip install psutil
```

### Exemple

```python
import psutil

print("CPU %:", psutil.cpu_percent(interval=1))
print("Memòria lliure:", psutil.virtual_memory().available)
print("Processos actius:")
for proc in psutil.process_iter(['pid', 'name']):
    print(proc.info)
```

### 📚 Referències
- [psutil — PyPI](https://pypi.org/project/psutil/)  
- [Documentació oficial](https://psutil.readthedocs.io/)

---

## 🌐 4. `socket` — Xarxes i connexions

Aquesta llibreria permet crear **sockets de xarxa** i treballar amb protocols com TCP/IP.

### Exemple

```python
import socket

host = "example.com"
ip = socket.gethostbyname(host)
print(f"L'adreça IP de {host} és {ip}")
```

### 📚 Referències
- [Documentació oficial de `socket`](https://docs.python.org/3/library/socket.html)

---

## 🔐 5. `paramiko` — SSH amb Python

[`paramiko`](https://www.paramiko.org/) permet **connectar-se per SSH** a servidors i executar-hi comandes.

### Instal·lació
```bash
pip install paramiko
```

### Exemple

```python
import paramiko

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect("server.exemple.cat", username="usuari", password="contrasenya")

stdin, stdout, stderr = client.exec_command("uname -a")
print(stdout.read().decode())

client.close()
```

### 📚 Referències
- [Paramiko — lloc oficial](https://www.paramiko.org/)  
- [Paramiko — GitHub](https://github.com/paramiko/paramiko)

---

## 🤖 6. `fabric` — Automatització remota via SSH

[`fabric`](https://www.fabfile.org/) simplifica tasques d’administració remota (per exemple desplegaments o manteniments en diversos servidors).

### Instal·lació
```bash
pip install fabric
```

### Exemple

```python
from fabric import Connection

conn = Connection("usuari@server.exemple.cat")
conn.run("uptime")
conn.put("script.py", "/tmp/script.py")
conn.run("python3 /tmp/script.py")
```

### 📚 Referències
- [Fabric — lloc oficial](https://www.fabfile.org/)  
- [Documentació de Fabric](https://docs.fabfile.org/)

---

## ⚙️ 7. `ansible` (API de Python)

Ansible és una eina d’orquestració molt potent que també pot ser utilitzada des de Python.

> 🧰 Normalment es fa servir la **línia d’ordres**, però també disposa d’una **API Python** per a integracions avançades.

### Exemple bàsic (executar un *playbook*)

```python
from ansible_runner import run

r = run(private_data_dir="/ruta/al/projecte", playbook="playbook.yml")
print(f"Estat: {r.status}")
print(f"Retorn: {r.rc}")
```

### 📚 Referències
- [Ansible — documentació oficial](https://docs.ansible.com/)  
- [Ansible Runner — GitHub](https://github.com/ansible/ansible-runner)

---

## 🪟 8. `pywinrm` — Administració remota de Windows

[`pywinrm`](https://pypi.org/project/pywinrm/) permet connectar-se a **equips Windows** mitjançant WinRM i executar-hi comandes.

### Instal·lació
```bash
pip install pywinrm
```

### Exemple

```python
import winrm

sessio = winrm.Session('windows-server.exemple.cat', auth=('usuari', 'contrasenya'))
resultat = sessio.run_cmd('ipconfig', ['/all'])
print(resultat.std_out.decode())
```

### 📚 Referències
- [pywinrm — PyPI](https://pypi.org/project/pywinrm/)  
- [pywinrm — GitHub](https://github.com/diyan/pywinrm)

---



---

## 🧪 9. `pyshark` — Anàlisi de trànsit de xarxa

[`pyshark`](https://pypi.org/project/pyshark/) és una interfície en Python per a Wireshark/TShark que permet **capturar i analitzar trànsit de xarxa** de manera programàtica.  
És molt útil per a tasques de seguretat, monitoratge i diagnosi de xarxes.

### Instal·lació
```bash
pip install pyshark
# Cal tenir tshark instal·lat al sistema (part de Wireshark)
```

### Exemple

```python
import pyshark

# Captura en temps real de la interfície 'eth0'
captura = pyshark.LiveCapture(interface='eth0')

for paquet in captura.sniff_continuously(packet_count=5):
    print(f"Paquet: {paquet.highest_layer} - {paquet}")
```

També pots llegir captures ja desades en fitxers `.pcap`:

```python
import pyshark

captura = pyshark.FileCapture('exemple.pcap')

for paquet in captura:
    print(paquet)
```

> 💡 Pyshark permet filtrar protocols (TCP, HTTP, DNS, etc.), extreure camps específics i analitzar trànsit sense haver de treballar directament amb Wireshark.

### 📚 Referències
- [Pyshark — PyPI](https://pypi.org/project/pyshark/)  
- [Pyshark — GitHub](https://github.com/KimiNewt/pyshark)  
- [TShark (Wireshark CLI)](https://www.wireshark.org/docs/man-pages/tshark.html)


## 🧰 Altres llibreries útils

- `logging` — per generar logs d’execució  
- `schedule` — per programar tasques repetitives  
- `requests` — per interactuar amb APIs REST

---

## 📝 Recursos addicionals en català

- [Material IOC sobre Python bàsic](https://ioc.xtec.cat/materials/FP/Recursos/fp_asx_m03_/web/fp_asx_m03_htmlindex/WebContent/u1/a1/continguts.html)  
- [Documentació Python (oficial, anglès)](https://docs.python.org/3/)  

---

## 📄 Llicència

Aquest recurs està publicat sota llicència [Creative Commons BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/deed.ca). Pots modificar-lo i reutilitzar-lo lliurement sempre que en reconeguis l’autoria.

---

## 🧑 Autor

Aquest document ha estat creat com a **material educatiu introductori** per a tasques d’administració de sistemes amb Python.  
Si tens suggeriments o millores, pots obrir un *issue* o una *pull request* al repositori de GitHub corresponent.


---

# 🧪 Exercicis pràctics amb solucions

A continuació trobaràs **un exercici per a cada llibreria** i la **solució comentada**. Els exercicis estan pensats per ser curts i enfocats a problemes reals de sysadmin.

## 1) `os`, `shutil`, `pathlib`
**Enunciat.** Escriu un script que:
1) cerqui recursivament tots els fitxers `.log` sota un directori,  
2) mogui els que tinguin més de 10 MB a `./logs_grans/` preservant l'estructura de subcarpetes.

**Solució**
```python
import os
from pathlib import Path
import shutil

origen = Path(".")
destinacio = Path("./logs_grans")

for p in origen.rglob("*.log"):
    if p.is_file() and p.stat().st_size > 10 * 1024 * 1024:
        rel = p.parent.relative_to(origen)
        dest_dir = destinacio / rel
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(p), str(dest_dir / p.name))
        print(f"Mogut: {p} -> {dest_dir / p.name}")
```

**Explicació.** `rglob` cerca recursivament; `stat().st_size` dona la mida; creem directoris amb `mkdir(..., parents=True)` i fem `move` amb `shutil` preservant l’estructura.

---

## 2) `subprocess`
**Enunciat.** Fes un script que executi `df -h` (o `Get-PSDrive -PSProvider FileSystem` a Windows) i gravi la sortida a `discos.txt`. Si la comanda falla, mostra l’error.

**Solució**
```python
import subprocess
import sys

cmd = ["df", "-h"] if sys.platform != "win32" else ["powershell", "-Command", "Get-PSDrive -PSProvider FileSystem"]
res = subprocess.run(cmd, capture_output=True, text=True)
if res.returncode == 0:
    with open("discos.txt", "w", encoding="utf-8") as f:
        f.write(res.stdout)
    print("OK: discos.txt creat")
else:
    print("Error execució:", res.stderr)
```

**Explicació.** `subprocess.run` retorna `returncode`. En cas d’èxit, escrivim `stdout` al fitxer; si no, informem amb `stderr`.

---

## 3) `psutil`
**Enunciat.** Llista els **5 processos** que més memòria resident (RSS) estiguin consumint ara mateix.

**Solució**
```python
import psutil

procs = []
for p in psutil.process_iter(["pid", "name", "memory_info"]):
    try:
        rss = p.info["memory_info"].rss if p.info["memory_info"] else 0
        procs.append((rss, p.info["pid"], p.info["name"]))
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

top5 = sorted(procs, reverse=True)[:5]
for rss, pid, name in top5:
    print(f"{pid:6d} {rss/1024/1024:8.1f} MiB  {name}")
```

**Explicació.** Recorrem processos amb camps seleccionats; ordenem per RSS i mostrem els 5 primers, gestionant processos que desapareixen o denegacions d’accés.

---

## 4) `socket`
**Enunciat.** Resol el nom DNS d’una llista d’hostnames i guarda un CSV amb `hostname,ip`. Ignora hostnames que no es puguin resoldre.

**Solució**
```python
import socket
import csv

hosts = ["example.com", "python.org", "noexisteix.local"]
with open("resolucions.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["hostname", "ip"])
    for h in hosts:
        try:
            ip = socket.gethostbyname(h)
            w.writerow([h, ip])
            print(h, ip)
        except socket.gaierror:
            print("No resolt:", h)
```

**Explicació.** `gethostbyname` pot llençar `gaierror` si el nom no es resol. Generem un CSV senzill amb el resultat.

---

## 5) `paramiko`
**Enunciat.** Connecta’t per SSH a un servidor i comprova si el paquet `nginx` està instal·lat executant una comanda remota. Mostra “instal·lat / no instal·lat” segons el codi de retorn.

**Solució**
```python
import paramiko

host = "server.exemple.cat"
user = "usuari"
password = "contrasenya"

cli = paramiko.SSHClient()
cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect(host, username=user, password=password)

# Exemple Debian/Ubuntu: dpkg -s nginx
stdin, stdout, stderr = cli.exec_command("dpkg -s nginx >/dev/null 2>&1")
exit_status = stdout.channel.recv_exit_status()
print("nginx instal·lat" if exit_status == 0 else "nginx NO instal·lat")
cli.close()
```

**Explicació.** `exec_command` retorna canals per llegir sortida i un codi d’estat via `recv_exit_status`. Si és 0, la comanda ha anat bé.

---

## 6) `fabric`
**Enunciat.** Envia un script local `backup.sh` a `/usr/local/bin/` de tres servidors i llança’l. Para l’execució si algun host falla.

**Solució**
```python
from fabric import Connection, ThreadingGroup

hosts = ["admin@h1.example", "admin@h2.example", "admin@h3.example"]
g = ThreadingGroup(*hosts)

# Copiem
for c in g:
    c.put("backup.sh", "/usr/local/bin/backup.sh")
    c.run("chmod +x /usr/local/bin/backup.sh")

# Executem i validem
for c in g:
    res = c.run("/usr/local/bin/backup.sh", warn=True)
    if res.exited != 0:
        raise SystemExit(f"Error a {c.host}: {res.stderr}")
```

**Explicació.** `ThreadingGroup` facilita execucions en paral·lel. `warn=True` evita excepcions automàtiques i permet revisar `exited` per decidir.

---

## 7) `ansible` (API)
**Enunciat.** Executa un playbook `site.yml` i mostra un resum: estat final i codi de retorn. Si falla, escriu la sortida d’errors a `errors.log`.

**Solució**
```python
from ansible_runner import run

r = run(private_data_dir=".", playbook="site.yml")
print("Estat:", r.status, "RC:", r.rc)
if r.rc != 0 and r.stderr:
    with open("errors.log", "w", encoding="utf-8") as f:
        f.write(r.stderr.read())
    print("Errors gravats a errors.log")
```

**Explicació.** `ansible-runner` encapsula l’execució. Consultem `status` i `rc`; si hi ha error, persistim `stderr`.

---

## 8) `pywinrm`
**Enunciat.** Connecta’t a un host Windows i llista els serveis que estan en estat “Running”. Desa la llista a `serveis_running.txt`.

**Solució**
```python
import winrm

sessio = winrm.Session("windows-server.exemple.cat", auth=("usuari", "contrasenya"))
r = sessio.run_ps("Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -ExpandProperty Name")
if r.status_code == 0:
    with open("serveis_running.txt", "w", encoding="utf-8") as f:
        f.write(r.std_out.decode("utf-8", errors="ignore"))
    print("Fitxer creat.")
else:
    print("Error:", r.std_err.decode())
```

**Explicació.** Fem servir PowerShell via WinRM. Si el codi és 200/0 segons binding, llegim `std_out` i el desem.

---

## 9) `pyshark`
**Enunciat.** Llegeix un fitxer `trafic.pcap` i compta quants paquets són DNS. Mostra el total i crea `resum_dns.txt` amb la llista de hosts consultats (si n’hi ha).

**Solució**
```python
import pyshark

pcap = "trafic.pcap"
dns_count = 0
hosts = []

cap = pyshark.FileCapture(pcap, display_filter="dns")
for pkt in cap:
    dns_count += 1
    try:
        if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
            hosts.append(pkt.dns.qry_name)
    except AttributeError:
        pass
cap.close()

print("Paquets DNS:", dns_count)
if hosts:
    with open("resum_dns.txt", "w", encoding="utf-8") as f:
        for h in hosts:
            f.write(str(h) + "\n")
    print("resum_dns.txt creat")
```

**Explicació.** `display_filter="dns"` filtra al motor de dissecció. Comptem paquets i, si hi ha camp `qry_name`, l’afegim al resum.



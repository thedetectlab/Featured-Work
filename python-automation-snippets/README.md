<div align="center">

```
r o o t @ s n i f f e r : ~ / f e a t u r e d - w o r k / p y t h o n - a u t o m a t i o n - s n i p p e t s #
```

# 🐍 Python Automation Snippets

**Small scripts for the repetitive work that shouldn't need a human.**

</div>

---

## 📁 File & Folder

**Bulk rename files with a pattern**

```python
import os
folder = "photos"
prefix = "batch_2026"
for i, filename in enumerate(sorted(os.listdir(folder)), start=1):
    ext = os.path.splitext(filename)[1]
    new_name = f"{prefix}_{i:03d}{ext}"
    os.rename(os.path.join(folder, filename), os.path.join(folder, new_name))
```

**Watch a folder and process new files automatically**

```python
import time, os
folder = "incoming"
seen = set(os.listdir(folder))
while True:
    current = set(os.listdir(folder))
    for f in current - seen:
        print(f"New file detected: {f}")
        # add your processing logic here
    seen = current
    time.sleep(5)
```

## 📊 Spreadsheet & Data

**Merge multiple Excel files into one** — `pip install openpyxl pandas`

```python
import pandas as pd
import glob
files = glob.glob("reports/*.xlsx")
combined = pd.concat([pd.read_excel(f) for f in files], ignore_index=True)
combined.to_excel("merged_report.xlsx", index=False)
```

**Auto-generate a summary report from raw data**

```python
import pandas as pd
df = pd.read_excel("sales_data.xlsx")
summary = df.groupby("region").agg(
    total_sales=("amount", "sum"),
    avg_sale=("amount", "mean"),
    num_orders=("amount", "count"),
).reset_index()
summary.to_excel("sales_summary.xlsx", index=False)
```

## 🌐 Web & API

**Check multiple URLs for broken links**

```python
import requests
with open("urls.txt") as f:
    urls = [line.strip() for line in f if line.strip()]
for url in urls:
    try:
        r = requests.get(url, timeout=5)
        status = "OK" if r.status_code == 200 else f"BROKEN ({r.status_code})"
    except requests.RequestException:
        status = "UNREACHABLE"
    print(f"{url}: {status}")
```

## 📄 PDF

**Extract text from a PDF** — `pip install pypdf`

```python
from pypdf import PdfReader
reader = PdfReader("document.pdf")
text = "".join(page.extract_text() for page in reader.pages)
print(text)
```

**Merge multiple PDFs into one**

```python
from pypdf import PdfWriter
writer = PdfWriter()
for filename in ["part1.pdf", "part2.pdf", "part3.pdf"]:
    writer.append(filename)
with open("combined.pdf", "wb") as f:
    writer.write(f)
```

## ⏰ Scheduling — Making Scripts Run Themselves

```bash
# cron (Mac/Linux) — run daily at 8am
crontab -e
0 8 * * * /usr/bin/python3 /path/to/your_script.py
```

```
# Windows: Task Scheduler
Create Basic Task → set trigger → Action: "Start a program"
→ point it to python.exe, script path as argument
```

**Log the output of scheduled scripts somewhere** — a script that silently stops running is worse than no automation at all, because you stop checking manually too.

---

<div align="center">

```
TYPE      SCRIPT REFERENCE
STATUS    ACTIVE
```

⚠️ Test any file-modifying script (delete/overwrite) on a backup copy before pointing it at real data.

</div>

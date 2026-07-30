# Day 20 — Delimited files: multiple fields per line

## Main goal

Learn how to store simple records in a text file where each line has multiple fields separated by a comma.

By the end of this lesson, you should understand this flow:

```text
file line -> split into fields -> create dictionary -> add to list
```

Example file line:

```text
alice@smallco.com,2026-04-01
```

Example Python record:

```python
{
    "email": "alice@smallco.com",
    "date": "2026-04-01"
}
```

---

## 1. Review: one value per line

In Day 18 and Day 19, each line usually stored one value:

```text
alice@smallco.com
bob@smallco.com
tom@trialdomain.com
```

That is useful, but real records usually need more than one field.

For TeamOne activity, we may want to store:

- email
- date

So each line can contain both values.

---

## 2. A simple delimited activity file

Create a file called `usage_activity.txt` with this content:

```text
alice@smallco.com,2026-04-01
bob@smallco.com,2026-04-01
tom@trialdomain.com,2026-04-02
support@cbc.ca,2026-04-02
demo@newlead.com,2026-04-03
```

Each line is one activity record.

Each record has two fields:

```text
email,date
```

The comma is the delimiter.

A delimiter is a character that separates values.

---

## 3. Split one line manually

Start with one line as a string:

```python
line = "alice@smallco.com,2026-04-01"

parts = line.split(",")

print(parts)
print(parts[0])
print(parts[1])
```

Output:

```text
['alice@smallco.com', '2026-04-01']
alice@smallco.com
2026-04-01
```

Explanation:

```python
parts = line.split(",")
```

means:

```text
Cut the string wherever there is a comma.
Return the pieces as a list.
```

Then:

```python
email = parts[0]
date = parts[1]
```

---

## 4. Read delimited records from a file

```python
with open("usage_activity.txt", "r") as file:
    lines = file.readlines()

for line in lines:
    clean_line = line.strip()
    parts = clean_line.split(",")

    email = parts[0]
    date = parts[1]

    print(email)
    print(date)
```

Why `.strip()` matters:

```python
clean_line = line.strip()
```

It removes the newline character at the end of each line.

---

## 5. Print readable activity summaries

```python
with open("usage_activity.txt", "r") as file:
    lines = file.readlines()

for line in lines:
    clean_line = line.strip()
    parts = clean_line.split(",")

    email = parts[0]
    date = parts[1]

    print(f"{email} used TeamOne on {date}")
```

This is much easier to read than printing raw lines.

---

## 6. Convert each line into a dictionary

A delimited line is useful, but Python dictionaries are easier to work with in code.

```python
line = "alice@smallco.com,2026-04-01"
parts = line.split(",")

record = {
    "email": parts[0],
    "date": parts[1]
}

print(record)
print(record["email"])
print(record["date"])
```

This creates one activity record as a dictionary.

---

## 7. Convert the whole file into a list of dictionaries

This is the most important pattern for today.

```python
usage_records = []

with open("usage_activity.txt", "r") as file:
    lines = file.readlines()

for line in lines:
    clean_line = line.strip()
    parts = clean_line.split(",")

    record = {
        "email": parts[0],
        "date": parts[1]
    }

    usage_records.append(record)

print(usage_records)
```

Mental model:

```text
usage_activity.txt has many text lines.
Each line becomes one dictionary.
All dictionaries are stored in usage_records.
```

---

## 8. Loop through loaded records

After the file is converted into `usage_records`, we can use normal list-of-dictionaries code again.

```python
for record in usage_records:
    print(record["email"])
```

Or:

```python
for record in usage_records:
    print(f'{record["email"]} used TeamOne on {record["date"]}')
```

---

## 9. Filter loaded records by domain

```python
def get_domain(email):
    return email[email.find("@") + 1:]

for record in usage_records:
    email = record["email"]
    domain = get_domain(email)

    if domain == "smallco.com":
        print(email)
```

This connects file data to the TeamOne activity tracker idea.

---

## 10. Handle bad lines safely

Sometimes a file may have a bad line:

```text
bad-line-without-comma
```

If we try this:

```python
parts = clean_line.split(",")
email = parts[0]
date = parts[1]
```

Python may crash if there is no second field.

A simple beginner-safe check:

```python
parts = clean_line.split(",")

if len(parts) == 2:
    email = parts[0]
    date = parts[1]
    print(email, date)
else:
    print("Skipping bad line:", clean_line)
```

This avoids an `IndexError`.

---

## 11. Current working directory and file paths

When you write:

```python
with open("usage_activity.txt", "w") as file:
```

Python writes the file in the **current working directory**.

That is the folder Python is currently running from.

It is not always the same folder where the script is saved.

To check the current working directory:

```python
import os

print(os.getcwd())
```

If a file appears in a surprising place, use `os.getcwd()` to check where Python is reading and writing files.

For now, the simplest habit is:

1. Keep your `.py` file and `.txt` file in the same project folder.
2. Run the script from that folder.
3. Use `print(os.getcwd())` if the file is missing or appears somewhere unexpected.

---

## 12. Optional preview: using the script folder

This is optional for now, but useful later.

```python
from pathlib import Path

BASE_DIR = Path(__file__).parent
file_path = BASE_DIR / "usage_activity.txt"

with open(file_path, "r") as file:
    lines = file.readlines()
```

This means:

```text
Find the folder where this script is saved.
Use usage_activity.txt from that folder.
```

You do not need to master this yet.

For today, focus on manual `.split(",")` and converting file lines into dictionaries.

---

# Drills

## Drill 1 — Split one record

Predict the output:

```python
line = "alice@smallco.com,2026-04-01"
parts = line.split(",")

print(parts[0])
print(parts[1])
```

---

## Drill 2 — Explain the delimiter

In this line:

```text
bob@smallco.com,2026-04-01
```

Answer:

1. What is the delimiter?
2. What is the first field?
3. What is the second field?

---

## Drill 3 — Read and split lines

Trace this code:

```python
with open("usage_activity.txt", "r") as file:
    lines = file.readlines()

for line in lines:
    clean_line = line.strip()
    parts = clean_line.split(",")
    print(parts)
```

What does `parts` contain for each line?

---

## Drill 4 — Create one dictionary from one line

Fill in the missing parts:

```python
line = "tom@trialdomain.com,2026-04-02"
parts = line.split(",")

record = {
    "email": parts[___],
    "date": parts[___]
}

print(record)
```

---

## Drill 5 — Convert many lines into records

Explain what this line does:

```python
usage_records.append(record)
```

Why do we need it inside the loop?

---

## Drill 6 — Predict a formatted summary

```python
record = {
    "email": "support@cbc.ca",
    "date": "2026-04-02"
}

print(f'{record["email"]} used TeamOne on {record["date"]}')
```

What is printed?

---

## Drill 7 — Find the bug

What is wrong here?

```python
line = "alice@smallco.com,2026-04-01"
parts = line.split()

email = parts[0]
date = parts[1]
```

---

## Drill 8 — Bad line check

Predict what happens:

```python
clean_line = "bad-line-without-comma"
parts = clean_line.split(",")

if len(parts) == 2:
    print("Good line")
else:
    print("Bad line")
```

---

## Drill 9 — Current working directory

What does this print?

```python
import os

print(os.getcwd())
```

Explain in plain English why this can help when a file is missing.

---

## Drill 10 — Domain filter from loaded records

Explain each step:

```python
for record in usage_records:
    email = record["email"]

    if "smallco.com" in email:
        print(email)
```

---

# Review and explain-back

Answer these in your own words:

1. What is a delimiter?
2. What does `.split(",")` do?
3. Why do we use `.strip()` before splitting file lines?
4. What does `parts[0]` usually contain in today’s activity file?
5. What does `parts[1]` usually contain?
6. Why convert file lines into dictionaries?
7. Why store all dictionaries in a list?
8. What can go wrong if a line is missing a comma?
9. What does `os.getcwd()` show?
10. How does this day connect to the TeamOne Client Activity Hub project?

---

# Coaching hints

- The main goal is not perfect CSV handling. The main goal is understanding how text rows become Python records.
- Keep the delimiter example simple. Do not introduce quoted CSV values yet.
- If the student struggles, go back to one line only before reading the full file.
- Ask the student to explain the shape: “file -> lines -> parts -> dictionary -> list.”
- If they get an `IndexError`, ask them to print `parts` before accessing `parts[1]`.
- If the file cannot be found, ask them to run `print(os.getcwd())`.
- Keep `pathlib` optional. The required lesson should use simple file names like `usage_activity.txt`.

# Day 23 — JSON basics: structured data files

## Main goal

Learn how to save and load structured Python data using JSON.

By the end of this lesson, students should understand that:

- JSON is a text file format for structured data.
- JSON can store data that looks like Python lists and dictionaries.
- `json.dump()` saves Python data into a JSON file.
- `json.load()` loads JSON data back into Python.
- JSON is easier than manually splitting comma-delimited lines when the data already has labels.

This day connects directly to the TeamOne Client Activity Hub project.

---

## 1. Why JSON?

Before JSON, we stored records in comma-delimited text files:

```text
alice@smallco.com,2026-04-01
bob@smallco.com,2026-04-01
tom@trialdomain.com,2026-04-02
```

Then we had to split each line manually:

```python
parts = line.strip().split(",")
email = parts[0]
date = parts[1]
```

That works, but it has one problem: the file does not clearly show what each value means.

JSON can store labeled records directly:

```json
[
  {
    "email": "alice@smallco.com",
    "date": "2026-04-01"
  },
  {
    "email": "bob@smallco.com",
    "date": "2026-04-01"
  }
]
```

This looks very similar to a Python list of dictionaries.

---

## 2. Import the JSON module

Python has a built-in module for working with JSON.

```python
import json
```

A module is extra Python code we can use.

For JSON, we mainly use:

```python
json.dump()
json.load()
```

---

## 3. Save a list of dictionaries to JSON

```python
import json

usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-01"},
    {"email": "tom@trialdomain.com", "date": "2026-04-02"}
]

with open("usage.json", "w") as file:
    json.dump(usage_records, file, indent=2)

print("Usage records saved.")
```

Important parts:

```python
json.dump(usage_records, file, indent=2)
```

Means:

```text
Take the Python data in usage_records and write it into the file as JSON.
```

The `indent=2` part makes the JSON file easier for humans to read.

---

## 4. Load JSON back into Python

```python
import json

with open("usage.json", "r") as file:
    records = json.load(file)

print(records)
print(records[0]["email"])
```

Important part:

```python
records = json.load(file)
```

Means:

```text
Read the JSON file and turn it back into Python data.
```

After loading, `records` is a normal Python list.

Each item in the list is a dictionary.

---

## 5. Loop through loaded JSON data

```python
import json

with open("usage.json", "r") as file:
    records = json.load(file)

for record in records:
    print(record["email"])
```

This is the same loop pattern from earlier days.

The only difference is that the data now comes from a JSON file instead of being hardcoded inside the script.

---

## 6. Save client records to JSON

```python
import json

clients = [
    {"name": "SmallCo", "primary_domain": "smallco.com", "plan": "8-user"},
    {"name": "CBC", "primary_domain": "cbc.ca", "plan": "unlimited"},
    {"name": "News Corp", "primary_domain": "newscorp.com", "plan": "unlimited"}
]

with open("clients.json", "w") as file:
    json.dump(clients, file, indent=2)

print("Clients saved.")
```

This is very useful for the TeamOne project.

Later, `clients.json` can represent known clients and their domains.

---

## 7. Load client records and print names

```python
import json

with open("clients.json", "r") as file:
    clients = json.load(file)

for client in clients:
    print(client["name"])
```

---

## 8. Search loaded client records

```python
import json

with open("clients.json", "r") as file:
    clients = json.load(file)

keyword = "co"

for client in clients:
    if keyword.lower() in client["name"].lower():
        print(client["name"])
```

This is the same search pattern from lists of dictionaries.

Now the data comes from a JSON file.

---

## 9. Compare JSON with delimited files

Delimited file:

```text
alice@smallco.com,2026-04-01
```

Python has to guess field meaning based on position:

```python
email = parts[0]
date = parts[1]
```

JSON file:

```json
{
  "email": "alice@smallco.com",
  "date": "2026-04-01"
}
```

Python can use clear labels:

```python
record["email"]
record["date"]
```

JSON is usually better when records have multiple fields and labels matter.

---

## 10. Simple warning: JSON syntax is strict

JSON files must be written carefully.

Common mistakes:

```json
[
  {"email": "alice@smallco.com", "date": "2026-04-01"}
  {"email": "bob@smallco.com", "date": "2026-04-01"}
]
```

This is wrong because there is a missing comma between records.

Correct version:

```json
[
  {"email": "alice@smallco.com", "date": "2026-04-01"},
  {"email": "bob@smallco.com", "date": "2026-04-01"}
]
```

For now, it is safest to let Python create JSON files using `json.dump()`.

---

# Drills

## Drill 1 — Explain JSON

Answer in your own words:

```text
What is JSON used for?
```

---

## Drill 2 — Name the function

Which function saves Python data to a JSON file?

```python
json._____()
```

Which function loads JSON data back into Python?

```python
json._____()
```

---

## Drill 3 — Predict the loaded data type

```python
with open("usage.json", "r") as file:
    records = json.load(file)

print(type(records))
```

If `usage.json` contains a list of records, what type is `records`?

---

## Drill 4 — Access one field

```python
records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"}
]

print(records[0]["email"])
```

Predict the output.

---

## Drill 5 — Loop through loaded records

```python
records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-01"}
]

for record in records:
    print(record["date"])
```

Predict the output.

---

## Drill 6 — Fix the mistake

```python
import json

with open("usage.json", "w") as file:
    json.load(usage_records, file)
```

What should be used instead of `json.load()` here?

---

## Drill 7 — Fix the mistake

```python
import json

with open("usage.json", "r") as file:
    records = json.dump(file)
```

What should be used instead of `json.dump()` here?

---

## Drill 8 — Save clients

Write the missing line:

```python
import json

clients = [
    {"name": "SmallCo", "primary_domain": "smallco.com", "plan": "8-user"}
]

with open("clients.json", "w") as file:
    ______________________________
```

---

## Drill 9 — Search loaded clients

Fill in the missing field name:

```python
for client in clients:
    if "small" in client["_____"].lower():
        print(client["name"])
```

---

## Drill 10 — Explain the upgrade

Explain why JSON is easier than comma-delimited text for a list of dictionaries.

---

# Review and explain-back

By the end of Day 23, students should be able to answer:

1. What is JSON?
2. Why do we use `import json`?
3. What does `json.dump()` do?
4. What does `json.load()` do?
5. After loading JSON, can we loop through it like normal Python data?
6. Why is JSON useful for the TeamOne Client Activity Hub project?

---

# Coaching hints

- Keep repeating: JSON is just the file format. After `json.load()`, the data becomes normal Python data again.
- Do not introduce APIs yet. JSON will appear again with APIs later, but for now it is just a file format.
- If students confuse `dump` and `load`, use this memory aid: dump means put data into a file; load means bring data from a file into Python.
- Encourage students to open the JSON file after saving it so they can see what Python created.
- Avoid hand-editing complex JSON at first. Let Python write the JSON.
- If JSON errors happen, check for missing commas, missing quotes, or broken brackets.

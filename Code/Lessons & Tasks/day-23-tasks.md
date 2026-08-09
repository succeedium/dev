# Day 23 Tasks — JSON basics: structured data files

## Instructions

Create a Python file called:

```text
day-23.py
```

Complete the tasks below in order.

Use comments to separate the tasks:

```python
# Task 1 — Save usage records
```

---

## Task 1 — Save usage records

Create this list of usage records in Python:

```python
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-01"},
    {"email": "tom@trialdomain.com", "date": "2026-04-02"}
]
```

Save it to a file called:

```text
usage.json
```

Use `json.dump()` and `indent=2`.

---

## Task 2 — Load usage records

Load `usage.json` back into Python.

Print the loaded data.

---

## Task 3 — Print all usage emails

Load `usage.json`.

Loop through the records and print only the email from each record.

Expected output should include:

```text
alice@smallco.com
bob@smallco.com
tom@trialdomain.com
```

---

## Task 4 — Print usage summary sentences

Load `usage.json`.

For each record, print a sentence like:

```text
alice@smallco.com used TeamOne on 2026-04-01
```

---

## Task 5 — Save client records

Create this list of clients:

```python
clients = [
    {"name": "SmallCo", "primary_domain": "smallco.com", "plan": "8-user"},
    {"name": "CBC", "primary_domain": "cbc.ca", "plan": "unlimited"},
    {"name": "News Corp", "primary_domain": "newscorp.com", "plan": "unlimited"}
]
```

Save it to:

```text
clients.json
```

---

## Task 6 — Load and print client names

Load `clients.json`.

Loop through the clients and print each client name.

---

## Task 7 — Search clients by keyword

Load `clients.json`.

Create a variable:

```python
keyword = "co"
```

Print client names that contain the keyword.

The search should be case-insensitive.

---

## Task 8 — Build known domains from JSON

Load `clients.json`.

Create an empty list called:

```python
known_domains = []
```

Loop through clients and append each `primary_domain` to `known_domains`.

Print the final `known_domains` list.

---

## Task 9 — Unknown usage domains

Load both:

```text
usage.json
clients.json
```

Build a list of known domains from `clients.json`.

Loop through `usage_records`.

For each usage record:

1. Get the email.
2. Extract the domain.
3. Print the email if the domain is not in known domains.

Hint:

```python
domain = email[email.find("@") + 1:]
```

---

## Task 10 — Mini JSON report

Load both `usage.json` and `clients.json`.

Print a small report with:

```text
Total usage records: X
Total clients: Y
Known domains: [...]
```

Use `len()` for the totals.

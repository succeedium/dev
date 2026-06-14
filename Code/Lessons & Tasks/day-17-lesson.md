# Day 17 — Hardcoded Activity Tracker Mini-Project

## Main goal

Today you will combine several things you already know:

- lists
- dictionaries
- loops
- functions
- `if` statements
- simple searching and filtering
- clean, readable code

The project is a small hardcoded version of the future **TeamOne Client Activity Hub**.

For now, the data will stay inside the Python file. We are not using files yet.

---

## Big idea

A usage activity tracker needs two kinds of information:

1. **Activity records** — who used TeamOne and when.
2. **Client records** — which companies are known clients.

Example activity data:

```python
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-01"},
    {"email": "tom@trialdomain.com", "date": "2026-04-02"},
]
```

Example client data:

```python
clients = [
    {"name": "SmallCo", "primary_domain": "smallco.com", "plan": "8-user"},
    {"name": "CBC", "primary_domain": "cbc.ca", "plan": "unlimited"},
]
```

---

## Mental model

```text
usage_records is a list.
Each item in the list is a dictionary.
Each dictionary is one activity record.
Each activity record has fields like email and date.
```

```text
clients is a list.
Each item in the list is a dictionary.
Each dictionary is one client record.
Each client record has fields like name, primary_domain, and plan.
```

---

## Step 1 — Start with hardcoded data

```python
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-01"},
    {"email": "tom@trialdomain.com", "date": "2026-04-02"},
    {"email": "support@cbc.ca", "date": "2026-04-02"},
    {"email": "demo@newlead.com", "date": "2026-04-03"},
]

clients = [
    {"name": "SmallCo", "primary_domain": "smallco.com", "plan": "8-user"},
    {"name": "CBC", "primary_domain": "cbc.ca", "plan": "unlimited"},
]
```

This is not a real database yet. It is just data stored directly in variables.

---

## Step 2 — Write a helper function to clean emails

```python
def normalize_email(email):
    return email.strip().lower()
```

This function makes email cleanup reusable.

Example:

```python
print(normalize_email("  Alice@SmallCo.COM  "))
```

Output:

```text
alice@smallco.com
```

---

## Step 3 — Write a helper function to get a domain

```python
def get_domain(email):
    clean_email = normalize_email(email)
    at_position = clean_email.find("@")
    return clean_email[at_position + 1:]
```

Example:

```python
print(get_domain("alice@smallco.com"))
```

Output:

```text
smallco.com
```

For today, we assume the emails are valid-looking enough for this simple function.

---

## Step 4 — Print all activity records

```python
for record in usage_records:
    email = record["email"]
    date = record["date"]

    print(f"{email} used TeamOne on {date}")
```

This is a simple activity report.

---

## Step 5 — Print each email with its domain

```python
for record in usage_records:
    email = record["email"]
    domain = get_domain(email)

    print(f"{email} belongs to {domain}")
```

This connects activity records to domains.

---

## Step 6 — Search client records by company name

```python
search_name = "SmallCo"

for client in clients:
    if client["name"] == search_name:
        print(client["name"])
        print(client["primary_domain"])
        print(client["plan"])
```

This is an exact search.

It means:

```text
Go through each client.
If the name exactly matches the search name, print the client details.
```

---

## Step 7 — Search client records by keyword

```python
keyword = "small"

for client in clients:
    if keyword.lower() in client["name"].lower():
        print(client["name"])
```

This is a keyword search.

It can match:

```text
small
Small
SmallCo
```

because both sides are converted to lowercase before comparing.

---

## Step 8 — Build a list of known domains

```python
known_domains = []

for client in clients:
    known_domains.append(client["primary_domain"])

print(known_domains)
```

Output:

```text
['smallco.com', 'cbc.ca']
```

This list helps us decide whether activity belongs to a known client.

---

## Step 9 — Print known and unknown activity

```python
known_domains = []

for client in clients:
    known_domains.append(client["primary_domain"])

for record in usage_records:
    email = record["email"]
    domain = get_domain(email)

    if domain in known_domains:
        print(f"Known client activity: {email}")
    else:
        print(f"Unknown or trial activity: {email}")
```

This is the first version of a useful TeamOne activity report.

---

## Step 10 — Put the mini-project together

```python
def normalize_email(email):
    return email.strip().lower()


def get_domain(email):
    clean_email = normalize_email(email)
    at_position = clean_email.find("@")
    return clean_email[at_position + 1:]


usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-01"},
    {"email": "tom@trialdomain.com", "date": "2026-04-02"},
    {"email": "support@cbc.ca", "date": "2026-04-02"},
    {"email": "demo@newlead.com", "date": "2026-04-03"},
]

clients = [
    {"name": "SmallCo", "primary_domain": "smallco.com", "plan": "8-user"},
    {"name": "CBC", "primary_domain": "cbc.ca", "plan": "unlimited"},
]

known_domains = []

for client in clients:
    known_domains.append(client["primary_domain"])

print("Activity report")
print("---------------")

for record in usage_records:
    email = record["email"]
    date = record["date"]
    domain = get_domain(email)

    if domain in known_domains:
        status = "known client"
    else:
        status = "unknown or trial"

    print(f"{email} | {date} | {domain} | {status}")
```

---

# Drills

## Drill 1 — Explain the data shape

Look at this code:

```python
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-01"},
]
```

Answer in words:

1. What is `usage_records`?
2. What is each item inside the list?
3. What does each dictionary represent?
4. What fields does each record have?

---

## Drill 2 — Predict the output

```python
record = {"email": "alice@smallco.com", "date": "2026-04-01"}

print(record["email"])
print(record["date"])
```

Predict before running.

---

## Drill 3 — Loop through records

Predict the output:

```python
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-01"},
]

for record in usage_records:
    print(record["email"])
```

---

## Drill 4 — Trace the domain function

```python
def normalize_email(email):
    return email.strip().lower()


def get_domain(email):
    clean_email = normalize_email(email)
    at_position = clean_email.find("@")
    return clean_email[at_position + 1:]

print(get_domain("  Alice@SmallCo.COM  "))
```

Answer:

1. What does `normalize_email(...)` return?
2. What is `at_position`?
3. What does `get_domain(...)` return?

---

## Drill 5 — Fix the mistake

This code has a mistake:

```python
record = {"email": "alice@smallco.com", "date": "2026-04-01"}

print(record[email])
```

Fix it.

---

## Drill 6 — Search by exact company name

Predict the output:

```python
clients = [
    {"name": "SmallCo", "primary_domain": "smallco.com", "plan": "8-user"},
    {"name": "CBC", "primary_domain": "cbc.ca", "plan": "unlimited"},
]

search_name = "CBC"

for client in clients:
    if client["name"] == search_name:
        print(client["primary_domain"])
```

---

## Drill 7 — Search by keyword

Predict the output:

```python
clients = [
    {"name": "SmallCo", "primary_domain": "smallco.com", "plan": "8-user"},
    {"name": "CBC", "primary_domain": "cbc.ca", "plan": "unlimited"},
    {"name": "News Corp", "primary_domain": "newscorp.com", "plan": "unlimited"},
]

keyword = "co"

for client in clients:
    if keyword.lower() in client["name"].lower():
        print(client["name"])
```

---

## Drill 8 — Build known domains

Predict the final value of `known_domains`:

```python
clients = [
    {"name": "SmallCo", "primary_domain": "smallco.com", "plan": "8-user"},
    {"name": "CBC", "primary_domain": "cbc.ca", "plan": "unlimited"},
]

known_domains = []

for client in clients:
    known_domains.append(client["primary_domain"])

print(known_domains)
```

---

## Drill 9 — Known or unknown activity

Predict the output:

```python
known_domains = ["smallco.com", "cbc.ca"]

email = "demo@newlead.com"
domain = "newlead.com"

if domain in known_domains:
    print("known")
else:
    print("unknown")
```

---

## Drill 10 — Explain the report line

Explain this line in plain English:

```python
print(f"{email} | {date} | {domain} | {status}")
```

What are the four values being printed?

---

# Review and explain-back

At the end of the lesson, explain these in your own words:

1. What is a hardcoded activity tracker?
2. What is the difference between `usage_records` and `clients`?
3. Why do we use helper functions like `get_domain()`?
4. How do we search a list of dictionaries?
5. What is a known domain?
6. What is an unknown or trial domain?
7. How does this mini-project connect to the future TeamOne Client Activity Hub?

---

# Coaching hints

- Do not rush into files yet. The goal today is to combine known concepts inside one Python file.
- If the student is confused, go back to one dictionary first, then one list, then a loop.
- Keep repeating the phrase: “A list of dictionaries means many records.”
- Encourage helper variables like `email`, `date`, `domain`, and `status` instead of long one-line expressions.
- If search feels hard, explain it as: “Look at each record one by one and check one field.”
- Make the student predict output before running the code.
- If they make bracket mistakes, ask: “Are you selecting from a list or dictionary, or calling a function?”
- This day is successful if they can explain `for record in usage_records:` and `record["email"]` clearly.

# Day 16 — Lists of dictionaries: first TeamOne activity data

## Main goal

Today you will learn how to store many similar records using a **list of dictionaries**.

This is an important step for the TeamOne Client Activity Hub project.

So far, you have used:

- strings
- lists
- loops
- functions
- dictionaries

Today you will combine them.

By the end of this lesson, you should understand this pattern:

```python
for record in usage_records:
    print(record["email"])
```

That means:

1. `usage_records` is a list.
2. Each item in the list is a dictionary.
3. Each dictionary is one record.
4. `record["email"]` gets one field from the current record.

---

## 1. Review: one dictionary is one record

A dictionary can represent one record.

```python
usage_record = {
    "email": "alice@smallco.com",
    "date": "2026-04-01"
}

print(usage_record)
print(usage_record["email"])
print(usage_record["date"])
```

Think of this as one TeamOne usage event:

```text
alice@smallco.com used TeamOne on 2026-04-01
```

The keys are labels:

```text
"email"
"date"
```

The values are the actual data:

```text
"alice@smallco.com"
"2026-04-01"
```

---

## 2. A list of dictionaries stores many records

A real activity tracker needs more than one record.

```python
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-01"},
    {"email": "tom@trialdomain.com", "date": "2026-04-02"}
]

print(usage_records)
```

The outer structure is a list:

```python
[
    ...,
    ...,
    ...
]
```

Each item inside the list is a dictionary:

```python
{"email": "alice@smallco.com", "date": "2026-04-01"}
```

So the full shape is:

```text
list of dictionaries
```

Or in project words:

```text
many usage records
```

---

## 3. Access one record by index

Before looping, access just one record.

```python
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-01"},
    {"email": "tom@trialdomain.com", "date": "2026-04-02"}
]

first_record = usage_records[0]

print(first_record)
print(first_record["email"])
print(first_record["date"])
```

Step by step:

```python
usage_records[0]
```

gets the first dictionary.

Then:

```python
first_record["email"]
```

gets the email field from that dictionary.

You can also write it in one line:

```python
print(usage_records[0]["email"])
```

But at first, this is easier to read:

```python
first_record = usage_records[0]
print(first_record["email"])
```

---

## 4. Loop through all records

Usually, we do not want only the first record. We want to process every record.

```python
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-01"},
    {"email": "tom@trialdomain.com", "date": "2026-04-02"}
]

for record in usage_records:
    print(record["email"])
```

Important:

```python
record
```

is one dictionary at a time.

On the first loop:

```python
record = {"email": "alice@smallco.com", "date": "2026-04-01"}
```

On the second loop:

```python
record = {"email": "bob@smallco.com", "date": "2026-04-01"}
```

On the third loop:

```python
record = {"email": "tom@trialdomain.com", "date": "2026-04-02"}
```

---

## 5. Print readable usage summaries

Use f-strings to print useful messages.

```python
for record in usage_records:
    print(f'{record["email"]} used TeamOne on {record["date"]}')
```

Output:

```text
alice@smallco.com used TeamOne on 2026-04-01
bob@smallco.com used TeamOne on 2026-04-01
tom@trialdomain.com used TeamOne on 2026-04-02
```

This already looks like a simple activity report.

---

## 6. Client records

A different type of record can use different fields.

```python
clients = [
    {"name": "SmallCo", "plan": "8-user", "primary_domain": "smallco.com"},
    {"name": "CBC", "plan": "unlimited", "primary_domain": "cbc.ca"},
    {"name": "Trial Account", "plan": "trial", "primary_domain": "trialdomain.com"}
]

for client in clients:
    print(client["name"])
```

Each client dictionary has these fields:

```text
name
plan
primary_domain
```

You can print more than one field:

```python
for client in clients:
    print(f'{client["name"]} uses the {client["plan"]} plan')
```

---

## 7. Filter usage records by domain

Filtering means printing only records that match a condition.

```python
for record in usage_records:
    if "smallco.com" in record["email"]:
        print(record["email"])
```

This prints only SmallCo emails.

This works because each record has an email field:

```python
record["email"]
```

And we can check whether the email contains a domain:

```python
"smallco.com" in record["email"]
```

---

## 8. Use a helper function with records

You can reuse your old email helper function.

```python
def get_domain(email):
    return email[email.find("@") + 1:]

for record in usage_records:
    email = record["email"]
    domain = get_domain(email)

    print(domain)
```

This is easier to read than putting everything in one line.

Now filter by exact domain:

```python
def get_domain(email):
    return email[email.find("@") + 1:]

for record in usage_records:
    email = record["email"]
    domain = get_domain(email)

    if domain == "smallco.com":
        print(email)
```

---

## 9. Search clients by exact company name

Searching means:

1. loop through each record
2. look at one field
3. check whether it matches what we want
4. print the matching record

Example:

```python
search_name = "SmallCo"

for client in clients:
    if client["name"] == search_name:
        print(client["name"])
        print(client["plan"])
        print(client["primary_domain"])
```

This is an exact search. The name must match exactly.

---

## 10. Search clients by keyword

Keyword search is more flexible.

```python
keyword = "small"

for client in clients:
    if keyword.lower() in client["name"].lower():
        print(client["name"])
```

This works even if the capitalization is different.

For example:

```text
small
Small
SMALL
```

can all match `SmallCo` if we use `.lower()`.

---

## 11. Add a new record with append()

Lists can grow.

```python
usage_records.append({
    "email": "new.user@smallco.com",
    "date": "2026-04-03"
})

print(usage_records)
```

You are adding one new dictionary to the list.

---

## 12. Count records with len()

Use `len()` to count how many records are in the list.

```python
print(len(usage_records))
```

You can print a nicer message:

```python
print(f"Total usage records: {len(usage_records)}")
```

---

# Drills

## Drill 1 — Identify the data shape

Look at this code:

```python
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-01"}
]
```

Answer in plain English:

1. What is `usage_records`?
2. What is each item inside `usage_records`?
3. What fields does each record have?

---

## Drill 2 — Predict the output

```python
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-02"}
]

print(usage_records[0])
print(usage_records[0]["email"])
print(usage_records[1]["date"])
```

Predict the output before running it.

---

## Drill 3 — Loop through records

Predict the output:

```python
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-02"}
]

for record in usage_records:
    print(record["email"])
```

Then explain what `record` is during each loop.

---

## Drill 4 — Print readable summaries

Fill in the missing parts:

```python
for record in usage_records:
    print(f'{record["_____"]} used TeamOne on {record["_____"]}')
```

Expected message style:

```text
alice@smallco.com used TeamOne on 2026-04-01
```

---

## Drill 5 — Client records

Predict the output:

```python
clients = [
    {"name": "SmallCo", "plan": "8-user", "primary_domain": "smallco.com"},
    {"name": "CBC", "plan": "unlimited", "primary_domain": "cbc.ca"}
]

for client in clients:
    print(client["name"])
```

Then change the code so it prints each plan instead.

---

## Drill 6 — Fix dictionary access mistakes

Fix the mistakes:

```python
for record in usage_records:
    print(record[email])
```

```python
for client in clients:
    print(client("name"))
```

```python
print(usage_records[0]("email"))
```

---

## Drill 7 — Filter by domain

Predict what will print:

```python
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-02"},
    {"email": "tom@trialdomain.com", "date": "2026-04-02"}
]

for record in usage_records:
    if "smallco.com" in record["email"]:
        print(record["email"])
```

---

## Drill 8 — Helper function with record data

Trace this code:

```python
def get_domain(email):
    return email[email.find("@") + 1:]

record = {"email": "alice@smallco.com", "date": "2026-04-01"}

email = record["email"]
domain = get_domain(email)

print(domain)
```

Answer:

1. What is stored in `email`?
2. What is passed into `get_domain()`?
3. What is stored in `domain`?

---

## Drill 9 — Exact search

Predict the output:

```python
clients = [
    {"name": "SmallCo", "plan": "8-user", "primary_domain": "smallco.com"},
    {"name": "CBC", "plan": "unlimited", "primary_domain": "cbc.ca"}
]

search_name = "CBC"

for client in clients:
    if client["name"] == search_name:
        print(client["plan"])
```

---

## Drill 10 — Keyword search

Predict the output:

```python
clients = [
    {"name": "SmallCo", "plan": "8-user", "primary_domain": "smallco.com"},
    {"name": "CBC Radio-Canada", "plan": "unlimited", "primary_domain": "cbc.ca"},
    {"name": "Trial Account", "plan": "trial", "primary_domain": "trialdomain.com"}
]

keyword = "radio"

for client in clients:
    if keyword.lower() in client["name"].lower():
        print(client["name"])
```

Then change `keyword` to `trial` and predict the new output.

---

# Review and explain-back

Answer these in your own words:

1. What is a list of dictionaries?
2. What does one dictionary represent in `usage_records`?
3. What does `record["email"]` mean?
4. In `for record in usage_records`, what is `record`?
5. Why are lists of dictionaries useful for the TeamOne Client Activity Hub?
6. How do you search for a client by name?
7. What is the difference between exact search and keyword search?
8. Why do we often use `.lower()` when searching by keyword?
9. How does `append()` add a new record?
10. How does `len(usage_records)` help with reporting?

---

# Coaching hints

- The most important mental model is: **list = many records, dictionary = one record**.
- If the student is confused, ask them to point to the outer list first, then to one dictionary inside it.
- Avoid one-line expressions too early. Prefer helper variables:

```python
record = usage_records[0]
email = record["email"]
print(email)
```

instead of:

```python
print(usage_records[0]["email"])
```

- Search should be explained as a simple loop plus condition.
- Keep exact search and keyword search separate at first.
- Do not introduce JSON, files, nested dictionaries, `.get()`, or advanced search functions yet.
- If they make mistakes with brackets, remind them:
  - `[]` gets an item from a list or dictionary
  - `()` calls a function
  - `{}` creates a dictionary

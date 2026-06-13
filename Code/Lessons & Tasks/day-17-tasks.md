# Day 17 Tasks — Hardcoded Activity Tracker Mini-Project

## Submission instructions

Create one Python file:

```text
day-17.py
```

Complete all tasks in the same file.

Use comments to separate the tasks:

```python
# Task 1 — Create hardcoded activity records
```

---

## Task 1 — Create hardcoded activity records

Create a list called `usage_records` with at least five dictionaries.

Each dictionary should have:

- `email`
- `date`

Use examples like:

```python
{"email": "alice@smallco.com", "date": "2026-04-01"}
```

Print the whole list.

---

## Task 2 — Create hardcoded client records

Create a list called `clients` with at least three dictionaries.

Each dictionary should have:

- `name`
- `primary_domain`
- `plan`

Example:

```python
{"name": "SmallCo", "primary_domain": "smallco.com", "plan": "8-user"}
```

Print the whole list.

---

## Task 3 — Print all activity emails

Loop through `usage_records` and print each email.

Expected style:

```text
alice@smallco.com
bob@smallco.com
```

---

## Task 4 — Print readable activity summaries

Loop through `usage_records` and print a sentence for each record.

Example output:

```text
alice@smallco.com used TeamOne on 2026-04-01
```

---

## Task 5 — Create a normalize_email function

Create a function called `normalize_email(email)`.

It should:

- remove spaces from the beginning and end
- convert the email to lowercase
- return the cleaned email

Test it with:

```python
print(normalize_email("  Alice@SmallCo.COM  "))
```

---

## Task 6 — Create a get_domain function

Create a function called `get_domain(email)`.

It should return the domain after the `@` symbol.

Example:

```python
print(get_domain("alice@smallco.com"))
```

Expected output:

```text
smallco.com
```

---

## Task 7 — Print each activity email with its domain

Loop through `usage_records`.

For each record, print:

- email
- domain

Example output:

```text
alice@smallco.com belongs to smallco.com
```

---

## Task 8 — Search clients by exact company name

Create a variable called `search_name`.

Example:

```python
search_name = "SmallCo"
```

Loop through `clients` and print the matching client’s:

- name
- primary domain
- plan

---

## Task 9 — Search clients by keyword

Create a variable called `keyword`.

Example:

```python
keyword = "co"
```

Loop through `clients` and print client names that contain the keyword.

The search should ignore uppercase/lowercase differences.

Hint:

```python
keyword.lower() in client["name"].lower()
```

---

## Task 10 — Build known domains list

Create an empty list called `known_domains`.

Loop through `clients` and append each client’s `primary_domain` to `known_domains`.

Print `known_domains`.

---

## Task 11 — Print known vs unknown activity

Use `known_domains` and `usage_records`.

For each usage record:

1. get the email
2. get the domain
3. check whether the domain is in `known_domains`
4. print one of these messages:

```text
Known client activity: alice@smallco.com
```

or:

```text
Unknown or trial activity: demo@newlead.com
```

---

## Task 12 — Final mini report

Print a simple report with one line per usage record.

Each line should include:

- email
- date
- domain
- status

Example output:

```text
alice@smallco.com | 2026-04-01 | smallco.com | known client
```

For unknown domains, use:

```text
unknown or trial
```

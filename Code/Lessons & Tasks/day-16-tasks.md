# Day 16 Tasks — Lists of dictionaries: first TeamOne activity data

## Instructions

Create a Python file named:

```text
day-16.py
```

Complete the tasks below in the same file.

Use comments to separate your work:

```python
# Task 1
# Task 2
# Task 3
```

Try to write clear, readable code.

---

## Task 1 — One usage record

Create one dictionary named `usage_record` with these fields:

- `email`
- `date`

Use this example data:

```text
email: alice@smallco.com
date: 2026-04-01
```

Print the whole dictionary.

Then print the email and date separately.

---

## Task 2 — Three usage records

Create a list named `usage_records` with three dictionaries.

Use these records:

```text
alice@smallco.com — 2026-04-01
bob@smallco.com — 2026-04-01
tom@trialdomain.com — 2026-04-02
```

Print the full list.

---

## Task 3 — First record details

Using the `usage_records` list from Task 2:

1. Store the first record in a variable named `first_record`.
2. Print `first_record`.
3. Print the first record's email.
4. Print the first record's date.

---

## Task 4 — Print all usage emails

Loop through `usage_records` and print each email.

Expected style:

```text
alice@smallco.com
bob@smallco.com
tom@trialdomain.com
```

---

## Task 5 — Print usage summary sentences

Loop through `usage_records` and print a sentence for each record.

Expected style:

```text
alice@smallco.com used TeamOne on 2026-04-01
```

---

## Task 6 — Client records

Create a list named `clients` with three client dictionaries.

Use these records:

```text
SmallCo — 8-user — smallco.com
CBC — unlimited — cbc.ca
Trial Account — trial — trialdomain.com
```

Each dictionary should have these fields:

- `name`
- `plan`
- `primary_domain`

Loop through the list and print each client name.

---

## Task 7 — Client plan summary

Using the `clients` list from Task 6, print a sentence for each client.

Expected style:

```text
SmallCo uses the 8-user plan
CBC uses the unlimited plan
Trial Account uses the trial plan
```

---

## Task 8 — Filter SmallCo usage records

Loop through `usage_records` and print only the emails that contain:

```text
smallco.com
```

Expected output:

```text
alice@smallco.com
bob@smallco.com
```

---

## Task 9 — Search client by exact name

Create a variable:

```python
search_name = "CBC"
```

Loop through `clients`.

If the client's name equals `search_name`, print:

- the client name
- the plan
- the primary domain

---

## Task 10 — Search clients by keyword

Create a variable:

```python
keyword = "trial"
```

Loop through `clients`.

Print the names of clients where the keyword appears in the client name.

The search should be case-insensitive.

Hint:

```python
keyword.lower() in client["name"].lower()
```

---

## Task 11 — Add a new usage record

Add this new record to `usage_records` using `append()`:

```text
new.user@smallco.com — 2026-04-03
```

After adding it, print the total number of usage records using `len()`.

Then print all usage emails again.

---

## Task 12 — Challenge: print trial-domain usage

Loop through `usage_records` and print only emails that contain:

```text
trialdomain.com
```

Expected output:

```text
tom@trialdomain.com
```

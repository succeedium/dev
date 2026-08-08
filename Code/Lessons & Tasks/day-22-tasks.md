# Day 22 Tasks — Counting and simple reports from file data

## Instructions

Create a Python file called:

```text
day-22.py
```

Also create this text file in the same folder:

```text
usage_activity.txt
```

Put this data inside `usage_activity.txt`:

```text
alice@smallco.com,2026-04-01
bob@smallco.com,2026-04-01
tom@trialdomain.com,2026-04-02
support@cbc.ca,2026-04-02
demo@newlead.com,2026-04-03
bad-line-without-comma
```

Complete each task in `day-22.py`.

Use comments to separate tasks:

```python
# Task 1 — Load valid records
```

---

## Task 1 — Load valid records

Read `usage_activity.txt`.

For each line:

- remove the newline with `.strip()`
- split the line by comma
- if the line has exactly 2 parts, create a dictionary with:
  - `email`
  - `date`
- append the dictionary to a list called `usage_records`
- if the line is bad, print `Skipping bad line:` and the line

At the end, print `usage_records`.

---

## Task 2 — Print total valid records

Print the number of valid records loaded into `usage_records`.

Expected style:

```text
Total valid records: 5
```

---

## Task 3 — Print all activity summaries

Loop through `usage_records` and print one sentence per record.

Example style:

```text
alice@smallco.com used TeamOne on 2026-04-01
```

---

## Task 4 — Create a domain helper function

Create a function called `get_domain(email)`.

It should return the part of the email after `@`.

Example:

```python
print(get_domain("alice@smallco.com"))
```

Expected output:

```text
smallco.com
```

---

## Task 5 — Count SmallCo records

Count how many records belong to this domain:

```text
smallco.com
```

Print the result.

Expected style:

```text
SmallCo records: 2
```

---

## Task 6 — Count records for one date

Count how many records are on this date:

```text
2026-04-02
```

Print the result.

Expected style:

```text
Records on 2026-04-02: 2
```

---

## Task 7 — Count known and unknown domains

Create this list:

```python
known_domains = ["smallco.com", "cbc.ca"]
```

Loop through `usage_records`.

Count:

- records where the domain is in `known_domains`
- records where the domain is not in `known_domains`

Print both counts.

Expected style:

```text
Known-domain records: 3
Unknown-domain records: 2
```

---

## Task 8 — Print unknown-domain emails

Print only the emails where the domain is not in `known_domains`.

Expected style:

```text
Unknown-domain email: tom@trialdomain.com
Unknown-domain email: demo@newlead.com
```

---

## Task 9 — Print a final activity report

Print a clean final report with at least these lines:

```text
TeamOne Activity Report
-----------------------
Total valid records: 5
SmallCo records: 2
Records on 2026-04-02: 2
Known-domain records: 3
Unknown-domain records: 2
```

The exact formatting can be slightly different, but the report should be easy to read.

---

## Task 10 — Add one new record and rerun the report

Add one more good line to `usage_activity.txt` manually.

Example:

```text
newuser@smallco.com,2026-04-03
```

Run the program again.

Confirm that the counts changed.

At the bottom of your Python file, add a comment answering:

```python
# What changed after adding the new line?
```

Write a short answer in a comment.

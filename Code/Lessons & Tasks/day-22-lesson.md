# Day 22 — Counting and simple reports from file data

## Main goal

Use a text file as a small dataset and create simple reports from it.

By the end of this lesson, the student should understand how to:

- read records from a comma-delimited text file
- split each line into fields
- skip blank or broken lines
- convert file rows into dictionaries
- count total records
- count records for one domain
- count records for one date
- print simple report messages

This day connects file work with reporting. The file starts to behave like a very small database.

---

## Starting dataset

Create a file called `usage_activity.txt` in the same folder as the Python script.

Put this data inside the file:

```text
alice@smallco.com,2026-04-01
bob@smallco.com,2026-04-01
tom@trialdomain.com,2026-04-02
support@cbc.ca,2026-04-02
demo@newlead.com,2026-04-03
bad-line-without-comma
```

Each good line has two fields:

```text
email,date
```

Example:

```text
alice@smallco.com,2026-04-01
```

This means:

```text
alice@smallco.com used TeamOne on 2026-04-01
```

---

## Review: read the file line by line

```python
with open("usage_activity.txt", "r") as file:
    lines = file.readlines()

for line in lines:
    print(line.strip())
```

Important reminder:

```python
line.strip()
```

removes the invisible newline character at the end of each line.

---

## Split one activity record

```python
line = "alice@smallco.com,2026-04-01"
parts = line.split(",")

email = parts[0]
date = parts[1]

print(email)
print(date)
```

Output:

```text
alice@smallco.com
2026-04-01
```

---

## Safe split with a bad-line check

Some lines may be broken or incomplete.

Example bad line:

```text
bad-line-without-comma
```

If we run this:

```python
parts = line.split(",")
email = parts[0]
date = parts[1]
```

Python may fail because there is no second field.

Use `len(parts)` to check first:

```python
line = "bad-line-without-comma"
parts = line.split(",")

if len(parts) == 2:
    email = parts[0]
    date = parts[1]
    print(email, date)
else:
    print("Skipping bad line:", line)
```

Key idea:

```text
Before using parts[1], make sure it exists.
```

---

## Load file data into a list of dictionaries

This is the main pattern for today.

```python
usage_records = []

with open("usage_activity.txt", "r") as file:
    lines = file.readlines()

for line in lines:
    clean_line = line.strip()

    if clean_line == "":
        continue

    parts = clean_line.split(",")

    if len(parts) == 2:
        record = {
            "email": parts[0],
            "date": parts[1]
        }

        usage_records.append(record)
    else:
        print("Skipping bad line:", clean_line)

print(usage_records)
```

Important shape:

```text
usage_activity.txt file
→ lines
→ split fields
→ dictionaries
→ usage_records list
```

---

## Count total valid records

Once the file data is loaded into `usage_records`, counting becomes simple.

```python
print("Total valid records:", len(usage_records))
```

Or with a manual counter:

```python
total_count = 0

for record in usage_records:
    total_count = total_count + 1

print("Total valid records:", total_count)
```

Both are useful to understand.

`len(usage_records)` is shorter.

The manual counter helps us learn report logic.

---

## Helper function: get domain from email

```python
def get_domain(email):
    return email[email.find("@") + 1:]
```

Example:

```python
print(get_domain("alice@smallco.com"))
```

Output:

```text
smallco.com
```

---

## Count records for one domain

```python
smallco_count = 0

for record in usage_records:
    email = record["email"]
    domain = get_domain(email)

    if domain == "smallco.com":
        smallco_count = smallco_count + 1

print("SmallCo records:", smallco_count)
```

Step-by-step:

```text
1. Start count at 0.
2. Go through each record.
3. Get the email.
4. Extract the domain.
5. If the domain matches, add 1 to the count.
6. Print the final count.
```

---

## Count records for one date

Dates are still plain strings for now.

```python
date_count = 0

target_date = "2026-04-02"

for record in usage_records:
    if record["date"] == target_date:
        date_count = date_count + 1

print("Records on", target_date + ":", date_count)
```

We are not doing real date math yet.

For now:

```text
2026-04-02 is just text.
```

---

## Count known and unknown domains

```python
known_domains = ["smallco.com", "cbc.ca"]

known_count = 0
unknown_count = 0

for record in usage_records:
    email = record["email"]
    domain = get_domain(email)

    if domain in known_domains:
        known_count = known_count + 1
    else:
        unknown_count = unknown_count + 1

print("Known-domain records:", known_count)
print("Unknown-domain records:", unknown_count)
```

This connects directly to the TeamOne Client Activity Hub idea.

Known domains may belong to existing clients.

Unknown domains may be trial users, leads, test accounts, or setup issues.

---

## Print a simple report

```python
print("TeamOne Activity Report")
print("-----------------------")
print("Total valid records:", len(usage_records))
print("SmallCo records:", smallco_count)
print("Known-domain records:", known_count)
print("Unknown-domain records:", unknown_count)
```

A report is just organized output.

The code does the counting first.

Then the code prints the results clearly.

---

## Drills

### Drill 1 — Predict the split result

```python
line = "alice@smallco.com,2026-04-01"
parts = line.split(",")

print(parts)
print(parts[0])
print(parts[1])
```

Before running it, write down what each `print()` will show.

---

### Drill 2 — Explain the bad-line check

Explain why this check is useful:

```python
if len(parts) == 2:
    print("Good line")
else:
    print("Bad line")
```

What could go wrong if we try to use `parts[1]` without checking?

---

### Drill 3 — Trace the loaded records

Given this file:

```text
alice@smallco.com,2026-04-01
bad-line
bob@smallco.com,2026-04-01
```

How many dictionaries should be added to `usage_records`?

Which line should be skipped?

---

### Drill 4 — Count manually first

Look at this data:

```text
alice@smallco.com,2026-04-01
bob@smallco.com,2026-04-01
tom@trialdomain.com,2026-04-02
```

Before writing code, answer:

- How many total valid records are there?
- How many records belong to `smallco.com`?
- How many records are on `2026-04-01`?

---

### Drill 5 — Complete the counter

Fill in the missing line:

```python
smallco_count = 0

for record in usage_records:
    domain = get_domain(record["email"])

    if domain == "smallco.com":
        __________________________

print(smallco_count)
```

---

### Drill 6 — Known or unknown?

Predict the output:

```python
known_domains = ["smallco.com", "cbc.ca"]
domain = "trialdomain.com"

if domain in known_domains:
    print("Known")
else:
    print("Unknown")
```

---

### Drill 7 — Count known and unknown records

Trace this code with your finger:

```python
known_count = 0
unknown_count = 0
known_domains = ["smallco.com"]

for record in usage_records:
    domain = get_domain(record["email"])

    if domain in known_domains:
        known_count = known_count + 1
    else:
        unknown_count = unknown_count + 1
```

What should `known_count` and `unknown_count` mean?

---

### Drill 8 — Fix the mistake

This code has a mistake:

```python
if domain = "smallco.com":
    smallco_count = smallco_count + 1
```

Fix it.

---

### Drill 9 — Build a report sentence

Given:

```python
total_count = 5
unknown_count = 2
```

Write code that prints:

```text
Total records: 5
Unknown-domain records: 2
```

---

### Drill 10 — Explain the full flow

Explain this in plain English:

```text
file → lines → split fields → dictionaries → list → counts → report
```

---

## Review and explain-back

By the end of Day 22, the student should be able to answer:

1. What does a comma-delimited activity line contain?
2. Why do we use `.split(",")`?
3. Why do we check `len(parts) == 2`?
4. What is the difference between total records and records for one domain?
5. Why are dates still treated as strings for now?
6. What does `domain in known_domains` mean?
7. Why is counting useful for reports?
8. How does this connect to the TeamOne Client Activity Hub?

---

## Coaching hints

- Keep the focus on reports, not perfect file parsing.
- Make her count manually before coding. This builds intuition.
- If she struggles, return to a tiny dataset with only 3 lines.
- Reinforce that a report is just calculated values printed clearly.
- Remind her that `count = count + 1` means: calculate the right side first, then store the new value.
- Keep dates as strings. Do not introduce date math yet.
- Keep `known_domains` as a simple list. Do not introduce sets yet.
- Bad lines are useful because they teach why safety checks matter.

# Day 20 Tasks — Delimited files: multiple fields per line

## Submission instructions

Create a Python file called:

```text
day-20.py
```

Also create any required `.txt` files in the same folder as your Python file.

Use comments to separate each task:

```python
# Task 1 — Create usage_activity.txt
# your code here
```

---

## Task 1 — Create a delimited activity file

Create a file called `usage_activity.txt` using Python.

Write these lines into it:

```text
alice@smallco.com,2026-04-01
bob@smallco.com,2026-04-01
tom@trialdomain.com,2026-04-02
support@cbc.ca,2026-04-02
demo@newlead.com,2026-04-03
```

Each line should end with `\n`.

---

## Task 2 — Read and print the raw file

Read `usage_activity.txt` using `file.read()`.

Print the full text.

---

## Task 3 — Read lines and split each record

Read `usage_activity.txt` using `file.readlines()`.

Loop through the lines.

For each line:

1. use `.strip()`
2. use `.split(",")`
3. print the `parts` list

---

## Task 4 — Print email and date separately

Read `usage_activity.txt`.

For each line, print:

```text
Email: alice@smallco.com
Date: 2026-04-01
```

Use `parts[0]` for email and `parts[1]` for date.

---

## Task 5 — Print activity summary sentences

Read `usage_activity.txt`.

For each line, print a sentence like:

```text
alice@smallco.com used TeamOne on 2026-04-01.
```

---

## Task 6 — Convert one line into a dictionary

Start with this string:

```python
line = "alice@smallco.com,2026-04-01"
```

Split the line and create this dictionary:

```python
{
    "email": "alice@smallco.com",
    "date": "2026-04-01"
}
```

Print the dictionary.

Then print the email and date from the dictionary separately.

---

## Task 7 — Convert the file into a list of dictionaries

Create an empty list called `usage_records`.

Read `usage_activity.txt`.

For each line:

1. clean the line
2. split the line by comma
3. create a dictionary with `email` and `date`
4. append the dictionary to `usage_records`

Print `usage_records` at the end.

---

## Task 8 — Loop through the loaded dictionaries

Using the `usage_records` list from Task 7, loop through the records and print only the emails.

Expected style:

```text
alice@smallco.com
bob@smallco.com
...
```

---

## Task 9 — Filter SmallCo records

Using `usage_records`, print only records where the email contains:

```text
smallco.com
```

Print a sentence like:

```text
SmallCo activity: alice@smallco.com on 2026-04-01
```

---

## Task 10 — Skip bad lines safely

Create a file called `usage_activity_with_bad_lines.txt` using Python.

Write these lines into it:

```text
alice@smallco.com,2026-04-01
bad-line-without-comma
bob@smallco.com,2026-04-01
another bad line
```

Read the file.

For each line:

1. clean it
2. split by comma
3. if `len(parts) == 2`, print the email and date
4. otherwise print:

```text
Skipping bad line: bad-line-without-comma
```

---

## Task 11 — Show current working directory

Import `os`.

Print the current working directory using:

```python
os.getcwd()
```

Then print this message:

```text
This is where Python reads and writes simple file names by default.
```

---

## Task 12 — Mini activity loader

Create a mini program that:

1. creates or uses `usage_activity.txt`
2. reads the file
3. converts good lines into dictionaries
4. stores all dictionaries in `usage_records`
5. prints total number of loaded records
6. prints all activity summary sentences
7. prints only records from `smallco.com`

Keep the program simple and readable.

Use helper variables.
Do not write one giant line of code.

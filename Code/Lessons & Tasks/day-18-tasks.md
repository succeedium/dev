# Day 18 Tasks — Simple text files

## Submission instructions

Create a Python file named:

```text
day-18.py
```

Complete the tasks below in the same file.

Use comments to separate the tasks:

```python
# Task 1 — Write two emails
```

For this day, your code will create and read simple `.txt` files.

---

## Task 1 — Write two emails to a file

Create a file called `emails.txt`.

Write these two emails into the file, one email per line:

```text
alice@smallco.com
bob@smallco.com
```

Then run the program and open the file to check its content.

---

## Task 2 — Read the whole file

Read `emails.txt` using `file.read()`.

Print the full file content.

---

## Task 3 — Read lines and print clean emails

Read `emails.txt` using `file.readlines()`.

Loop through the lines.

For each line:

1. clean it with `.strip()`
2. print the cleaned email

---

## Task 4 — Append a new email

Append this email to the end of `emails.txt`:

```text
tom@trialdomain.com
```

Use append mode, not write mode.

Then read the file again and print the full content.

---

## Task 5 — Write a list of emails to a file

Create this list in Python:

```python
emails = [
    "alice@smallco.com",
    "bob@smallco.com",
    "tom@trialdomain.com",
    "support@cbc.ca",
    "demo@newlead.com"
]
```

Write all emails into a file called `email_dataset.txt`, one email per line.

---

## Task 6 — Read the email dataset

Read `email_dataset.txt`.

Loop through the file lines and print each cleaned email.

---

## Task 7 — Print only SmallCo emails

Read `email_dataset.txt`.

Print only emails that contain:

```text
smallco.com
```

---

## Task 8 — Count all emails in the file

Read `email_dataset.txt`.

Use a counter to count how many cleaned email lines are in the file.

Print a message like:

```text
Total emails: 5
```

---

## Task 9 — Save user input

Ask the user to enter an email using `input()`.

Append that email to a file called `submitted_emails.txt`.

Remember to add a new line after the email.

---

## Task 10 — Final mini task: simple file email report

Create or reuse `email_dataset.txt`.

Read the emails from the file.

Print:

1. all cleaned emails
2. only emails from `smallco.com`
3. total number of emails

Example output style:

```text
All emails:
alice@smallco.com
bob@smallco.com

SmallCo emails:
alice@smallco.com
bob@smallco.com

Total emails: 5
```

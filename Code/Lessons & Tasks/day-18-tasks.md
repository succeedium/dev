# Day 18 Tasks — Simple Text Files and Growing Datasets

## Submission instructions

Create a file called:

```text
day-18.py
```

Complete the tasks below in the same file.

Use comments to separate the tasks:

```python
# Task 1 — Create emails.txt
```

Today you will also create and use text files such as:

```text
emails.txt
notes.txt
email_dataset.txt
```

---

## Task 1 — Create `emails.txt`

Use Python to create a file called `emails.txt`.

Write three emails into the file, each on its own line.

Example emails:

```text
alice@smallco.com
bob@smallco.com
tom@trialdomain.com
```

Then print:

```text
emails.txt created
```

---

## Task 2 — Read the whole file

Open `emails.txt` in read mode.

Use `file.read()` to read the full contents.

Print the result.

---

## Task 3 — Read lines and clean them

Open `emails.txt` again.

Use `file.readlines()`.

Loop through the lines.

For each line:

1. use `.strip()`
2. store the cleaned value in a variable called `email`
3. print the email

---

## Task 4 — Append one hardcoded email

Append this email to `emails.txt`:

```text
support@cbc.ca
```

Then read the file and print all saved emails.

Make sure the new email appears on its own line.

---

## Task 5 — Add one email from input

Ask the user to enter an email address.

Append the entered email to `emails.txt`.

Then print:

```text
Email saved.
```

---

## Task 6 — Add a cleaned email from input

Ask the user to enter another email address.

Clean it using:

```python
.strip().lower()
```

Append the cleaned email to `emails.txt`.

Then read the file and print all saved emails.

---

## Task 7 — Count saved emails

Read `emails.txt` using `readlines()`.

Count how many non-empty emails are saved in the file.

Print a message like:

```text
Total saved emails: 6
```

The number may be different depending on how many times you ran your program.

---

## Task 8 — Create a notes file

Create a file called `notes.txt`.

Write two short lines about what you learned today.

Then read the file back and print it.

---

## Task 9 — Create a larger email dataset

Create a file called `email_dataset.txt`.

Write at least six emails into it, each on its own line.

Include at least:

- two `smallco.com` emails
- one `cbc.ca` email
- one `trialdomain.com` email
- one `newlead.com` email

Then read the file and print all emails.

---

## Task 10 — Filter the dataset

Read `email_dataset.txt`.

Loop through each line.

Print only emails that contain:

```text
smallco.com
```

---

## Task 11 — Mini database growth demo

Write a small program section that does this:

1. Ask the user for a TeamOne user email.
2. Clean the email with `.strip().lower()`.
3. Append it to `email_dataset.txt`.
4. Read `email_dataset.txt`.
5. Print all saved emails.
6. Print the total number of non-empty saved emails.

This task simulates a very small growing database.

---

## Task 12 — Reflection comment

At the bottom of your file, add a Python comment answering this question:

```text
Why is appending to a file useful for a program that collects activity data?
```

Example:

```python
# Appending is useful because...
```

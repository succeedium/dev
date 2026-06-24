# Day 19 Tasks — Text files as datasets

## Submission instructions

Create one Python file for today’s work:

```text
day-19.py
```

Write your answers in the same file.

Use comments to separate tasks:

```python
# Task 1 — Create the dataset file
```

Today, use this main file name for saved emails:

```text
email_dataset.txt
```

---

## Task 1 — Create the dataset file

Create `email_dataset.txt` and write at least five emails into it, one email per line.

Use these emails or your own similar examples:

```text
alice@smallco.com
bob@smallco.com
tom@trialdomain.com
support@cbc.ca
demo@newlead.com
```

Print a message when the file has been created.

---

## Task 2 — Read and print all saved emails

Read `email_dataset.txt` using `readlines()`.

Loop through the lines and print each cleaned email.

Remember to use `.strip()`.

---

## Task 3 — Count saved emails

Read `email_dataset.txt`.

Count how many non-empty email lines are saved in the file.

Print a message like:

```text
Total saved emails: 5
```

---

## Task 4 — Add one email from input

Ask the user to enter a new email address.

Clean it with `.strip().lower()`.

Append it to `email_dataset.txt`.

Then print:

```text
Email saved.
```

---

## Task 5 — Read the file after appending

After Task 4 appends the new email, read `email_dataset.txt` again.

Print all saved emails so the user can see that the dataset grew.

---

## Task 6 — Skip blank lines

Add at least one blank line to `email_dataset.txt` manually or by writing one from Python.

Read the file and print only non-empty lines.

Blank lines should not print.

---

## Task 7 — Print only SmallCo emails

Read `email_dataset.txt`.

Print only emails that contain:

```text
smallco.com
```

---

## Task 8 — Print valid-looking and invalid-looking emails

Read `email_dataset.txt`.

For each non-empty line:

- print `Valid-looking:` if the email contains `@`
- print `Invalid-looking:` if the email does not contain `@`

Example output:

```text
Valid-looking: alice@smallco.com
Invalid-looking: bad-email
```

---

## Task 9 — Extract domains from saved emails

Read `email_dataset.txt`.

For each valid-looking email, extract and print the domain.

Example:

```text
alice@smallco.com -> smallco.com
```

Skip invalid-looking emails.

---

## Task 10 — Mini dataset report

Create a small report from `email_dataset.txt`.

The report should print:

- total non-empty saved records
- number of valid-looking emails
- number of invalid-looking emails
- number of `smallco.com` emails

Example output:

```text
Dataset report
Total records: 6
Valid-looking emails: 5
Invalid-looking emails: 1
SmallCo emails: 2
```

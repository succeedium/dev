# Day 15 Tasks — Debugging Basics and Reading Errors

Complete these tasks in your submission file:

```text
day-15.py
```

For each task, keep the task label as a comment, for example:

```python
# Task 1 — Fix syntax errors
```

The goal today is not just to make code work. The goal is to understand what was wrong and how you fixed it.

---

## Task 1 — Fix syntax errors

Copy this broken code into your file and fix it:

```python
email = "name@gmail.com"
if "@" in email
    print("valid")
else
    print("invalid")
```

Expected behavior:

- if the email contains `@`, print `valid`
- otherwise print `invalid`

---

## Task 2 — Fix variable name mistakes

Copy this broken code and fix it:

```python
client_name = "CBC"
contact_email = "admin@cbc.ca"

print(client)
print(contactemail)
```

Expected behavior:

- print the client name
- print the contact email

---

## Task 3 — Fix string and number combination

Copy this broken code and fix it using an f-string:

```python
client = "SmallCo"
amount = 8000

print(client + " pays " + amount + " per year")
```

Expected output idea:

```text
SmallCo pays 8000 per year
```

---

## Task 4 — Fix list index error

Copy this code and fix the index problem:

```python
emails = ["a@gmail.com", "b@yahoo.com", "c@test.ca"]

print(emails[3])
```

Then add two more print lines:

- print the length of the list using `len()`
- print the last email using `len(emails) - 1`

---

## Task 5 — Add debug prints

Start with this code:

```python
email = "  USER@GMAIL.com  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
domain = clean_email[at_pos + 1:]

print(domain)
```

Add debug prints so the program prints:

- original email
- clean email
- position of `@`
- domain

Use clear labels like:

```python
print("DEBUG clean_email:", clean_email)
```

---

## Task 6 — Fix loop indentation

Copy this broken code and fix it:

```python
emails = ["a@gmail.com", "bademail.com", "c@test.ca"]

for email in emails:
if "@" in email:
print(email)
```

Expected behavior:

- print only emails that contain `@`

---

## Task 7 — Debug wrong logic

This code runs, but the result is wrong or unsafe:

```python
email = "bademail.com"
at_pos = email.find("@")
domain = email[at_pos + 1:]

print(domain)
```

Fix it so the code checks whether the email contains `@` before extracting the domain.

Expected behavior:

- if valid-looking, print the domain
- otherwise print `invalid email`

---

## Task 8 — Fix a function

Copy this broken function and fix it:

```python
def clean_email(email)
return email.strip().lower()

print(clean_email("  Name@GMAIL.com  "))
```

Expected output:

```text
name@gmail.com
```

---

## Task 9 — Explain three errors in comments

Write three short comments in your Python file explaining these errors:

```python
# SyntaxError means ...
# NameError means ...
# IndexError means ...
```

Use your own words.

---

## Task 10 — Mini debugging challenge

Fix this program. It has several problems.

```python
emails = [" A@GMAIL.com ", "bademail.com", " C@Test.ca "

valid_count = 0

for email in emails
    clean_email = email.strip.lower()
    if "@" in clean_email:
        valid_count = valid_count + 1
        print(clean_email)

print("Valid emails: " + valid_count)
```

Correct behavior:

- clean each email
- print only valid-looking emails
- count valid-looking emails
- print the final count

Hint: fix one problem at a time.

# Day 13 Tasks — Comments, clean code, and readable programs

Complete these tasks in your submission file:

```text
submissions/your-name/day-13.py
```

Use comments, meaningful variable names, and helper variables. The goal is not only to make the code work, but also to make it easy to read.

---

## Task 1 — Add comments to email cleanup

Start with this code:

```python
email = "  Name@GMAIL.com  "
clean_email = email.strip().lower()
print(clean_email)
```

Add useful comments that explain the main steps.

---

## Task 2 — Rename unclear variables

Rewrite this code with better variable names:

```python
x = "  ADMIN@CBC.ca  "
y = x.strip().lower()
z = y.find("@")
a = y[z + 1:]
print(a)
```

Use names like:

- `email`
- `clean_email`
- `at_pos`
- `domain`

---

## Task 3 — Break a long expression into helper variables

Rewrite this code using helper variables:

```python
email = "  User@Test.ca  "
print(email.strip().lower()[email.strip().lower().find("@") + 1:])
```

Your version should use:

- `clean_email`
- `at_pos`
- `domain`

---

## Task 4 — Organize an email checker into sections

Write a small program that:

- stores an email
- cleans it
- checks if it contains `@`
- prints the username and domain if valid
- prints `"invalid email"` otherwise

Add section comments such as:

```python
# Input data
# Clean data
# Check and extract
# Output
```

---

## Task 5 — Add debug prints

Use this code:

```python
email = "  Sales@SmallCo.com  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
username = clean_email[:at_pos]
domain = clean_email[at_pos + 1:]
```

Add debug prints for:

- `clean_email`
- `at_pos`
- `username`
- `domain`

Use labels like:

```python
print("DEBUG clean_email:", clean_email)
```

---

## Task 6 — Clean up messy code

Improve this code so it is readable:

```python
e="  USER@Test.ca  "
c=e.strip().lower()
if "@" in c:
 p=c.find("@")
 print(c[p+1:])
else:
 print("bad")
```

Your improved version should include:

- better variable names
- proper indentation
- helper variables
- clearer output message
- at least two useful comments

---

## Task 7 — Write small clear functions

Create these functions:

```python
clean_email(email)
looks_valid(email)
get_domain(email)
```

Then test them using:

```python
email = "  Admin@CBC.ca  "
```

Print:

- cleaned email
- whether it looks valid
- the domain

Use clear variable names.

---

## Task 8 — Make a readable email report

Use this list:

```python
emails = ["  ADMIN@CBC.ca  ", "bademail.com", " User@Test.ca "]
```

Write a readable program that:

- loops through the emails
- cleans each email
- checks if it contains `@`
- prints username and domain for valid-looking emails
- prints a clear invalid message for invalid emails

Use comments and helper variables.

---

## Task 9 — Add comments explaining a loop

Use this code idea:

```python
emails = ["a@gmail.com", "bademail.com", "c@test.ca"]
valid_count = 0

for email in emails:
    if "@" in email:
        valid_count = valid_count + 1

print(valid_count)
```

Rewrite it with comments explaining:

- what the list stores
- what the counter stores
- what the loop checks
- why the counter increases

---

## Task 10 — Mini clean-code review

Write two versions of a tiny program:

### Version A — messy version

Create a short messy version that works but is hard to read.

### Version B — cleaned-up version

Rewrite it using:

- better variable names
- helper variables
- comments
- clean formatting

Use an email example, such as extracting a domain from an email.

At the end, add a comment explaining why Version B is better.

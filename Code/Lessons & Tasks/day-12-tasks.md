# Day 12 — Functions: drills, practice tasks, and review

---

## Practice tasks

### Task 1 — Say hello function

Write a function called `say_hello()`.

It should print:

```python
Hello from Python
```

Call the function two times.

---

### Task 2 — Greeting function

Write a function called `greet(name)`.

It should print:

```python
Hello NAME
```

Call it with:

- `"Dominika"`
- `"Monika"`
- your own name

---

### Task 3 — Lowercase function

Write a function called `make_lower(text)`.

It should return the lowercase version of the text.

Test it with:

```python
"TEAMONE"
"CBC"
"HELLO"
```

---

### Task 4 — Clean email function

Write a function called `clean_email(email)`.

It should:

- remove spaces around the email
- convert it to lowercase
- return the cleaned email

Test it with:

```python
"  Name@GMAIL.com  "
" ADMIN@Test.ca "
"user@yahoo.com"
```

---

### Task 5 — Username function

Write `get_username(email)`.

It should return the part before `@`.

Example:

```python
get_username("name@gmail.com")
```

should return:

```python
name
```

---

### Task 6 — Domain function

Write `get_domain(email)`.

It should return the part after `@`.

Example:

```python
get_domain("name@gmail.com")
```

should return:

```python
gmail.com
```

---

### Task 7 — Validation function

Write `looks_valid(email)`.

It should return `True` if the email contains `@`.

It should return `False` otherwise.

Test it with:

```python
"name@gmail.com"
"bademail.com"
"admin@test.ca"
```

---

### Task 8 — Use validation before domain extraction

Use your functions:

- `looks_valid(email)`
- `get_domain(email)`

Store:

```python
email = "bademail.com"
```

If the email looks valid:

- print the domain

Otherwise:

- print `"invalid email"`

Then change the email to:

```python
email = "admin@test.ca"
```

and test again.

---

### Task 9 — Clean and validate

Use your functions:

- `clean_email(email)`
- `looks_valid(email)`

Store:

```python
email = "  ADMIN@Test.ca  "
```

Clean it first.

Then check if it looks valid.

Print:

- the original email
- the cleaned email
- `"valid-looking"` or `"invalid"`

---

### Task 10 — Full email breakdown function practice

Use your functions:

- `clean_email(email)`
- `looks_valid(email)`
- `get_username(email)`
- `get_domain(email)`

Store:

```python
email = "  USER@GMAIL.com  "
```

Then:

- clean the email
- check if it looks valid
- if valid, print username and domain
- otherwise print `"invalid email"`

---

### Task 11 — Function inside loop

Use:

```python
emails = ["  A@GMAIL.com  ", "bademail.com", "user@test.ca"]
```

Write or reuse:

```python
clean_email(email)
looks_valid(email)
```

Loop through the emails.

For each email:

- clean it
- print `"valid-looking: EMAIL"` if it looks valid
- print `"invalid: EMAIL"` otherwise

---

### Task 12 — Extract domains from a list

Use:

```python
emails = ["a@gmail.com", "bademail.com", "c@test.ca", "admin@site.org"]
```

Write or reuse:

```python
looks_valid(email)
get_domain(email)
```

Loop through the emails.

For each valid-looking email:

- print the domain

For invalid emails:

- print `"invalid email"`

---

### Task 13 — Large deal function

Write a function called `is_large_deal(amount)`.

It should return `True` if the amount is greater than `10000`.

Test it with:

- `8000`
- `12000`
- `25000`

---

### Task 14 — Paid client function

Write a function called `is_paid_client(status)`.

It should return `True` if the status is `"paid"`.

Test it with:

- `"trial"`
- `"paid"`
- `"expired"`

---

### Task 15 — Format client name

Write a function called `format_client_name(name)`.

It should:

- remove spaces around the name
- convert it to uppercase
- return the result

Test with:

```python
"  cbc  "
" DoorDash "
"smallco"
```

---

### Task 16 — Gmail checker

Write a function called `is_gmail(email)`.

It should:

- clean the email
- return `True` if `"gmail"` is in the cleaned email
- return `False` otherwise

Test with:

```python
"A@GMAIL.com"
"b@yahoo.com"
" c@gmail.com "
```

---

### Task 17 — Reusable mini email report

Create these functions:

```python
clean_email(email)
looks_valid(email)
get_username(email)
get_domain(email)
```

Use:

```python
emails = ["  ADMIN@CBC.ca  ", "bademail.com", "user@test.ca", "SALES@SmallCo.com"]
```

Loop through the emails.

For each email:

- clean it
- if valid:
  - print username
  - print domain
- otherwise:
  - print `"invalid email"`

---

### Task 18 — Count valid emails with a function

Use:

```python
emails = ["a@gmail.com", "bademail.com", "c@test.ca", "hello.com", "admin@site.org"]
```

Write or reuse:

```python
looks_valid(email)
```

Create `valid_count = 0`.

Loop through emails.

If `looks_valid(email)` returns `True`, add `1` to the count.

Print the final count.

---

### Task 19 — Mini account summary with functions

Create these functions:

```python
format_client_name(name)
clean_email(email)
looks_valid(email)
```

Use:

```python
client_name = "  cbc  "
email = " ADMIN@CBC.ca "
status = "paid"
```

Print:

- formatted client name
- cleaned email
- whether the email is valid-looking
- whether the status means paid client

---

### Task 20 — Challenge: function-based email inspector

Create these functions:

- `clean_email(email)`
- `looks_valid(email)`
- `get_username(email)`
- `get_domain(email)`
- `is_gmail(email)`

Use:

```python
emails = ["  A@GMAIL.com  ", "bademail.com", "user@test.ca", "contact@yahoo.com"]
```

Loop through the emails.

For each email:

- clean it
- check if it looks valid
- if valid:
  - print cleaned email
  - print username
  - print domain
  - print whether it is Gmail
- if invalid:
  - print `"invalid email"`

---

## Review and explain-back

Ask the student to explain in simple words:

- What is a function?
- Why do functions help us?
- What does `def` mean?
- What is a function name?
- What is a parameter?
- What is an argument?
- What does it mean to call a function?
- Why do we use parentheses when calling a function?
- What does `return` do?
- What is the difference between `print()` and `return`?
- Why is a function call also an expression?
- What value comes back from `clean_email("  A@GMAIL.com  ")`?
- What value comes back from `looks_valid("bademail.com")`?
- Why should functions usually do one small clear job?
- How can we reuse the same function with many different emails?

### Explain-back prompts

Ask her to talk through these step by step:

1. What happens here?

```python
def greet(name):
    print(f"Hello {name}")

greet("Dominika")
```

2. What happens here?

```python
def clean_email(email):
    return email.strip().lower()

clean = clean_email("  A@GMAIL.com  ")
print(clean)
```

3. What is the difference between these?

```python
def show_email(email):
    print(email)
```

and:

```python
def get_email(email):
    return email
```

4. What does this return?

```python
def looks_valid(email):
    return "@" in email

looks_valid("bademail.com")
```

5. Why does this work inside an `if`?

```python
if looks_valid(email):
    print("valid")
```

6. What happens step by step?

```python
def get_domain(email):
    at_pos = email.find("@")
    domain = email[at_pos + 1:]
    return domain
```

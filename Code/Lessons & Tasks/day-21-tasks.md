# Day 21 Tasks — Boolean logic: `elif`, `and`, `or`, `not`

## Instructions

Create a Python file named:

```text
day-21.py
```

Complete each task in the same file.

Use comments to separate your tasks:

```python
# Task 1 — Plan classifier
```

Run your file and make sure each task prints clear output.

---

## Task 1 — Plan classifier

Create a variable:

```python
plan = "trial"
```

Use `if / elif / else` to print:

- `Enterprise client` if the plan is `unlimited`
- `Small team client` if the plan is `8-user`
- `Trial client` if the plan is `trial`
- `Unknown plan` for anything else

Test your code with at least three different plan values.

---

## Task 2 — Valid-looking email check

Create a variable with an email.

Use `and` to check whether the email contains both:

- `@`
- `.`

Print either:

```text
Valid-looking email
```

or:

```text
Invalid-looking email
```

---

## Task 3 — Follow-up status check

Create a variable:

```python
status = "lead"
```

Use `or` to print `Needs follow-up` if the status is either:

- `trial`
- `lead`

Otherwise, print `No follow-up needed`.

Test it with at least three statuses.

---

## Task 4 — Known domain check

Create this list:

```python
known_domains = ["smallco.com", "cbc.ca", "newscorp.com"]
```

Create a variable:

```python
domain = "smallco.com"
```

Use `in` to check whether the domain is known.

Print either:

```text
Known client domain
```

or:

```text
Unknown domain
```

---

## Task 5 — Unknown domain check with `not in`

Use the same `known_domains` list.

Set:

```python
domain = "newlead.com"
```

Use `not in` to print:

```text
Potential trial or lead domain
```

if the domain is not in the known list.

Otherwise, print:

```text
Known client domain
```

---

## Task 6 — Helper variables for conditions

Create an email variable:

```python
email = "alice@smallco.com"
```

Create two boolean variables:

```python
has_at = "@" in email
has_dot = "." in email
```

Use `has_at and has_dot` in an `if` statement.

Print whether the email is valid-looking.

---

## Task 7 — Activity records: print valid-looking emails

Use this list:

```python
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@cbc.ca", "date": "2026-04-01"},
    {"email": "demo@newlead.com", "date": "2026-04-02"},
    {"email": "bad-email", "date": "2026-04-02"}
]
```

Loop through the records.

Print only emails that contain both `@` and `.`.

---

## Task 8 — Activity records: known vs unknown domains

Use this helper function:

```python
def get_domain(email):
    return email[email.find("@") + 1:]
```

Use this list:

```python
known_domains = ["smallco.com", "cbc.ca"]
```

Loop through `usage_records`.

For each valid-looking email:

- extract the domain
- print `Known: domain` if the domain is in `known_domains`
- print `Unknown: domain` if the domain is not in `known_domains`

Skip invalid-looking emails.

---

## Task 9 — Client plan report

Use this list:

```python
clients = [
    {"name": "SmallCo", "plan": "8-user", "primary_domain": "smallco.com"},
    {"name": "CBC", "plan": "unlimited", "primary_domain": "cbc.ca"},
    {"name": "Demo Lead", "plan": "trial", "primary_domain": "newlead.com"}
]
```

Loop through the clients.

Use `if / elif / else` to print a message for each client:

- unlimited plan → `Enterprise client`
- 8-user plan → `Small team client`
- trial plan → `Trial client`
- anything else → `Unknown plan`

Include the client name in the printed message.

Example output:

```text
SmallCo: Small team client
```

---

## Task 10 — Mini boolean activity report

Use `usage_records` and `known_domains` again.

Print three sections:

```text
Valid-looking emails:
...

Known domains:
...

Unknown domains:
...
```

Rules:

- valid-looking emails must contain both `@` and `.`
- known domains must be in the `known_domains` list
- unknown domains must not be in the `known_domains` list
- skip invalid-looking emails

Keep your code readable by using helper variables like:

```python
has_at = "@" in email
has_dot = "." in email
```

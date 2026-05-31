# Day 14 Tasks — Dictionaries: Small Records with Labels

Complete these tasks in your submission file.

Suggested file name:

```text
submissions/YOUR_NAME/day-14.py
```

Use comments to label each task:

```python
# Task 1 — One client record
```

---

## Task 1 — One client record

Create one dictionary called `client` with these keys:

- `name`
- `plan`
- `contact_email`

Use any realistic values.

Print each value separately.

---

## Task 2 — One usage record

Create one dictionary called `usage` with these keys:

- `email`
- `date`
- `product`

Print each value separately.

---

## Task 3 — Mini description

Create a dictionary:

```python
client = {
    "name": "SmallCo",
    "plan": "trial"
}
```

Print a sentence like:

```text
SmallCo is on a trial plan.
```

Use an f-string and values from the dictionary.

---

## Task 4 — Add a missing email

Start with:

```python
client = {
    "name": "SmallCo",
    "plan": "trial"
}
```

Add a new key called `contact_email` with value:

```python
"owner@smallco.com"
```

Print the final dictionary.

---

## Task 5 — Change the plan

Start with:

```python
client = {
    "name": "SmallCo",
    "plan": "trial"
}
```

Change the plan from `"trial"` to `"paid"`.

Print the final dictionary.

---

## Task 6 — Check if email exists

Start with:

```python
client = {
    "name": "SmallCo",
    "plan": "trial"
}
```

Use `if` to check whether the key `"contact_email"` exists in the dictionary.

If it exists, print the email.

Otherwise, print:

```text
contact email is missing
```

---

## Task 7 — Usage record domain

Create a usage dictionary:

```python
usage = {
    "email": "alice@smallco.com",
    "date": "2026-04-01"
}
```

Use the email from the dictionary.

Extract the domain using either:

- `.find()` and slicing
- or `.split("@")`

Print the domain.

Expected result:

```text
smallco.com
```

---

## Task 8 — Client with different value types

Create a dictionary called `client` with:

- `name` as a string
- `plan` as a string
- `max_users` as an integer
- `active` as a boolean

Print all four values.

---

## Task 9 — Simple status check

Create a dictionary:

```python
client = {
    "name": "SmallCo",
    "plan": "trial"
}
```

Use `if / else`:

- if the plan is `"trial"`, print `"trial client"`
- otherwise, print `"not trial"`

Use the value from the dictionary, not a separate variable.

---

## Task 10 — Mini account card

Create a dictionary called `client` with:

- `name`
- `plan`
- `primary_domain`
- `contact_email`

Print a small account card like this:

```text
Client: SmallCo
Plan: trial
Domain: smallco.com
Contact: owner@smallco.com
```

Use dictionary values in the printed lines.

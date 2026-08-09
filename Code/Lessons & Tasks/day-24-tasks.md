# Day 24 Tasks — Modules and helper functions

## Instructions

For Day 24, create two Python files:

```text
helpers.py
main.py
```

Run the program using:

```text
python main.py
```

Use comments in `main.py` to separate the tasks.

---

## Task 1 — Create `helpers.py`

Create a file called:

```text
helpers.py
```

Add this function:

```python
def get_domain(email):
    return email[email.find("@") + 1:]
```

---

## Task 2 — Import `get_domain()` in `main.py`

Create a file called:

```text
main.py
```

Import the function:

```python
from helpers import get_domain
```

Use it to print the domain from:

```python
"alice@smallco.com"
```

---

## Task 3 — Add `normalize_email()`

In `helpers.py`, add this function:

```python
def normalize_email(email):
    return email.strip().lower()
```

In `main.py`, import it and use it on:

```python
"  Bob@CBC.ca  "
```

Print the cleaned email.

---

## Task 4 — Use both helper functions together

In `main.py`:

1. Start with this email:

```python
email = "  Demo@NewLead.com  "
```

2. Clean the email using `normalize_email()`.
3. Extract the domain using `get_domain()`.
4. Print both the cleaned email and the domain.

---

## Task 5 — Add `is_valid_email()`

In `helpers.py`, add:

```python
def is_valid_email(email):
    return "@" in email and "." in email
```

In `main.py`, import it and test it with:

```python
"alice@smallco.com"
"bad-email"
```

Print the results.

---

## Task 6 — Add JSON helper functions

In `helpers.py`, add:

```python
import json


def load_json(filename):
    with open(filename, "r") as file:
        return json.load(file)


def save_json(filename, data):
    with open(filename, "w") as file:
        json.dump(data, file, indent=2)
```

Make sure `import json` is at the top of `helpers.py`.

---

## Task 7 — Save usage records using helper function

In `main.py`, import `save_json`.

Create this data:

```python
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-01"},
    {"email": "tom@trialdomain.com", "date": "2026-04-02"}
]
```

Use `save_json()` to save it to:

```text
usage.json
```

---

## Task 8 — Load usage records using helper function

In `main.py`, import `load_json`.

Load `usage.json`.

Loop through the records and print each email.

---

## Task 9 — Print domains from loaded records

Load `usage.json`.

For each record:

1. Get the email.
2. Use `get_domain()` to extract the domain.
3. Print the domain.

---

## Task 10 — Mini helper-based report

Using `helpers.py` and `main.py`, print a small report like:

```text
Total records: 3
Domains:
smallco.com
smallco.com
trialdomain.com
```

Use:

- `load_json()`
- `get_domain()`
- `len()`

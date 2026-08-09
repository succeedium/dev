# Day 24 — Modules and helper functions

## Main goal

Learn how to split reusable code into helper files.

By the end of this lesson, students should understand that:

- A module is a Python file that can be imported by another Python file.
- Helper functions should go into a helper file when they are reused many times.
- `main.py` should contain the main program flow.
- `helpers.py` can contain reusable functions like `get_domain()` and `load_json()`.

This day helps prepare for the final TeamOne Client Activity Hub app.

---

## 1. Why split code into files?

So far, most programs used one Python file.

That is okay for small exercises.

But real programs become easier to manage when we split them into smaller files.

Example project:

```text
teamone_activity_hub/
  main.py
  helpers.py
  usage.json
  clients.json
```

`main.py` is where the program starts.

`helpers.py` stores reusable helper functions.

---

## 2. Create a helper function

In one file, we might have this function:

```python
def get_domain(email):
    return email[email.find("@") + 1:]
```

This function is useful in many places.

So it is a good candidate for `helpers.py`.

---

## 3. Create `helpers.py`

Create a file called:

```text
helpers.py
```

Add this code:

```python
def get_domain(email):
    return email[email.find("@") + 1:]


def normalize_email(email):
    return email.strip().lower()
```

Now `helpers.py` contains reusable functions.

---

## 4. Import helper functions into `main.py`

Create another file called:

```text
main.py
```

Add this code:

```python
from helpers import get_domain, normalize_email

email = "  Alice@SmallCo.com  "
clean_email = normalize_email(email)
domain = get_domain(clean_email)

print(clean_email)
print(domain)
```

When you run `main.py`, Python imports the functions from `helpers.py`.

---

## 5. Important import rule

This works:

```python
from helpers import get_domain
```

This does not work:

```python
from helpers import get_domain()
```

When importing, use the function name without parentheses.

Parentheses are only used when calling the function.

---

## 6. Another import style

You can also import the whole helper module:

```python
import helpers

email = "alice@smallco.com"
print(helpers.get_domain(email))
```

This style uses the file name before the function name:

```python
helpers.get_domain(email)
```

For this course, we will mostly use:

```python
from helpers import get_domain
```

It is simpler for beginners.

---

## 7. Add JSON helper functions

Since the project uses JSON, we can create helper functions for loading and saving data.

In `helpers.py`:

```python
import json


def load_json(filename):
    with open(filename, "r") as file:
        return json.load(file)


def save_json(filename, data):
    with open(filename, "w") as file:
        json.dump(data, file, indent=2)
```

Then in `main.py`:

```python
from helpers import load_json

records = load_json("usage.json")

for record in records:
    print(record["email"])
```

Now the main file is cleaner.

---

## 8. What belongs in helpers?

Good functions for `helpers.py`:

```python
get_domain(email)
normalize_email(email)
load_json(filename)
save_json(filename, data)
is_valid_email(email)
```

These are reusable.

They can be used in many tasks.

---

## 9. What belongs in main?

The main file should usually contain:

- the main program flow
- loading the project data
- calling helper functions
- printing reports
- asking the user for choices later

Example:

```python
from helpers import get_domain, load_json

records = load_json("usage.json")

for record in records:
    email = record["email"]
    domain = get_domain(email)
    print(domain)
```

---

## 10. Common mistake: running the wrong file

If your project has `helpers.py` and `main.py`, usually you run:

```text
python main.py
```

Do not run `helpers.py` unless you are only testing helper functions.

`helpers.py` is like a toolbox.

`main.py` is the actual program.

---

# Drills

## Drill 1 — What is a module?

Answer in your own words:

```text
What is a Python module?
```

---

## Drill 2 — What belongs in helpers?

Which of these should probably go in `helpers.py`?

```text
get_domain(email)
normalize_email(email)
print the final report title
load_json(filename)
```

---

## Drill 3 — Import without parentheses

Fix this import:

```python
from helpers import get_domain()
```

---

## Drill 4 — Predict output

`helpers.py`:

```python
def get_domain(email):
    return email[email.find("@") + 1:]
```

`main.py`:

```python
from helpers import get_domain

print(get_domain("alice@smallco.com"))
```

Predict the output.

---

## Drill 5 — Normalize email

`helpers.py`:

```python
def normalize_email(email):
    return email.strip().lower()
```

`main.py`:

```python
from helpers import normalize_email

print(normalize_email("  Bob@CBC.ca  "))
```

Predict the output.

---

## Drill 6 — Import whole module

Fill in the missing part:

```python
import helpers

print(__________.get_domain("tom@test.ca"))
```

---

## Drill 7 — Helper function call

What is the difference between defining a function and calling a function?

Use this example:

```python
def get_domain(email):
    return email[email.find("@") + 1:]

get_domain("alice@smallco.com")
```

---

## Drill 8 — Load JSON helper

What does this function return?

```python
def load_json(filename):
    with open(filename, "r") as file:
        return json.load(file)
```

---

## Drill 9 — Main file or helper file?

For each item, choose `main.py` or `helpers.py`:

```text
Function that extracts email domain
Code that prints the final report
Function that loads JSON
Code that asks user for menu choice
```

---

## Drill 10 — Explain the toolbox idea

Explain why `helpers.py` is like a toolbox.

---

# Review and explain-back

By the end of Day 24, students should be able to answer:

1. What is a module?
2. Why do we use `helpers.py`?
3. What does `from helpers import get_domain` do?
4. Why do we not use parentheses when importing a function?
5. What kind of code belongs in `helpers.py`?
6. What kind of code belongs in `main.py`?

---

# Coaching hints

- Keep the first module example very small. Too many files too soon can feel confusing.
- Make sure `helpers.py` and `main.py` are in the same folder.
- Reinforce that importing a function is different from calling a function.
- If students get `ModuleNotFoundError`, check the file name, folder, and spelling.
- Use the phrase: `helpers.py` stores tools; `main.py` uses tools.
- Do not introduce packages or folder-based imports yet.

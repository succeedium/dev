# Day 21 — Boolean logic: `elif`, `and`, `or`, `not`

## Main goal

Today you will make your `if` statements more powerful.

So far, you have used simple conditions like:

```python
if "@" in email:
    print("Looks valid")
```

Today you will learn how to handle more realistic decisions:

- `elif` — check another condition if the first one was false
- `and` — both conditions must be true
- `or` — at least one condition must be true
- `not` — reverse a condition

These are very useful for checking emails, filtering activity records, and building reports.

---

## Part 1 — Review: a simple `if / else`

```python
email = "alice@smallco.com"

if "@" in email:
    print("This looks like an email")
else:
    print("This does not look like an email")
```

The condition after `if` must become either `True` or `False`.

```python
print("@" in email)
```

Python checks the condition first. Then it decides which block to run.

---

## Part 2 — `elif`: another condition

`elif` means: **else if**.

Use it when you want to check more than two possibilities.

```python
plan = "trial"

if plan == "unlimited":
    print("Enterprise client")
elif plan == "8-user":
    print("Small team client")
elif plan == "trial":
    print("Trial client")
else:
    print("Unknown plan")
```

Python checks from top to bottom:

1. Is `plan == "unlimited"` true?
2. If not, is `plan == "8-user"` true?
3. If not, is `plan == "trial"` true?
4. If none are true, run `else`.

Only one branch runs.

---

## Part 3 — `and`: both conditions must be true

Use `and` when two conditions both need to be true.

```python
email = "alice@smallco.com"

if "@" in email and "." in email:
    print("Valid-looking email")
else:
    print("Invalid-looking email")
```

This means:

```text
The email must contain @
AND
The email must contain .
```

Both sides must be true.

---

## Part 4 — `or`: at least one condition must be true

Use `or` when either condition is acceptable.

```python
plan = "trial"

if plan == "trial" or plan == "lead":
    print("Not a paid client yet")
else:
    print("Paid or other client")
```

This means:

```text
If plan is trial
OR
If plan is lead
```

At least one side must be true.

---

## Part 5 — `not`: reverse a condition

Use `not` to reverse a condition.

```python
email = "bad-email"

if not "@" in email:
    print("Missing @ symbol")
```

This is easier to read like this:

```python
if "@" not in email:
    print("Missing @ symbol")
```

For membership checks, prefer `not in` because it reads naturally.

---

## Part 6 — `in` and `not in` with lists

You already used `in` with strings:

```python
if "smallco" in email:
    print("SmallCo email")
```

You can also use `in` with lists:

```python
known_domains = ["smallco.com", "cbc.ca", "newscorp.com"]
domain = "smallco.com"

if domain in known_domains:
    print("Known client domain")
else:
    print("Unknown domain")
```

And `not in`:

```python
if domain not in known_domains:
    print("Unknown domain")
```

This will be very important for the TeamOne Client Activity Hub.

---

## Part 7 — Boolean logic with activity records

```python
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@cbc.ca", "date": "2026-04-01"},
    {"email": "demo@newlead.com", "date": "2026-04-02"},
    {"email": "bad-email", "date": "2026-04-02"}
]

known_domains = ["smallco.com", "cbc.ca"]
```

Helper function:

```python
def get_domain(email):
    return email[email.find("@") + 1:]
```

Print only valid-looking emails:

```python
for record in usage_records:
    email = record["email"]

    if "@" in email and "." in email:
        print(email)
```

Print unknown domains:

```python
for record in usage_records:
    email = record["email"]

    if "@" in email:
        domain = get_domain(email)

        if domain not in known_domains:
            print(domain)
```

This combines:

- loops
- dictionaries
- helper functions
- `if`
- `and`
- `not in`

---

## Part 8 — Keep conditions readable

Avoid very long conditions at first:

```python
if "@" in record["email"] and "." in record["email"] and get_domain(record["email"]) not in known_domains:
    print(record["email"])
```

Better beginner version:

```python
email = record["email"]
has_at = "@" in email
has_dot = "." in email

if has_at and has_dot:
    domain = get_domain(email)

    if domain not in known_domains:
        print(email)
```

Small steps are easier to debug.

---

# Drills

## Drill 1 — Predict `elif`

Predict the output.

```python
plan = "8-user"

if plan == "unlimited":
    print("A")
elif plan == "8-user":
    print("B")
elif plan == "trial":
    print("C")
else:
    print("D")
```

---

## Drill 2 — Change the plan

Use the same code as Drill 1, but test these values one at a time:

```python
plan = "unlimited"
plan = "trial"
plan = "unknown"
```

Write down which branch runs each time.

---

## Drill 3 — Predict `and`

```python
email = "alice@smallco.com"

if "@" in email and "." in email:
    print("Valid-looking")
else:
    print("Invalid-looking")
```

Now try:

```python
email = "bad-email"
email = "person@example"
email = "person.example.com"
```

---

## Drill 4 — Predict `or`

```python
plan = "lead"

if plan == "trial" or plan == "lead":
    print("Follow up")
else:
    print("No follow up")
```

Try with:

```python
plan = "trial"
plan = "unlimited"
```

---

## Drill 5 — Use `not in`

Predict the output.

```python
known_domains = ["smallco.com", "cbc.ca"]
domain = "newlead.com"

if domain not in known_domains:
    print("Unknown domain")
else:
    print("Known domain")
```

---

## Drill 6 — Fix the syntax

Fix the broken code.

```python
plan = "trial"

if plan = "trial":
    print("Trial")
elif plan = "unlimited":
    print("Unlimited")
```

---

## Drill 7 — Fix the boolean logic

This code has a logic problem.

```python
email = "bad-email"

if "@" and "." in email:
    print("Valid-looking")
else:
    print("Invalid-looking")
```

Rewrite the condition so it correctly checks whether the email contains both `@` and `.`.

---

## Drill 8 — Store conditions in variables

Rewrite this using `has_at` and `has_dot` variables.

```python
email = "alice@smallco.com"

if "@" in email and "." in email:
    print("Valid-looking")
```

---

## Drill 9 — Unknown domain check

Trace the code.

```python
known_domains = ["smallco.com", "cbc.ca"]
email = "demo@newlead.com"

domain = email[email.find("@") + 1:]

if domain not in known_domains:
    print("Unknown")
else:
    print("Known")
```

What is the value of `domain`?
Which branch runs?

---

## Drill 10 — Readable condition practice

Take this condition:

```python
if "@" in email and "." in email:
```

Explain it in plain English.

Then take this condition:

```python
if domain not in known_domains:
```

Explain it in plain English.

---

# Review and explain-back

By the end of Day 21, you should be able to answer these questions:

1. What does `elif` mean?
2. Why does only one branch of an `if / elif / else` block run?
3. What does `and` mean?
4. What does `or` mean?
5. What does `not in` mean?
6. How is `in` with a list different from `in` with a string?
7. Why is it helpful to store conditions in variables like `has_at`?
8. How can boolean logic help us find unknown TeamOne activity domains?

Explain-back prompt:

```text
A condition is an expression that becomes True or False.
I can use elif to check another possibility.
I can use and when both conditions must be true.
I can use or when either condition is enough.
I can use not in to check that a value is missing from a list.
```

---

# Coaching hints

- Keep this day practical. Do not turn it into a formal logic lesson.
- Make students predict results before running code.
- If `and` / `or` feels confusing, use plain English examples first.
- Spend extra time on the common mistake: `if "@" and "." in email:`.
- Encourage helper variables like `has_at`, `has_dot`, and `is_known_domain`.
- Keep conditions short and readable.
- Do not introduce complex nested conditions unless needed.
- Use TeamOne examples: trial, paid, known domain, unknown domain.

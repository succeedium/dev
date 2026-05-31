# Day 14 — Dictionaries: Small Records with Labels

## Main goal

Learn how dictionaries store related information using labels called **keys**. Use dictionaries to represent small records such as a client, usage event, or account.

By the end of this lesson, students should understand:

- a dictionary stores values with labels
- dictionaries use `{}` braces
- each item has a `key: value` pair
- values are accessed by key, not by position
- dictionaries are useful for records like clients and usage events

---

## Guided lesson

So far, we used separate variables:

```python
client_name = "SmallCo"
client_plan = "trial"
client_email = "owner@smallco.com"
```

This works, but the values are separate. They belong together, but Python does not know that.

A dictionary lets us group related values together:

```python
client = {
    "name": "SmallCo",
    "plan": "trial",
    "email": "owner@smallco.com"
}
```

This dictionary is one variable called `client`, but it stores several labeled values.

A dictionary uses **key-value pairs**:

```python
"name": "SmallCo"
```

- `"name"` is the key
- `"SmallCo"` is the value

You can think of keys as labels.

---

## Reading values from a dictionary

To read a value, use the key inside square brackets:

```python
client = {
    "name": "SmallCo",
    "plan": "trial",
    "email": "owner@smallco.com"
}

print(client["name"])
print(client["plan"])
print(client["email"])
```

Important:

- lists use indexes like `[0]`, `[1]`, `[2]`
- dictionaries use keys like `["name"]`, `["plan"]`, `["email"]`

Compare:

```python
clients = ["CBC", "SmallCo", "News Corp"]
print(clients[1])
```

This gets the item by position.

Now compare:

```python
client = {"name": "SmallCo", "plan": "trial"}
print(client["name"])
```

This gets the value by label.

---

## Braces `{}` finally have a job

Earlier, we said:

- `()` are usually for calling functions and methods
- `[]` are for selecting items or slicing
- `{}` are for dictionaries later

Today is that “later.”

Dictionaries use braces:

```python
client = {"name": "SmallCo", "plan": "trial"}
```

Inside the braces, we write key-value pairs:

```python
"key": "value"
```

Example:

```python
usage = {
    "email": "name@gmail.com",
    "date": "2026-04-01"
}

print(usage["email"])
print(usage["date"])
```

This is a small usage record.

---

## Dictionaries are useful for records

A record is a group of related information.

A client record:

```python
client = {
    "name": "SmallCo",
    "plan": "8-user",
    "primary_domain": "smallco.com",
    "active": True
}
```

A usage record:

```python
usage = {
    "email": "alice@smallco.com",
    "date": "2026-04-01",
    "product": "TeamOne"
}
```

A contact record:

```python
contact = {
    "name": "Alice",
    "email": "alice@smallco.com",
    "role": "Finance Manager"
}
```

Dictionaries are very useful for the TeamOne Client Activity Hub project because each usage event or client can be stored as a labeled record.

---

## Adding or changing dictionary values

You can add a new key:

```python
client = {
    "name": "SmallCo",
    "plan": "trial"
}

client["email"] = "owner@smallco.com"

print(client)
```

You can also change an existing value:

```python
client = {
    "name": "SmallCo",
    "plan": "trial"
}

client["plan"] = "paid"

print(client)
```

Same bracket idea, but with a key instead of an index.

---

## Checking if a key exists

Before reading a key, we can check whether the key exists:

```python
client = {
    "name": "SmallCo",
    "plan": "trial"
}

if "email" in client:
    print(client["email"])
else:
    print("email is missing")
```

This is similar to earlier checks:

```python
if "@" in email:
```

But now we are checking if a key exists in a dictionary.

This will help avoid errors later.

---

## Dictionary values can be different types

A dictionary can store strings, numbers, booleans, and other values:

```python
client = {
    "name": "SmallCo",
    "plan": "8-user",
    "max_users": 8,
    "active": True
}

print(client["name"])
print(client["max_users"])
print(client["active"])
```

For now, keep dictionaries simple and readable.

---

## Common beginner mistakes

Wrong: using list brackets to build a dictionary.

```python
client = ["name": "SmallCo", "plan": "trial"]
```

Correct:

```python
client = {"name": "SmallCo", "plan": "trial"}
```

Wrong: using `=` inside a dictionary.

```python
client = {"name" = "SmallCo"}
```

Correct:

```python
client = {"name": "SmallCo"}
```

Wrong: reading a key without quotes.

```python
print(client[name])
```

Correct:

```python
print(client["name"])
```

Unless `name` is a variable, dictionary keys written as text need quotes.

---

## Drills

### Drill 1 — Read values

Predict the output:

```python
client = {
    "name": "SmallCo",
    "plan": "trial",
    "email": "owner@smallco.com"
}

print(client["name"])
print(client["plan"])
print(client["email"])
```

---

### Drill 2 — Usage record

Predict the output:

```python
usage = {
    "email": "name@gmail.com",
    "date": "2026-04-01"
}

print(usage["email"])
print(usage["date"])
```

---

### Drill 3 — Dictionary or list?

For each value, say whether it is a list or a dictionary:

```python
clients = ["CBC", "SmallCo", "News Corp"]
```

```python
client = {"name": "SmallCo", "plan": "trial"}
```

```python
emails = ["a@gmail.com", "b@yahoo.com"]
```

```python
usage = {"email": "a@gmail.com", "date": "2026-04-01"}
```

---

### Drill 4 — Fix dictionary syntax

Correct these:

```python
client = ["name": "SmallCo", "plan": "trial"]
```

```python
client = {"name" = "SmallCo"}
```

```python
client = {name: "SmallCo", plan: "trial"}
```

```python
usage = {"email": "a@gmail.com" "date": "2026-04-01"}
```

---

### Drill 5 — Fill in the key

Fill in the missing keys:

```python
usage = {
    "email": "name@gmail.com",
    "date": "2026-04-01"
}

print(usage["_____"])
print(usage["_____"])
```

---

### Drill 6 — Add a new value

Predict the final dictionary:

```python
client = {
    "name": "SmallCo",
    "plan": "trial"
}

client["email"] = "owner@smallco.com"

print(client)
```

---

### Drill 7 — Change an existing value

Predict the final dictionary:

```python
client = {
    "name": "SmallCo",
    "plan": "trial"
}

client["plan"] = "paid"

print(client)
```

---

### Drill 8 — Check if a key exists

Predict the output:

```python
client = {
    "name": "SmallCo",
    "plan": "trial"
}

if "email" in client:
    print(client["email"])
else:
    print("email is missing")
```

---

### Drill 9 — Dictionary values with different types

Predict the output:

```python
client = {
    "name": "SmallCo",
    "max_users": 8,
    "active": True
}

print(client["name"])
print(client["max_users"])
print(client["active"])
```

---

### Drill 10 — Use dictionary value in an f-string

Predict the output:

```python
client = {
    "name": "SmallCo",
    "plan": "trial"
}

print(f'{client["name"]} is on a {client["plan"]} plan.')
```

---

## Review and explain-back

Ask the student to explain in simple words:

- What is a dictionary?
- What problem does a dictionary solve?
- What are keys?
- What are values?
- What are braces `{}` used for?
- What does `client["name"]` mean?
- How is a dictionary different from a list?
- When do we use an index like `[0]`?
- When do we use a key like `["email"]`?
- How can we add a new key-value pair?
- How can we change an existing value?
- Why is `"email" in client` useful?

---

## Explain-back prompts

Ask her to talk through these step by step:

### Prompt 1

```python
client = {
    "name": "SmallCo",
    "plan": "trial"
}

print(client["name"])
```

What is printed, and why?

### Prompt 2

```python
usage = {
    "email": "alice@smallco.com",
    "date": "2026-04-01"
}
```

What are the keys? What are the values?

### Prompt 3

```python
client["plan"] = "paid"
```

Does this add a new key or change an existing value?

### Prompt 4

```python
if "email" in client:
    print(client["email"])
else:
    print("email is missing")
```

What is this code checking?

---

## Coaching hints

- Keep saying: a dictionary is a labeled record.
- Compare lists and dictionaries often:
  - list = items by position
  - dictionary = values by label
- If she uses `[]` to build a dictionary, remind her that dictionaries use `{}`.
- If she uses `=` inside a dictionary, remind her that key-value pairs use `:`.
- If she forgets quotes around keys, ask whether the key is text or a variable.
- Avoid nested dictionaries for now.
- Avoid `.keys()`, `.values()`, and `.items()` for now unless she is very comfortable.
- Focus on reading and writing simple fields.
- Use project examples: client record, usage record, contact record.

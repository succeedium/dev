# Day 12 — Functions: inputs, outputs, and reuse

**Main goal:** Learn that functions are small reusable tools. Practice creating functions, passing values into them, returning values back, and reusing the same logic with different emails, clients, and lists.

---

## Guided lesson

Today introduces a very important idea: **functions**.

A function is like a small tool.

It can:

- take input
- do some work
- give back an output
- be reused many times

Simple mental model:

```python
input goes in -> function does work -> output comes back
```

We already used functions and methods many times:

```python
print("Hello")
input("Email: ")
len(emails)
email.strip()
email.lower()
email.find("@")
```

Today we will create our own functions.

---

## First simple function

Start with the simplest possible function:

```python
def say_hello():
    print("Hello")
```

This defines the function, but it does not run it yet.

To run it, we must **call** it:

```python
say_hello()
```

Full example:

```python
def say_hello():
    print("Hello")

say_hello()
```

Important:

- `def` means we are defining a function
- `say_hello` is the function name
- `()` are used to call the function
- the indented line belongs to the function
- the function runs only when we call it

---

## Function with input

Now let the function receive a value.

```python
def greet(name):
    print(f"Hello {name}")

greet("Dominika")
greet("Monika")
```

Explain:

- `name` is a **parameter**
- a parameter is like a temporary variable inside the function
- `"Dominika"` goes into `name`
- then `"Monika"` goes into `name`

Think of it like this:

```python
greet("Dominika")
```

means:

```python
name = "Dominika"
print(f"Hello {name}")
```

but only inside the function.

---

## Function that returns a value

Now create a function that gives a value back.

```python
def make_lower(text):
    return text.lower()

result = make_lower("HELLO")
print(result)
```

Explain:

- `text` receives `"HELLO"`
- `text.lower()` becomes `"hello"`
- `return` sends `"hello"` back
- the returned value is stored in `result`
- then we print `result`

Very important:

```python
make_lower("HELLO")
```

is an **expression**.

It becomes a value.

That means we can do either:

```python
result = make_lower("HELLO")
print(result)
```

or:

```python
print(make_lower("HELLO"))
```

For beginners, the first version is often easier because it uses a helper variable.

---

## `print()` vs `return`

This is one of the most important ideas today.

`print()` shows something on the screen.

`return` sends a value back to the code that called the function.

Compare:

```python
def show_lower(text):
    print(text.lower())

show_lower("HELLO")
```

This prints the result, but does not give it back to store.

Now compare:

```python
def get_lower(text):
    return text.lower()

clean_text = get_lower("HELLO")
print(clean_text)
```

This returns the result so we can store it and use it later.

Simple rule:

- use `print()` when you only want to show something
- use `return` when you want the function to give a value back

---

## Email helper function: clean email

Now use functions for something familiar.

```python
def clean_email(email):
    return email.strip().lower()

email = "  Name@GMAIL.com  "
clean = clean_email(email)

print(clean)
```

Explain:

- messy email goes in
- function strips spaces and lowercases it
- clean email comes back

Now call the same function with different emails:

```python
def clean_email(email):
    return email.strip().lower()

print(clean_email("  Name@GMAIL.com  "))
print(clean_email(" ADMIN@Test.ca "))
print(clean_email("user@yahoo.com"))
```

This is why functions are useful.

We write the logic once, then reuse it.

---

## Email helper function: looks valid

Now create a function that returns `True` or `False`.

```python
def looks_valid(email):
    return "@" in email

print(looks_valid("name@gmail.com"))
print(looks_valid("bademail.com"))
```

Explain:

- `"@" in email` becomes `True` or `False`
- the function returns that boolean value

This function can be used inside an `if` statement:

```python
def looks_valid(email):
    return "@" in email

email = "name@gmail.com"

if looks_valid(email):
    print("valid-looking email")
else:
    print("invalid email")
```

Important idea:

The function call:

```python
looks_valid(email)
```

becomes `True` or `False`.

Then `if` uses that result.

---

## Email helper function: get domain

Now create a function to get the domain part after `@`.

First simple version:

```python
def get_domain(email):
    at_pos = email.find("@")
    return email[at_pos + 1:]

print(get_domain("name@gmail.com"))
```

Step by step:

- email goes in
- find the position of `@`
- slice everything after `@`
- return the domain

Better beginner version with helper variables:

```python
def get_domain(email):
    at_pos = email.find("@")
    domain = email[at_pos + 1:]
    return domain

domain = get_domain("name@gmail.com")
print(domain)
```

This is easier to read.

Now create a username function:

```python
def get_username(email):
    at_pos = email.find("@")
    username = email[:at_pos]
    return username

print(get_username("name@gmail.com"))
```

---

## Combine functions

Now combine the helper functions:

```python
def clean_email(email):
    return email.strip().lower()

def looks_valid(email):
    return "@" in email

def get_username(email):
    at_pos = email.find("@")
    return email[:at_pos]

def get_domain(email):
    at_pos = email.find("@")
    return email[at_pos + 1:]

email = "  Name@GMAIL.com  "
clean = clean_email(email)

if looks_valid(clean):
    username = get_username(clean)
    domain = get_domain(clean)

    print(username)
    print(domain)
else:
    print("invalid email")
```

This combines many previous ideas:

- functions
- strings
- `.strip()`
- `.lower()`
- `if`
- `find()`
- slicing
- helper variables

---

## Use functions inside loops

Functions are especially useful with loops.

```python
def clean_email(email):
    return email.strip().lower()

emails = ["  A@GMAIL.com  ", "bademail.com", "user@test.ca"]

for email in emails:
    clean = clean_email(email)
    print(clean)
```

Now combine with validation:

```python
def clean_email(email):
    return email.strip().lower()

def looks_valid(email):
    return "@" in email

emails = ["  A@GMAIL.com  ", "bademail.com", "user@test.ca"]

for email in emails:
    clean = clean_email(email)

    if looks_valid(clean):
        print(f"valid-looking: {clean}")
    else:
        print(f"invalid: {clean}")
```

This is the beginning of reusable programming.

---

## Key rule for today

Do not write big functions yet.

Start with small functions that do one clear thing:

- clean an email
- check if email contains `@`
- get username
- get domain
- format a client name
- check if a plan is paid
- check if a domain is Gmail

Small functions are easier to test and reuse.

---

## Drills

### Drill 1 — Name the function parts

Look at this code:

```python
def greet(name):
    print(f"Hello {name}")

greet("Dominika")
```

Answer:

- What is the function name?
- What is the parameter?
- What value is passed into the function?
- Which line calls the function?
- Which line is inside the function?

---

### Drill 2 — Predict simple function output

```python
def say_hello():
    print("Hello")

say_hello()
say_hello()
```

Predict:

- what prints?
- how many times does it print?

---

### Drill 3 — Predict function with parameter

```python
def greet(name):
    print(f"Hello {name}")

greet("Monika")
greet("Dominika")
```

Predict the output.

---

### Drill 4 — Predict return value

```python
def make_lower(text):
    return text.lower()

result = make_lower("TEAMONE")
print(result)
```

Predict:

- what is returned?
- what is stored in `result`?
- what is printed?

---

### Drill 5 — Print vs return

Predict the outputs.

```python
def show_lower(text):
    print(text.lower())

show_lower("HELLO")
```

Now compare:

```python
def get_lower(text):
    return text.lower()

result = get_lower("HELLO")
print(result)
```

Explain the difference.

---

### Drill 6 — Function call as expression

Predict this:

```python
def make_upper(text):
    return text.upper()

print(make_upper("cbc"))
```

Now predict this:

```python
def make_upper(text):
    return text.upper()

client = make_upper("cbc")
print(client)
```

Why do both print `"CBC"`?

---

### Drill 7 — Clean email function

Predict the output:

```python
def clean_email(email):
    return email.strip().lower()

print(clean_email("  Name@GMAIL.com  "))
```

---

### Drill 8 — Store returned value

Predict the output:

```python
def clean_email(email):
    return email.strip().lower()

email = "  ADMIN@Test.ca  "
clean = clean_email(email)

print(email)
print(clean)
```

Explain why the original email did not change.

---

### Drill 9 — Boolean function

Predict the output:

```python
def looks_valid(email):
    return "@" in email

print(looks_valid("name@gmail.com"))
print(looks_valid("bademail.com"))
```

---

### Drill 10 — Boolean function inside `if`

Predict the output:

```python
def looks_valid(email):
    return "@" in email

email = "bademail.com"

if looks_valid(email):
    print("valid-looking")
else:
    print("invalid")
```

---

### Drill 11 — Domain function

Predict the output:

```python
def get_domain(email):
    at_pos = email.find("@")
    return email[at_pos + 1:]

print(get_domain("a@test.ca"))
```

---

### Drill 12 — Username function

Predict the output:

```python
def get_username(email):
    at_pos = email.find("@")
    return email[:at_pos]

print(get_username("a@test.ca"))
```

---

### Drill 13 — Combine clean and domain

Predict the output:

```python
def clean_email(email):
    return email.strip().lower()

def get_domain(email):
    at_pos = email.find("@")
    return email[at_pos + 1:]

email = "  USER@GMAIL.com  "
clean = clean_email(email)
domain = get_domain(clean)

print(clean)
print(domain)
```

---

### Drill 14 — Function inside loop

Predict the output:

```python
def clean_email(email):
    return email.strip().lower()

emails = ["  A@GMAIL.com  ", " B@YAHOO.com ", "c@Test.ca"]

for email in emails:
    clean = clean_email(email)
    print(clean)
```

---

### Drill 15 — Function with numbers

Predict the output:

```python
def is_large_deal(amount):
    return amount > 10000

print(is_large_deal(12000))
print(is_large_deal(8000))
```

---

### Drill 16 — Function with status

Predict the output:

```python
def is_paid_client(status):
    return status == "paid"

print(is_paid_client("paid"))
print(is_paid_client("trial"))
```

---

### Drill 17 — Fix function syntax mistakes

Correct these:

```python
def clean_email(email)
    return email.strip().lower()
```

```python
def clean_email(email):
return email.strip().lower()
```

```python
clean_email(email):
    return email.strip().lower()
```

```python
def clean_email:
    return email.strip().lower()
```

```python
def clean_email(email):
    email.strip().lower()
```

For the last one, explain what is missing.

---

### Drill 18 — Fill in missing pieces

```python
def get_username(email):
    at_pos = email.find("@")
    return email[:_____]
```

```python
def get_domain(email):
    at_pos = email.find("@")
    return email[_____ + 1:]
```

```python
def is_paid_client(status):
    return status == "_____"
```

```python
def clean_email(email):
    return email._____()._____()
```

### Coaching hints

- Keep saying: a function is a reusable mini-tool.
- Use the pattern:
  - input goes in
  - function does work
  - output comes back
- If she forgets the colon, point to the function header.
- If she forgets indentation, explain that indented lines belong to the function.
- If she forgets `return`, ask:
  - does the function give anything back?
- If she uses `print()` instead of `return`, ask:
  - do we only want to show it?
  - or do we need to use the value later?
- Keep functions small.
- Avoid advanced topics like default arguments, recursion, or type hints for now.
- Encourage storing returned values in variables before using them in bigger expressions.
- If a function feels confusing, test it with one simple input first.

# Day 15 Lesson — Debugging Basics and Reading Errors

## Main goal

Learn how to read simple Python error messages and use small debugging habits to find problems faster.

By the end of this lesson, students should understand that errors are not failures. Errors are messages from Python that help explain what went wrong.

Today is not about memorizing every possible error. The goal is to learn a calm debugging process:

1. Read the last line of the error.
2. Look at the line number.
3. Identify the error type.
4. Check the code near that line.
5. Use `print()` to inspect values.
6. Fix one thing at a time.

---

## Guided lesson

When Python cannot run your code, it often gives an error message.

At first, error messages can look scary, but they usually contain useful clues.

A typical error message tells you:

- the file name
- the line number
- the type of error
- a short explanation

The most useful part is usually the **last line**.

Example:

```python
print(client_name)
```

If `client_name` was never created, Python may show something like:

```text
NameError: name 'client_name' is not defined
```

This means Python does not know what `client_name` is.

A good first question is:

> Did I create this variable before using it?

---

## Error 1 — `SyntaxError`

A `SyntaxError` means Python cannot understand the structure of the code.

Example:

```python
if "@" in email
    print("valid")
```

The problem is that the `if` line is missing a colon.

Correct version:

```python
if "@" in email:
    print("valid")
```

Common causes of `SyntaxError`:

- missing colon after `if`, `for`, `while`, or `def`
- missing quote
- missing closing bracket or parenthesis
- writing code in a way Python cannot understand

Example with a missing quote:

```python
email = "name@gmail.com
```

Correct version:

```python
email = "name@gmail.com"
```

---

## Error 2 — `NameError`

A `NameError` means Python does not recognize a variable or function name.

Example:

```python
print(clean_email)
```

If `clean_email` was never created, Python may show:

```text
NameError: name 'clean_email' is not defined
```

Correct version:

```python
email = "  Name@GMAIL.com  "
clean_email = email.strip().lower()
print(clean_email)
```

Common causes of `NameError`:

- variable was never created
- variable name was misspelled
- uppercase/lowercase mismatch
- function was called before it was defined

Example:

```python
client_name = "CBC"
print(clientname)
```

`client_name` and `clientname` are not the same variable.

---

## Error 3 — `TypeError`

A `TypeError` often means we are using the wrong kind of value for an operation.

Example:

```python
amount = 8000
print("Amount: " + amount)
```

Python cannot combine text and a number using `+` like this.

Better version using an f-string:

```python
amount = 8000
print(f"Amount: {amount}")
```

Another example:

```python
email = "name@gmail.com"
print(email["0"])
```

String indexes must be numbers, not strings.

Correct version:

```python
email = "name@gmail.com"
print(email[0])
```

---

## Error 4 — `IndexError`

An `IndexError` often means we are trying to access a list item or string position that does not exist.

Example:

```python
emails = ["a@gmail.com", "b@yahoo.com"]
print(emails[2])
```

This list has 2 items, but the indexes are:

- `0`
- `1`

There is no index `2`.

Correct version:

```python
emails = ["a@gmail.com", "b@yahoo.com"]
print(emails[1])
```

Important reminder:

```python
emails = ["a@gmail.com", "b@yahoo.com"]
print(len(emails))
```

The length is `2`, but the last index is `1`.

Last index is usually:

```python
len(emails) - 1
```

---

## Error 5 — `KeyError` preview

A `KeyError` happens with dictionaries when we ask for a key that does not exist.

This is only a preview because dictionaries will be covered more deeply soon.

Example:

```python
client = {"name": "SmallCo", "plan": "trial"}
print(client["email"])
```

There is no `"email"` key in this dictionary.

Correct version:

```python
client = {"name": "SmallCo", "plan": "trial", "email": "owner@smallco.com"}
print(client["email"])
```

For now, the main idea is:

> If Python says `KeyError`, check whether the dictionary actually has that key.

---

## Debugging with `print()`

One of the simplest debugging tools is `print()`.

If code is not doing what we expect, print the values.

Example:

```python
email = "  Name@GMAIL.com  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")

debug_message = f"DEBUG: clean_email={clean_email}, at_pos={at_pos}"
print(debug_message)
```

You can also print one value at a time:

```python
print("DEBUG email:", email)
print("DEBUG clean_email:", clean_email)
print("DEBUG at_pos:", at_pos)
```

A simple debugging habit:

```text
If you are confused, print the variable.
```

---

## Fix one thing at a time

Beginners often try to fix many things at once. That can make the program more confusing.

Better process:

1. Run the code.
2. Read the error.
3. Fix one error.
4. Run again.
5. Repeat.

Example broken code:

```python
emails = ["a@gmail.com", "b@yahoo.com"
for email in emails
    print(email)
```

This has more than one problem.

Fix the list first:

```python
emails = ["a@gmail.com", "b@yahoo.com"]
for email in emails
    print(email)
```

Then fix the missing colon:

```python
emails = ["a@gmail.com", "b@yahoo.com"]
for email in emails:
    print(email)
```

One fix at a time is easier.

---

## Drills

### Drill 1 — Identify the error type

Look at each example and say which error type is likely:

```python
print(client_name)
```

```python
if "@" in email
    print("valid")
```

```python
emails = ["a@gmail.com", "b@yahoo.com"]
print(emails[5])
```

```python
amount = 8000
print("Amount: " + amount)
```

Choices:

- `SyntaxError`
- `NameError`
- `TypeError`
- `IndexError`

---

### Drill 2 — Fix `SyntaxError`

Correct this code:

```python
email = "name@gmail.com"
if "@" in email
    print("valid")
```

Correct this code:

```python
clients = ["CBC", "SmallCo"
print(clients)
```

Correct this code:

```python
def clean_email(email)
    return email.strip().lower()
```

---

### Drill 3 — Fix `NameError`

Correct this code:

```python
email = "name@gmail.com"
print(clean_email)
```

Correct this code:

```python
client_name = "CBC"
print(clientname)
```

Correct this code:

```python
def get_domain(email):
    return email[email.find("@") + 1:]

print(domain("a@gmail.com"))
```

---

### Drill 4 — Fix `TypeError`

Correct this code:

```python
amount = 8000
print("Amount: " + amount)
```

Correct this code:

```python
email = "name@gmail.com"
print(email["0"])
```

Correct this code:

```python
count = 3
message = "Total records: " + count
print(message)
```

---

### Drill 5 — Fix `IndexError`

Correct this code:

```python
emails = ["a@gmail.com", "b@yahoo.com"]
print(emails[2])
```

Correct this code:

```python
clients = ["CBC", "SmallCo", "News Corp"]
print(clients[3])
```

Then answer:

- What is the length of the list?
- What is the last valid index?

---

### Drill 6 — Read the last line

For each fake error message, identify the important last line:

```text
Traceback (most recent call last):
  File "day15.py", line 4, in <module>
    print(clean_email)
NameError: name 'clean_email' is not defined
```

```text
Traceback (most recent call last):
  File "day15.py", line 7, in <module>
    print(emails[5])
IndexError: list index out of range
```

Say what Python is trying to tell you.

---

### Drill 7 — Debug with print

Add debug prints to this code:

```python
email = "  USER@GMAIL.com  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
domain = clean_email[at_pos + 1:]

print(domain)
```

Print:

- original email
- clean email
- at position
- domain

---

### Drill 8 — Fix one thing at a time

This code has several problems. Fix only one problem at a time.

```python
emails = ["a@gmail.com", "bademail.com", "c@test.ca"

for email in emails
if "@" in email:
print(email)
```

After each fix, run or mentally check the code again.

---

### Drill 9 — Explain the error in plain English

Explain each error in simple words:

- `SyntaxError`
- `NameError`
- `TypeError`
- `IndexError`
- `KeyError`

Use one sentence for each.

---

### Drill 10 — Choose the debugging move

For each situation, say what you would do first:

1. Python says a variable is not defined.
2. Python says list index out of range.
3. Python says invalid syntax.
4. The code runs, but prints the wrong domain.
5. The loop runs, but skips an email you expected to see.

Good answers may include:

- check spelling
- check line number
- check list length
- print intermediate values
- fix missing colon or bracket
- check indentation

---

## Review and explain-back

Ask the student to explain in simple words:

- Why are errors useful?
- What part of an error message should we usually read first?
- What is a `SyntaxError`?
- What is a `NameError`?
- What is a `TypeError`?
- What is an `IndexError`?
- What is a `KeyError`?
- Why is `print()` useful for debugging?
- Why is it better to fix one thing at a time?
- What does it mean to inspect a variable?
- What should you do if code runs but the result is wrong?

### Explain-back prompts

Ask her to talk through these step by step:

1. What is wrong here?

```python
if "@" in email
    print("valid")
```

2. What is wrong here?

```python
emails = ["a@gmail.com", "b@yahoo.com"]
print(emails[2])
```

3. What is wrong here?

```python
client_name = "CBC"
print(clientname)
```

4. How would you debug this?

```python
email = "  USER@GMAIL.com  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
domain = clean_email[at_pos + 1:]
print(domain)
```

### Coaching hints

- Keep the tone calm. Errors are part of programming.
- Have her read the last line of the error out loud.
- Ask: what type of error is this?
- Ask: what line number does Python mention?
- Encourage using `print("DEBUG:", value)` often.
- If there are many errors, fix one at a time.
- If code runs but gives the wrong answer, print intermediate variables.
- Do not introduce `try / except` yet. First teach how to understand and fix errors directly.

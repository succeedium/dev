# Day 13 — Comments, clean code, and readable programs

## Main goal

Learn how to make Python code easier to read, easier to debug, and easier to review. Practice using comments, meaningful variable names, small helper steps, and clear program sections.

Today is not about learning a hard new Python feature. It is about becoming a better beginner programmer.

By the end of this lesson, students should understand that code is not only for the computer. Code is also for people who need to read it later.

---

## Guided lesson

So far, we have learned many Python tools:

- variables
- strings
- string methods
- `if / else`
- lists
- loops
- list methods
- functions

Now the next important skill is writing code that is easy to understand.

A program can work and still be hard to read. Good programmers try to make code clear.

---

## 1. Comments

A comment is text in the code that Python ignores.

Comments start with `#`.

```python
# This is a comment
print("Hello")
```

Python runs this line:

```python
print("Hello")
```

Python ignores this line:

```python
# This is a comment
```

Comments help explain the code to humans.

Example:

```python
# Store the original email from the user
email = "  Name@GMAIL.com  "

# Clean the email before checking it
clean_email = email.strip().lower()

print(clean_email)
```

A good comment explains why the code is there or what step the code is doing.

---

## 2. Good comments vs unnecessary comments

Not every line needs a comment.

This comment is not very useful:

```python
# Print clean_email
print(clean_email)
```

The code already says that.

This comment is more useful:

```python
# Clean first so capital letters and spaces do not affect the check
clean_email = email.strip().lower()
```

Good comments help explain the thinking.

---

## 3. Meaningful variable names

Variable names should explain what the value means.

Less clear:

```python
x = "  Name@GMAIL.com  "
y = x.strip().lower()
z = y.find("@")
```

Better:

```python
original_email = "  Name@GMAIL.com  "
clean_email = original_email.strip().lower()
at_pos = clean_email.find("@")
```

The second version is easier to read because the names tell a story.

Good names:

```python
client_name = "SmallCo"
email = "admin@smallco.com"
clean_email = email.strip().lower()
domain = "smallco.com"
valid_count = 0
```

Avoid names like:

```python
a = "SmallCo"
b = "admin@smallco.com"
x = 0
```

Those names do not explain anything.

---

## 4. Use helper variables instead of giant expressions

Beginners often try to write everything in one line. That can be hard to understand.

Harder to read:

```python
print(email.strip().lower()[email.strip().lower().find("@") + 1:])
```

Better:

```python
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
domain = clean_email[at_pos + 1:]
print(domain)
```

This version is better because each line does one small step.

The pattern is:

1. clean the email
2. find `@`
3. extract the domain
4. print the domain

This is easier to debug because we can print each helper variable.

```python
print(clean_email)
print(at_pos)
print(domain)
```

---

## 5. Organize code into sections

For bigger tasks, separate the code into clear sections with comments.

Example:

```python
# -----------------------------
# Input data
# -----------------------------
email = "  Name@GMAIL.com  "

# -----------------------------
# Clean the data
# -----------------------------
clean_email = email.strip().lower()

# -----------------------------
# Extract username and domain
# -----------------------------
at_pos = clean_email.find("@")
username = clean_email[:at_pos]
domain = clean_email[at_pos + 1:]

# -----------------------------
# Output
# -----------------------------
print(username)
print(domain)
```

This makes the code feel more like a small program and less like random lines.

---

## 6. Keep functions small and clear

A function should usually do one clear job.

Good small functions:

```python
def clean_email(email):
    return email.strip().lower()


def looks_valid(email):
    return "@" in email


def get_domain(email):
    at_pos = email.find("@")
    return email[at_pos + 1:]
```

Each function has one clear purpose.

Try to avoid one function that does too many unrelated things.

Harder to understand:

```python
def do_everything(email):
    clean_email = email.strip().lower()
    at_pos = clean_email.find("@")
    domain = clean_email[at_pos + 1:]
    print(clean_email)
    print(domain)
```

This can work, but it is less reusable.

A better habit is to create small tools and combine them.

---

## 7. Print values to debug

When code is confusing, print intermediate values.

Example:

```python
email = "  Name@GMAIL.com  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
domain = clean_email[at_pos + 1:]

print("DEBUG clean_email:", clean_email)
print("DEBUG at_pos:", at_pos)
print("DEBUG domain:", domain)
```

Debug prints help answer:

- What value do I have right now?
- Did this line do what I expected?
- Where did the program start going wrong?

Later, professional programmers use more advanced tools too, but `print()` debugging is still very useful.

---

## 8. Clean code example

Here is a clean version of a small email inspector:

```python
# Day 13 example — clean email inspector

# Input data
email = "  Name@GMAIL.com  "

# Clean the email before checking it
clean_email = email.strip().lower()

# Check whether the email has @
if "@" in clean_email:
    at_pos = clean_email.find("@")
    username = clean_email[:at_pos]
    domain = clean_email[at_pos + 1:]

    print(f"Clean email: {clean_email}")
    print(f"Username: {username}")
    print(f"Domain: {domain}")
else:
    print("Invalid email")
```

This code is readable because:

- the variable names are meaningful
- the comments explain the steps
- the code uses helper variables
- the `if / else` block is clear
- the output is easy to understand

---

## Drills

### Drill 1 — Identify good variable names

Which names are clearer?

```python
x = "admin@cbc.ca"
email = "admin@cbc.ca"
```

```python
a = 0
valid_count = 0
```

```python
b = "smallco.com"
domain = "smallco.com"
```

Explain why the better names are easier to understand.

---

### Drill 2 — Add useful comments

Add comments to this code:

```python
email = "  Name@GMAIL.com  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
domain = clean_email[at_pos + 1:]
print(domain)
```

The comments should explain the main steps, not every tiny detail.

---

### Drill 3 — Remove unnecessary comments

Which comments are unnecessary?

```python
# Set email to a value
email = "admin@cbc.ca"

# Print email
print(email)

# Clean the email before checking the domain
clean_email = email.strip().lower()
```

Explain which comment is useful and why.

---

### Drill 4 — Break one long expression into steps

Rewrite this code using helper variables:

```python
print(email.strip().lower()[email.strip().lower().find("@") + 1:])
```

Use:

- `clean_email`
- `at_pos`
- `domain`

---

### Drill 5 — Organize code into sections

Add section comments to this code:

```python
email = "  Name@GMAIL.com  "
clean_email = email.strip().lower()
if "@" in clean_email:
    at_pos = clean_email.find("@")
    domain = clean_email[at_pos + 1:]
    print(domain)
else:
    print("invalid email")
```

Suggested sections:

- Input data
- Clean data
- Check and extract
- Output

---

### Drill 6 — Rename unclear variables

Rewrite this code with better names:

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

### Drill 7 — Add debug prints

Add debug prints after each important step:

```python
email = "  Name@GMAIL.com  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
domain = clean_email[at_pos + 1:]
```

Use labels like:

```python
print("DEBUG clean_email:", clean_email)
```

---

### Drill 8 — Clean up messy code

Improve this code so it is easier to read:

```python
e="  USER@Test.ca  "
c=e.strip().lower()
if "@" in c:
 p=c.find("@")
 print(c[p+1:])
```

Make it use:

- better variable names
- normal indentation
- comments
- helper variables

---

### Drill 9 — Explain the program in plain English

Read this code and explain what it does line by line:

```python
email = "  Sales@SmallCo.com  "
clean_email = email.strip().lower()

if "@" in clean_email:
    at_pos = clean_email.find("@")
    username = clean_email[:at_pos]
    domain = clean_email[at_pos + 1:]
    print(f"{username} uses domain {domain}")
else:
    print("Invalid email")
```

---

### Drill 10 — Small functions with clear names

Explain why these function names are good:

```python
def clean_email(email):
    return email.strip().lower()


def get_domain(email):
    at_pos = email.find("@")
    return email[at_pos + 1:]
```

Then suggest a better name for this function:

```python
def do_it(email):
    return "@" in email
```

---

## Review and explain-back

Ask the student to explain in simple words:

- What is a comment?
- Does Python run comments?
- What makes a comment useful?
- Why are meaningful variable names important?
- Why is `clean_email` better than `x`?
- Why are helper variables useful?
- Why is a giant one-line expression hard to debug?
- What does it mean to organize code into sections?
- How can `print()` help with debugging?
- Why should small functions usually do one clear job?
- What is the difference between code that works and code that is readable?

### Explain-back prompts

Ask her to explain these examples:

1. Why is this hard to understand?

```python
x = "  A@GMAIL.com  "
y = x.strip().lower()
z = y.find("@")
print(y[z+1:])
```

2. Why is this easier?

```python
email = "  A@GMAIL.com  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
domain = clean_email[at_pos + 1:]
print(domain)
```

3. What does this comment help explain?

```python
# Clean first so spaces and capital letters do not affect the check
clean_email = email.strip().lower()
```

4. Why might this function be reusable?

```python
def clean_email(email):
    return email.strip().lower()
```

## Coaching hints

- Keep the day light. This is about habits, not hard syntax.
- Praise readable code, not only correct code.
- If the student writes messy but working code, say: "Good, now let's make it easier to read."
- Encourage helper variables instead of long expressions.
- Ask her to explain the code in plain English.
- If she uses unclear names like `x`, ask what the value represents.
- If she writes comments for every obvious line, explain that comments should help the reader understand the purpose or step.
- Use this day to prepare for dictionaries, where readable keys and structure will matter even more.

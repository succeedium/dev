# Day 19 — Text files as datasets: one value per line

## Main goal

Use a text file as a simple growing dataset.

Yesterday, you learned how to write, read, and append to files. Today, you will treat a file like a very simple database:

```text
one line = one saved record
```

For now, each record will be one email address.

Example file: `email_dataset.txt`

```text
alice@smallco.com
bob@smallco.com
tom@trialdomain.com
support@cbc.ca
bad-email
```

By the end of this lesson, you should be able to:

- read many lines from a file
- clean each line with `.strip()`
- skip blank lines
- loop through a file dataset
- count records
- filter emails by domain
- extract domains from saved emails
- append new user input to grow the dataset

---

## 1. Why files can act like simple datasets

A Python list disappears when the program stops:

```python
emails = ["alice@smallco.com", "bob@smallco.com"]
```

But a file stays saved after the program ends.

```text
email_dataset.txt
```

That means your program can:

1. save new data into the file
2. run again later
3. read the old saved data back
4. add more records

This is not a real database yet, but it is the first step toward thinking like one.

---

## 2. Create a small email dataset file

Start by creating a file with several emails.

```python
with open("email_dataset.txt", "w") as file:
    file.write("alice@smallco.com\n")
    file.write("bob@smallco.com\n")
    file.write("tom@trialdomain.com\n")
    file.write("support@cbc.ca\n")
    file.write("bad-email\n")
```

Important reminder:

```python
"\n"
```

means new line.

Without it, all emails may be saved on one long line.

---

## 3. Read all lines from the file

```python
with open("email_dataset.txt", "r") as file:
    lines = file.readlines()

print(lines)
```

The result may look like this:

```python
['alice@smallco.com\n', 'bob@smallco.com\n', 'tom@trialdomain.com\n']
```

Each line still includes the new line character `\n`.

That is why we usually clean each line with `.strip()`.

---

## 4. Loop through lines and clean them

```python
with open("email_dataset.txt", "r") as file:
    lines = file.readlines()

for line in lines:
    email = line.strip()
    print(email)
```

Mental model:

```text
line = raw text from the file
email = cleaned value we want to use
```

Use helper variables. Do not try to do everything in one long line yet.

---

## 5. Skip blank lines

Sometimes a file may contain empty lines.

Example:

```text
alice@smallco.com

bob@smallco.com
```

A blank line becomes an empty string after `.strip()`.

```python
for line in lines:
    email = line.strip()

    if email == "":
        continue

    print(email)
```

`continue` means:

```text
Skip the rest of this loop iteration and move to the next line.
```

Keep this simple. We use it here only to skip empty lines.

---

## 6. Count saved records

```python
count = 0

for line in lines:
    email = line.strip()

    if email != "":
        count = count + 1

print(f"Total saved emails: {count}")
```

Remember:

```python
count = count + 1
```

means:

1. calculate the right side
2. store the new value back into `count`

---

## 7. Filter saved emails by domain

```python
for line in lines:
    email = line.strip()

    if "smallco.com" in email:
        print(email)
```

This is the same search/filter pattern you already used with lists.

Now the data comes from a file instead of being hardcoded in Python.

---

## 8. Check valid-looking emails

```python
for line in lines:
    email = line.strip()

    if "@" in email:
        print(f"Valid-looking: {email}")
    else:
        print(f"Invalid-looking: {email}")
```

This is not perfect email validation. It is just a beginner-friendly check.

---

## 9. Extract domains from saved emails

```python
for line in lines:
    email = line.strip()

    if "@" in email:
        at_pos = email.find("@")
        domain = email[at_pos + 1:]
        print(domain)
```

The `if "@" in email` check protects the slicing code from invalid-looking emails.

---

## 10. Add new input and then read the growing dataset

This simulates database growth.

```python
new_email = input("Enter a new email: ").strip().lower()

with open("email_dataset.txt", "a") as file:
    file.write(new_email + "\n")

with open("email_dataset.txt", "r") as file:
    lines = file.readlines()

print("Saved emails:")

for line in lines:
    email = line.strip()

    if email != "":
        print(email)
```

This pattern is important:

```text
input -> append to file -> read file -> loop through saved records
```

---

# Drills

## Drill 1 — Predict the saved file

What will be inside `email_dataset.txt` after this code runs?

```python
with open("email_dataset.txt", "w") as file:
    file.write("alice@smallco.com\n")
    file.write("bob@smallco.com\n")
```

---

## Drill 2 — Explain `readlines()`

```python
with open("email_dataset.txt", "r") as file:
    lines = file.readlines()

print(lines)
```

Explain what `lines` contains.

Is it a string or a list?

---

## Drill 3 — Clean file lines

Predict the output:

```python
line = "alice@smallco.com\n"
email = line.strip()
print(email)
```

---

## Drill 4 — Loop through saved emails

Explain this code line by line:

```python
for line in lines:
    email = line.strip()
    print(email)
```

What is `line`?

What is `email`?

---

## Drill 5 — Skip blanks

Predict which values will print:

```python
lines = ["alice@smallco.com\n", "\n", "bob@smallco.com\n"]

for line in lines:
    email = line.strip()

    if email == "":
        continue

    print(email)
```

---

## Drill 6 — Count records

Trace the value of `count` after each loop:

```python
lines = ["a@test.ca\n", "b@test.ca\n", "\n"]

count = 0

for line in lines:
    email = line.strip()

    if email != "":
        count = count + 1

print(count)
```

---

## Drill 7 — Filter by domain

What will print?

```python
lines = ["alice@smallco.com\n", "tom@trialdomain.com\n", "bob@smallco.com\n"]

for line in lines:
    email = line.strip()

    if "smallco.com" in email:
        print(email)
```

---

## Drill 8 — Valid-looking emails

What will print?

```python
emails = ["alice@smallco.com", "bad-email", "bob@cbc.ca"]

for email in emails:
    if "@" in email:
        print("valid-looking")
    else:
        print("invalid-looking")
```

---

## Drill 9 — Extract domains

Fill in the missing code:

```python
email = "alice@smallco.com"
at_pos = email.find("@")
domain = email[_____]
print(domain)
```

Expected output:

```text
smallco.com
```

---

## Drill 10 — Input grows the dataset

Explain why this appends a new line instead of replacing the whole file:

```python
new_email = input("Enter email: ")

with open("email_dataset.txt", "a") as file:
    file.write(new_email + "\n")
```

---

# Review and explain-back

Answer these in your own words:

1. Why can a text file act like a simple dataset?
2. What does one line in `email_dataset.txt` represent?
3. Why do we use `.strip()` after reading lines from a file?
4. What is the difference between `read()` and `readlines()`?
5. What does append mode `"a"` do?
6. Why is `input()` plus append mode useful?
7. How do we count records from a file?
8. How do we filter saved emails by domain?
9. How do we avoid processing blank lines?
10. How is this different from hardcoded lists?

---

# Coaching hints

- Keep repeating the mental model: **one line = one record**.
- Make them open the text file after running the program so they can see that it really changed.
- If they forget `\n`, show them how the file becomes messy.
- If they forget `.strip()`, show them the hidden newline effect.
- If they get confused, first ask: “Are we writing to the file, reading from the file, or looping through lines?”
- Keep file names consistent. Use `email_dataset.txt` for most exercises.
- Avoid delimited rows until the next file lesson. Today should stay focused on one value per line.
- This is a good day to connect programming to the real idea of storing activity over time.

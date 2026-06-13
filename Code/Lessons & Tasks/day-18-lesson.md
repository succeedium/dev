# Day 18 — Simple Text Files: Writing, Reading, Appending, and Growing a Dataset

## Main goal

Learn how to save data into a text file, read it back, and append new values so the file can grow over time like a very simple dataset.

By the end of this lesson, the student should understand this pattern:

```text
User enters data → Python appends it to a file → the file grows → Python can read the saved data later
```

This is the first step toward using files like a very simple database.

---

## 1. Why files matter

So far, most data has lived inside Python variables:

```python
emails = ["alice@smallco.com", "bob@smallco.com"]
```

That is useful for practice, but the data disappears when the program ends.

A file lets us save data outside the program.

Example file: `emails.txt`

```text
alice@smallco.com
bob@smallco.com
```

Each line stores one email.

---

## 2. Write to a file with `"w"`

The letter `"w"` means **write**.

Important: `"w"` replaces the old file contents.

```python
with open("emails.txt", "w") as file:
    file.write("alice@smallco.com\n")
    file.write("bob@smallco.com\n")
```

After this code runs, `emails.txt` contains:

```text
alice@smallco.com
bob@smallco.com
```

### What does `\n` mean?

`\n` means **new line**.

Without `\n`, the emails would be written on the same line.

---

## 3. Read the whole file with `read()`

The letter `"r"` means **read**.

```python
with open("emails.txt", "r") as file:
    text = file.read()

print(text)
```

`file.read()` gives us the whole file as one string.

---

## 4. Read the file as lines with `readlines()`

For datasets, it is often better to read one line at a time.

```python
with open("emails.txt", "r") as file:
    lines = file.readlines()

print(lines)
```

This may print something like:

```python
['alice@smallco.com\n', 'bob@smallco.com\n']
```

Each line still has the new-line character `\n` at the end.

We can clean it with `.strip()`:

```python
for line in lines:
    email = line.strip()
    print(email)
```

---

## 5. Append to a file with `"a"`

The letter `"a"` means **append**.

Append means: add to the end of the file without deleting what is already there.

```python
with open("emails.txt", "a") as file:
    file.write("tom@trialdomain.com\n")
```

If the file already had two emails, it now has three.

This is the key idea for simulating database growth.

---

## 6. Populate a file from user input

Now the program can ask the user for data and save it.

```python
email = input("Enter a TeamOne user email: ")

with open("emails.txt", "a") as file:
    file.write(email + "\n")

print("Email saved.")
```

This is a simple version of:

```text
User input → saved record → growing dataset
```

Every time the program runs, it adds another line to `emails.txt`.

---

## 7. Read the growing dataset back

After adding emails, we can read all saved emails:

```python
with open("emails.txt", "r") as file:
    lines = file.readlines()

for line in lines:
    email = line.strip()
    print(email)
```

This is the basic pattern for working with file-based datasets.

---

## 8. Add one email, then show all saved emails

This example combines input, append, read, and loop.

```python
email = input("Enter a TeamOne user email: ")

with open("emails.txt", "a") as file:
    file.write(email + "\n")

print("Saved emails:")

with open("emails.txt", "r") as file:
    lines = file.readlines()

for line in lines:
    saved_email = line.strip()
    print(saved_email)
```

This is the most important example of the day.

---

## 9. Save a cleaned email

Before saving data, we can clean it.

```python
email = input("Enter email: ")
clean_email = email.strip().lower()

with open("emails.txt", "a") as file:
    file.write(clean_email + "\n")

print("Clean email saved.")
```

This connects file work to previous lessons about `.strip()` and `.lower()`.

---

## 10. Count saved emails

Once the file has multiple lines, we can count them.

```python
with open("emails.txt", "r") as file:
    lines = file.readlines()

count = 0

for line in lines:
    email = line.strip()

    if email != "":
        count = count + 1

print(f"Total saved emails: {count}")
```

This prepares students for future reporting tasks.

---

# Drills

## Drill 1 — Predict the file contents

What will be inside `emails.txt` after this code runs?

```python
with open("emails.txt", "w") as file:
    file.write("alice@smallco.com\n")
    file.write("bob@smallco.com\n")
```

---

## Drill 2 — Explain `w`, `r`, and `a`

Explain what each mode does:

```text
"w"
"r"
"a"
```

Which one can erase existing file contents?

---

## Drill 3 — Predict append behavior

Assume `emails.txt` already contains:

```text
alice@smallco.com
```

What will the file contain after this code?

```python
with open("emails.txt", "a") as file:
    file.write("bob@smallco.com\n")
```

---

## Drill 4 — Fix the missing new line

This code writes two emails on one line. Fix it.

```python
with open("emails.txt", "w") as file:
    file.write("alice@smallco.com")
    file.write("bob@smallco.com")
```

---

## Drill 5 — Read and clean lines

What does `.strip()` do here?

```python
with open("emails.txt", "r") as file:
    lines = file.readlines()

for line in lines:
    email = line.strip()
    print(email)
```

---

## Drill 6 — Input plus append

Explain this code in plain English:

```python
email = input("Enter email: ")

with open("emails.txt", "a") as file:
    file.write(email + "\n")
```

---

## Drill 7 — Clean before saving

Fill in the missing line.

```python
email = input("Enter email: ")
clean_email = ______________________

with open("emails.txt", "a") as file:
    file.write(clean_email + "\n")
```

Goal: remove extra spaces and make the email lowercase.

---

## Drill 8 — Fix file reading mistake

Fix the mistake.

```python
with open("emails.txt", "r") as file:
    lines = file.readlines

for line in lines:
    print(line.strip())
```

---

## Drill 9 — Count non-empty lines

What does this code count?

```python
count = 0

for line in lines:
    email = line.strip()

    if email != "":
        count = count + 1
```

---

## Drill 10 — Explain the dataset idea

Explain this in your own words:

```text
A text file can act like a tiny dataset because each line can store one record.
```

---

# Review and explain-back

The student should be able to answer:

1. What does `open("emails.txt", "w")` do?
2. Why can `"w"` be dangerous?
3. What does `open("emails.txt", "a")` do?
4. Why do we add `"\n"` when writing each email?
5. What is the difference between `read()` and `readlines()`?
6. Why do we often use `.strip()` when reading lines from a file?
7. How can `input()` help us grow a file-based dataset?
8. Why is a text file more useful than hardcoded variables for storing growing data?

---

# Coaching hints

- Keep the first mental model very simple: a text file is a place where Python can save text.
- Emphasize that `"w"` replaces the file, while `"a"` adds to the file.
- When students forget `\n`, show the file contents so they can see why lines joined together.
- Do not introduce CSV or JSON yet. This day is only about simple text files.
- The most important pattern is: ask with `input()`, clean the value, append it, read it back.
- If file paths cause confusion, keep the `.py` file and `.txt` file in the same folder for now.

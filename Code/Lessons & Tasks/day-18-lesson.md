# Day 18 — Simple text files: writing, reading, and appending

## Main goal

Today you will learn how Python can save information into a file and read it back later.

Until now, most of our data lived inside Python variables like this:

```python
emails = ["alice@smallco.com", "bob@smallco.com"]
```

That works, but when the program stops, the data disappears.

Files let us store data outside the program.

For this project, we will start with a simple file called:

```text
emails.txt
```

It will store one email per line.

Example file content:

```text
alice@smallco.com
bob@smallco.com
tom@trialdomain.com
```

This is the first step toward using files as small datasets.

---

## 1. Why files matter

A Python variable is temporary:

```python
email = "alice@smallco.com"
```

When the program ends, that variable is gone.

A file is saved on disk:

```text
emails.txt
```

If the program ends, the file can still be opened later.

In the TeamOne Client Activity Hub project, files can help us store:

- activity emails
- usage dates
- known client domains
- simple reports

For now, we will start with plain text files.

---

## 2. Writing to a file with `"w"`

The letter `"w"` means **write mode**.

```python
with open("emails.txt", "w") as file:
    file.write("alice@smallco.com\n")
    file.write("bob@smallco.com\n")
```

This creates or replaces the file `emails.txt`.

Important: `"w"` replaces the existing file content.

If the file already had old emails, they will be removed and replaced with the new content.

---

## 3. What does `\n` mean?

`\n` means **new line**.

This:

```python
file.write("alice@smallco.com\n")
file.write("bob@smallco.com\n")
```

creates this file:

```text
alice@smallco.com
bob@smallco.com
```

Without `\n`, the emails would be written on the same line:

```text
alice@smallco.combob@smallco.com
```

So when writing one item per line, remember to add `\n`.

---

## 4. Reading the whole file with `read()`

The letter `"r"` means **read mode**.

```python
with open("emails.txt", "r") as file:
    text = file.read()

print(text)
```

`file.read()` gives us the whole file as one string.

That is useful when we simply want to see all the file contents.

---

## 5. Reading lines with `readlines()`

Often, we want to process one line at a time.

```python
with open("emails.txt", "r") as file:
    lines = file.readlines()

print(lines)
```

The result may look like this:

```python
["alice@smallco.com\n", "bob@smallco.com\n"]
```

Each line is a string.

Notice that the `\n` is still there at the end of each line.

---

## 6. Cleaning each line with `.strip()`

When we read lines from a file, we usually clean each line with `.strip()`.

```python
with open("emails.txt", "r") as file:
    lines = file.readlines()

for line in lines:
    email = line.strip()
    print(email)
```

`line.strip()` removes extra spaces and the newline character `\n`.

This is very similar to cleaning user input or messy email text.

---

## 7. Appending to a file with `"a"`

The letter `"a"` means **append mode**.

Append means add to the end of the file without deleting what is already there.

```python
with open("emails.txt", "a") as file:
    file.write("tom@trialdomain.com\n")
```

Use `"a"` when you want to save a new item and keep the old items.

This is useful for saving new input.

```python
new_email = input("Enter an email: ")

with open("emails.txt", "a") as file:
    file.write(new_email + "\n")
```

---

## 8. Writing a list to a file

We can also write values from a list into a file.

```python
emails = [
    "alice@smallco.com",
    "bob@smallco.com",
    "tom@trialdomain.com"
]

with open("emails.txt", "w") as file:
    for email in emails:
        file.write(email + "\n")
```

This combines:

- lists
- loops
- files
- strings

---

## 9. Reading a file and filtering emails

Once we read emails from a file, we can use the same logic we already know.

```python
with open("emails.txt", "r") as file:
    lines = file.readlines()

for line in lines:
    email = line.strip().lower()

    if "smallco.com" in email:
        print(email)
```

The file is now acting like a simple dataset.

---

## 10. Common file modes

| Mode | Meaning | What it does |
|---|---|---|
| `"w"` | write | creates/replaces a file |
| `"r"` | read | reads an existing file |
| `"a"` | append | adds to the end of a file |

For now, these three are enough.

---

# Drills

## Drill 1 — Predict file content

What will be inside `emails.txt` after this code runs?

```python
with open("emails.txt", "w") as file:
    file.write("alice@smallco.com\n")
    file.write("bob@smallco.com\n")
```

---

## Drill 2 — Explain `\n`

What is the difference between these two versions?

```python
file.write("alice@smallco.com")
file.write("bob@smallco.com")
```

and:

```python
file.write("alice@smallco.com\n")
file.write("bob@smallco.com\n")
```

---

## Drill 3 — `w` versus `a`

Explain the difference between these two modes:

```python
open("emails.txt", "w")
```

```python
open("emails.txt", "a")
```

Which one replaces the file?

Which one adds to the end?

---

## Drill 4 — Read the full file

Predict what gets printed:

```python
with open("emails.txt", "r") as file:
    text = file.read()

print(text)
```

---

## Drill 5 — Read lines

Assume `emails.txt` contains:

```text
alice@smallco.com
bob@smallco.com
```

What type of value is `lines`?

```python
with open("emails.txt", "r") as file:
    lines = file.readlines()

print(lines)
```

---

## Drill 6 — Clean one line

What does this print?

```python
line = "alice@smallco.com\n"
email = line.strip()

print(email)
```

Why is `.strip()` useful when reading files?

---

## Drill 7 — Loop through file lines

Explain each step:

```python
with open("emails.txt", "r") as file:
    lines = file.readlines()

for line in lines:
    email = line.strip()
    print(email)
```

What is `line`?

What is `email`?

---

## Drill 8 — Fix the mistake

This code has a problem:

```python
with open("emails.txt", "w") as file
    file.write("alice@smallco.com\n")
```

What is missing?

---

## Drill 9 — Fix another mistake

This code has a problem:

```python
with open("emails.txt", "r") as file:
    text = file.read

print(text)
```

What is missing after `read`?

---

## Drill 10 — Filter file data

Assume the file contains:

```text
alice@smallco.com
bob@smallco.com
tom@trialdomain.com
```

What will this print?

```python
with open("emails.txt", "r") as file:
    lines = file.readlines()

for line in lines:
    email = line.strip().lower()

    if "smallco.com" in email:
        print(email)
```

---

# Review and explain-back

Answer these in your own words:

1. Why are files useful?
2. What does `open("emails.txt", "w")` do?
3. What does `open("emails.txt", "r")` do?
4. What does `open("emails.txt", "a")` do?
5. What does `\n` mean?
6. Why do we often use `.strip()` when reading lines from a file?
7. What is the difference between `read()` and `readlines()`?
8. How can a text file act like a simple dataset?

---

# Coaching hints

- Keep the first examples very small. Two or three lines in a file is enough.
- Emphasize that `"w"` replaces a file. This is one of the most important beginner file warnings.
- If the student forgets `\n`, show the actual file content so they can see why everything appears on one line.
- Do not introduce JSON or CSV yet. Today is only simple text files.
- Treat `with open(...) as file:` as a pattern. A deep explanation is not needed yet.
- If file location becomes confusing, remind the student that Python looks in the same folder where the program is running unless told otherwise.
- Encourage students to open `emails.txt` after running the code so they can see what Python created.

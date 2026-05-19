email = "name@gmail.com"
print(email[0])
print(email[4])
print(email[0:4])
print(email[0:5])

at_pos = [email.find('@') + 1]

email = 'name@gmail.com'
at_pos = email.find('@')
print(at_pos)
print(email[at_pos + 1:])

word = 'hello'
print(word[0])

print(word[4])

email = 'name@gmail.com'
print(email[0])

print(email[4])

word = "hello"
print(word[0:2])
#he


word = "hello"
print(word[1:4])
#ell

email = "name@gmail.com"
print(email[0:4])
#name

email = "name@gmail.com"
print(email[5:])
#gmail.com

email = 'name@gmail.com'
print(email.find('@'))

print(email.find('g'))

print(email.find('z'))

gmail = 'dom@gmail.com'
at_pos = gmail.find('@')
start_pos = at_pos + 1
domain = gmail[start_pos]
print(at_pos)
print(start_pos)
print(domain)

#
print("hello")
email = "name@gmail.com"
first_character = email[0]
email = "name@gmail.com"
word = email.find('@')
print(email[email.find('@'):])


email = "name@gmail.com"
print(email[email.find('@')+1:])

email = "name@gmail.com"
print(email[email.find('@')+1:])

~#
 Drill 6 — Write one tiny line 

 Write code that prints the first 4 characters of the email.
text = ('hello')
print(text[0:3])

Write code that prints from @ to the end.

email = 'name@gmail.com'
print(email[email.find('@'):])

Write code that prints after @.

email = 'name@gmail.com'
print(email[email.find('@') + 1 :])

Review and explain-back

What does index 0 mean?

the first index 

What does text[1:4] mean?

print indexs, example 123456 - print 234 (last does not count)

What does find() return?
# the number of the index that u r looking for
What does -1 mean?

value not found

Why does +1 remove the @ when slicing?

goes to next # or character

What is the difference between () and []?

(parenthesese) to do something / call a function. and [brackets] select something

What does the dot mean in email.find("@")? it connects find to email
#
Task 1 — Username and domain
Using:
email = "name@gmail.com"
Print:
the username part
the domain part with @
the domain part without @
Then also print:
just the @
just "gmail"


email = 'name123@gmail.com'
at_pos = ('@')
print(at_pos)

print(email[email.find('@'):])
print(email[email.find('@') + 1 :])
print(email[email.find('@')])
g_pos = email.find('g')
print(g_pos)
print(email[8:])


Repeat the same work with:
email = "dominika@yahoo.com"
Print:
the username part
the domain part with @
the domain part without @
Then answer:
Is the @ in the same position as before? no
Why is find() useful here? because instead of counting it finds it for you.

print("new start")
print(" ")

email = 'dominika@yahoo.com'
at_pos = email.find('@')
print(at_pos)
print(email[0:at_pos])
print(email[email.find('@'):])
print(email[email.find('@')+1:])


Task 3 — Find the symbol
Store:
email = "hello@test.ca"
Find the position of @, store it in at_pos, and print it.
Then print:
email[at_pos]
email[at_pos:]
email[at_pos + 1:]

email = 'hello@test.ca'
at_pos = email.find('@')
print(at_pos)
print(email[at_pos])
print(email[at_pos:])
print(email[at_pos + 1:])

 Task 4 — Small-step version
Using:
email = "student@school.org"
Store in variables:
at_pos
username
domain_with_at
domain_without_at
Then print all of them.

email = 'student@school.org'
at_pos = email.find('@')
a = (email[0:at_pos])
b = (email[email.find('@'):])
c = (email[email.find('@')+1:])

print(a, b, c)

Task 5 — Fix the code
Correct these:
print[email.find("@")]
print(email.find["@"])
print(word(0))

print(email.find("@"))
print(email.find("@"))
word = 'apple'
print(word[0])
#

user_name = '  MangoUser   '
print(user_name)

print(user_name.strip())


city = '  Vancouver  '
print(city)
print(city.strip())
print(city.strip().upper())


site = '  OpenAI.COM  '
print(site.strip())
print(site.strip().lower())

phrase = '  Hello World  '
print(phrase.strip())
print(phrase.lower())
print(phrase.strip().lower())

email = '  student@school.com  '
email = email.strip().lower()
at_pos = email.find('@')
print(at_pos)

print(email, at_pos)


email = '  User123@Example.com  '
email = email.strip().lower()
print(email)

at_pos = email.find('@')

user_name = email[0:at_pos]
print(user_name)
domain = email[at_pos:]
print(domain)

word = '  Python  '
word = word.strip().lower()
print(word[0])
print(word[-1])
print(word[0:3])

'''
Task 1

Store this value:
email = "  Name@GMAIL.com  "
Create a clean_email variable that:
removes spaces around the email
converts it to lowercase
Then:
print the original email
print the cleaned email
use if to print "email contains @" or "email does not contain @"
'''


email = "  Name@GMAIL.com  "
print(email)
print(email.strip().lower())

if ('@') in email:
    print('email contains @')
else:
    print('email does not contain @')


'''
Task 2 — Check whether the email looks valid
Store:
email = "studentgmail.com"

Use if and "@" in email to print:
"email looks valid" if it contains @
"email looks invalid" otherwise
Then change the value to:
email = "student@gmail.com"
and run the same check again.
email = 'studentgmail.com'
'''
email = 'studentgmail.com'

if ('@') in email:
    print('email looks vaild')

else:
    print('email looks invaild')

'''
Task 3 — Find the @ position
Store:
email = "hello@test.ca"
Create a variable called at_pos using .find("@").
Then print:
the full email
the value of at_pos
After that, use if to print:
"@ found" if at_pos != -1
"@ not found" otherwise
'''
email = 'hello@test.ca'
at_pos = email.find('@')
print(at_pos)

if at_pos != -1:
    print('@ found')

else:
    print('@ not found')

'''
Task 4 — Username and domain with slicing
Store:
email = "  User123@Example.com  "
First create a cleaned version using .strip().lower().
Then create:
at_pos
username → everything before @
domain → everything after @
Print all 4 values:
cleaned email
at_pos
username
domain
'''

email = '  User123@Example.com  '
email = email.strip().lower()
at_pos = email.find('@')
print(at_pos)
print(email)
username = (email[0:at_pos])
domain = (email[at_pos + 1 :])
print(username)
print(domain)

'''
Task 5 — Print the first and last character
Store:
word = "  Python  "
Clean it first with .strip().
Then print:
the cleaned word
the first character
the last character
the first 3 characters
'''
word = '  python  '
word = word.strip().lower()
print(word)
print(word[0])
print(word[-1])
print(word[0:3])

'''
Task 6 — Compare original and cleaned text
Store:
client_name = "  cBc  "
Create:
clean_name using .strip().lower()
upper_name using .strip().upper()
Then print:
the original value
the cleaned lowercase value
the cleaned uppercase value
Use if to check whether clean_name == "cbc" and print:
"name matches cbc"
or "name does not match cbc"
'''

client_name = '  cBc  '
clean_name = client_name.strip().lower()
upper_name = client_name.strip().upper()

print(client_name)
print(clean_name)
print(upper_name)

if clean_name == client_name:
    print('name matches cbc')

else:
    print('name does not match')

'''
Task 7 — Check large or standard deal
Store:
amount = 12000
Use if / else to print:
"large deal" if the amount is greater than 10000
"standard deal" otherwise
Then change the amount to 8000 and run it again.
'''
amount = (12000)

if amount > 10000:
    print('standard deal')
else:
    print('Change amount to 8000 and run again.')

'''
Task 8 — Check whether email starts with a space
Store:
email = " test@gmail.com"
Print:
the original email
the first character using indexing
Then use if to check whether the first character is a space:
if yes, print "email starts with a space"
otherwise print "email does not start with a space"
'''
email = ' test@gmail.com'
print(email)
print(email[0])

if email[0] == (' '):
    print('email starts with a space')
else:
    print('email does not start with space ')

'''
Task 9 — Slice from the @ symbol
Store:
email = "person@yahoo.com"
Use .find("@") and slicing to print:
everything from @ to the end
everything after @
Then use if to check whether the domain is "yahoo.com" and print:
"Yahoo domain"
or "Other domain"
'''
email = 'person@yahoo.com'
at_pos = email.find('@')
print(at_pos)
domain_at = (email[at_pos:])
domain = (email[at_pos + 1 :])
print(domain_at)
print(domain)
if domain == ('yahoo.com'):
    print('yahoo domain')
else:
    print('other domain')

'''
Task 10 — Build a clean account summary
Store:
client_name = "  SmallCo  "
email = "  SALES@SmallCo.com  "
amount = 8000
Create cleaned versions of the client name and email.
Then print one sentence like:
Client smallco uses email sales@smallco.com and pays 8000 per year.
After that, use if to print:
"large client" if amount > 10000
"smaller client" otherwise
'''

client_name = '  SmallCo  '
email = '  SALES@SmallCo.com  '
amount = 8000
client_name = client_name.strip().lower()
email = email.strip().lower()
print(f'Client {client_name} uses email {email} and pays {amount} per year.')

if amount > 10000:
    print('Large client')
else:
    print('Smaller client')

'''
Task 11 — Find and print just the domain
Store:
email = "  manager@company.org  "
Clean the email first.
Then use:
.find("@")
+ 1
slicing
to print only:
company.org
Then use if to check whether the domain is "company.org".
'''

email = '  manager@company.org  '
email = email.strip().lower()
domain = email[email.find('@') + 1:]
print(at_pos)

if domain == 'company.org':
    print('domain is == to company.org')
else:
    print('domain is not == company.org')

'''
Task 12 — Mini email inspector
Store:
email = "  Admin@Mail.com  "
Create a cleaned version.
Then print:
original email
cleaned email
whether it contains @
the position of @
the username part
the domain part
the email in uppercase
Finally, use if / else to print:
"valid-looking email" if it contains @
"invalid-looking email" otherwise

'''

email = '  Admin@Main.com  '
print(email)
email = email.strip().lower()
at_pos = email.find('@')
print(at_pos)

username = email[0:at_pos]
print(username)
domain = email[at_pos +1:]
print(domain)
print(email.upper())

if '@' in email:
    print('valid-looking email')
else: 
    print('invaild-looking email')    

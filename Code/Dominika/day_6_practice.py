'''
Task 1 — Simple @ check with in
Store:
email = "name@gmail.com"
·        Use if and "@" in email to print:
·        "email has @"
·        or "email is missing @"
'''
print('task 1')
email = "name@gmail.com"

if ("@") in email:
    print("email has @")
else:
    print("email missing @")

'''
Task 2 — Simple @ check with find()
Use the same email.
·        Create at_pos with .find("@").
·        Then use if to print:
·        "email has @" if at_pos != -1
·        "email is missing @" otherwise
·        Also print the value of at_pos.
'''
print('task 2')
email = "name@gmail.com"
at_pos = email.find("@")
if at_pos != -1:
    print("email has @")
else:
    print("email is missing @")
print(at_pos)

''' 
Task 3 — Check for both @ and dot
Store:
email = "user@test.ca"
Create:
has_at
has_dot
using in.
Then print both values.
After that, use if to print:
"email has both symbols" if both are present
otherwise "email is missing something"
'''
print('task 3')
email = "user@test.ca"
has_at = ("@") in email
has_dot = (".") in email
print(f'{has_at}, {has_dot}') 

if has_at and has_dot:
    print('email has both symbols')
else:
    print("email is missing something")

'''Task 4 — Clean first, then check
Store:
email = "  User@Test.com  "
·Create a clean_email variable using .strip().lower().
Then print the original email, print the cleaned email, 
check whether the cleaned email contains @, and check whether the cleaned email contains .. 
Print clear messages for both checks.
'''

print('task 4')

email = "  User@Test.com  "
print('original email:', email)
clean_email = email.strip().lower()
print("clean email:",clean_email)

if ("@") in clean_email:
    print("email contains '@'")
else:
    print('email does not contain @')
if (".") in clean_email:
    print("email contains '.'" )
else:
    print("email does not contain '.'" )
'''
email = "hello@test.ca"
·        Use if to check whether the email contains @.
·        If it does: find the position of @, create a domain variable with everything after @, and print the domain.
·        Otherwise: print "invalid email".
'''
print('task 5')

email = "hello@test.ca"
if ("@") in email:
    print(email.find("@"))
    domain = email[email.find("@") + 1:]
    print(domain)
else:
    print('invalid email')

'''
email = "hello@test.ca"
·        Check whether the email contains "." in two ways: first with in, then with find() != -1. Print the results of both.
·        Then answer: which one is easier to read? which one gives a position?
'''
print('task 6')

email = 'hello@test.ca'
if (".") in email:
    print("email contains '.'")
else:
    print("email does not contain '.'")

if email.find(".") != -1:
    print("email contains '.'")
else:
    print("email does not contain '.'")

'''
email = "first.last@gmail.com"
·        First: find @ and create a username variable with everything before @.
·        Then check whether "." in username and print "username has dot" or "username has no dot".
'''

print("task 7")

email = "first.last@gmail.com"
at_pos = email.find("@")
username = email[:at_pos]
print(f"Username: {username}")
if (".") in email:
    print("email contains '.'")
else:
    print("email does not contain '.'")

'''
email = "uest.caser@t"
·        If the email contains @: extract the domain part, check whether the domain contains .,
 and print "domain has dot" or "domain has no dot".
·        Otherwise: print "invalid email".
'''
print('task 8')
email = "uest.caser@t"

if ("@") in email:
    domain = email[email.find("@"):]
    print(domain)
    if (".") in domain:
        print("domain has '.'")
    else:
        print("invalid email")

'''
email = "  USER@GMAIL.com  "
·        First clean the email with .strip().lower().
·        If the cleaned email contains @: extract the domain, 
then use if / else to print: "Gmail user" if domain is "gmail.com",
 "Yahoo user" if domain is "yahoo.com", "Other provider" otherwise.
·        If there is no @, print "invalid email".
'''
print("task 9")
email = "  USER@GMAIL.com  "
clean_email = email.strip().lower()
if "@" in clean_email:
    at_pos = clean_email.find("@")
    domain = clean_email[at_pos + 1:]

    if domain == "gmail.com":
        print("gmail.com")
    elif domain == "yahoo.com":
        print("yahoo.com")
    else:
        print("other provider")

else:
    print("invalid email")
'''
email = "  dOMinIKA@School.org  "
Clean the email first.
If it contains @: extract the username, create a nicely formatted version with first
letter uppercase and rest lowercase, then print cleaned email, username, and formatted username.
Otherwise: print "invalid email".
'''
print("task 10")

email = "  dOMinIKA@School.org  "
clean_email = email.strip().lower()

if "@" in clean_email:
    at_pos = clean_email.find("@")
    username = clean_email[:at_pos]

    formatted_username = username[0].upper() + username[1:]

    print("cleaned email:", clean_email)
    print("username:", username)
    print("formatted_username:", formatted_username)

else:
    print("invalid email")

'''
Task 11 — Mini email inspector
Store:
email = "  Admin@Mail.com  "
Create a cleaned version.
Then print: original email, cleaned email, whether it contains @, 
whether it contains ., and the position of @.
'''
print("task 11")

email = "  Admin@Mail.com  "
clean_email = email.strip().lower()
print(email)
print(clean_email)
at_pos = email.find("@")
if ("@") in clean_email:
    print('email contains @')
else:
    print("email does not contain @")

dot_pos = email.find(".")
if (".") in clean_email:
    print("email contains '.'")
else:
    print("email does not contain '.'")
print("at_pos:", at_pos)
print("dot_pos:", dot_pos)


'''
Store:
email = "  student@School.com  "
·        Clean it first.
·        Then: check if it has @, check if it has ., and if it has @, extract username and domain.
Finally print a short summary sentence like:
Email student@school.com has username student and domain school.com.
If it is missing @, print:
Email looks invalid.
'''
print("task 12")

email = "  studentSchool.com  "
clean_email = email.strip().lower()
at_pos = clean_email.find('@')
dot_pos = clean_email.find('.')
domain = clean_email[at_pos + 1:]
username = clean_email[: at_pos]

if "@" in email and "." in email:
    print("email contains '@' and '.' ")
    print(username)
    print(domain)

    print(f"Email {clean_email} has username {username} and domain {domain}")
else:
    print("email looks invalid")







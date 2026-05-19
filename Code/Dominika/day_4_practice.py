email = "  Name@GMAIL.com  "
print(email)
print(email.strip())
print(email.lower())
print(email.strip().lower())

text = 'TeamOne'
print(text.upper())
print(text.lower())

Drill 1 — Predict the output
text = "  hello  "
print(text.strip())
#when it prints hello it will move it all the way to the left

email = "Name@GMAIL.com"
print(email.lower())
#it will make all characters lowercase in email

name = "domi"
print(name.upper())
#it will make all characters uppercase in name

'''Drill 2 — What changes and what stays

Does strip() remove spaces in the middle or only around the edges?
#it removes the space on the left

Does lower() change the original variable by itself or only return a new value?
#it returns a new value

Drill 3 — Fill in the code

email = "  User@Test.com  "
clean_email = email.strip().lower()
print(clean_email)

#Drill 4 — Fix the mistakes

email = "User@Test.com"
print(email.lower())


name = "Monika"
print(name.strip())


#Drill 5 — Tiny write-your-own tasks
#Store a client name with extra spaces and print a cleaned version.
#Store an email with capital letters and print a lowercase version.

client_name = '   andie  '
print(client_name)


email = 'DOMMY@GMAIL.COM'
print(email.lower())

# Practice tasks

Task 1 — Clean one email
Store an email with spaces before and after it. Create a clean_email variable that removes spaces and uses only lowercase.

Task 2 — Normalize two names
Store two names with messy capitalization. Print them in lowercase and uppercase.

Task 3 — Mini account summary
Store a messy email and a client name. Print one clean summary sentence using the cleaned email.

Review and explain-back
What does strip() do? - removes spaces from a string and moves it all the way to the left.
What does lower() do? - it makes all the characters in a string lower case.
Why is email.strip().lower() useful? - it makes the text look 'clean'
What does it mean that a method returns a new value? - it does not change the variable itself, but gives you a new one with what you wanted.
Good habit: Encourage her to create intermediate variables like clean_email instead of writing long chains everywhere.

email = '   domi@gmail.com '
print(email.strip())

name_1 = 'GenOIWHoih'
name_2 = 'yUiOpiE'
print(name_1.lower())
print(name_2.lower())


client_name = '   kIaHa hO   '
client_email = '   kIaHa.hO@gMaIl.CoM  '

print(client_name.strip().lower(),client_email.strip().lower())
'''
= '  vLaD@gmail.com   '
#print(user_name)

email = email.strip()

at_pos = email.find('@')
print(at_pos)

user_name = email[0:4]
print(user_name)

print(user_name.lower())
user_name = email.upper()[0] + email.lower()[1:]

print(user_name)

emails = ["a@gmail.com", "bademail.com", "c@test.ca", "hello.com", "admin@site.org"]
valid_count = 0
for email in emails:
    if looks_valid(email) == True:
        valid_count = valid_count + 1
print(valid_count)
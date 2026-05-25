email = "   Judy.ELmer@yahoo.com  "
clean_email = email.strip().lower()
print(email)
print(clean_email)

Name_one = "MonIkA"
Name_two = "ellA"
print((Name_one[0].upper()) + Name_one[1:].lower()) 
print(Name_two.lower())

messy_email = "MoNikA@gmAiL.com  "
messy_name = "mONIka"
print("The email is " + messy_email.strip().lower())

username = "   MangoUser   "
print(username.strip())

city = "  vancouver   "
print(city)
print(city.strip())
print(city.strip().upper())

Site = " OpenAl.COM "
trimmed_site = Site.strip()
clean_email = Site.lower().strip()
print(Site)
print(trimmed_site)
print(clean_email)

phrase = " Hello World "
print(phrase.strip())
print(phrase.lower())
print(phrase.strip().lower())

name= " ALINA "
email= " ALINA@MAIL.com "
clean_name =(name[1].upper()) + (name[2:].strip().lower())
clean_emailversion = email.strip().lower()

print(f"Client {clean_name}, can be reached at: {clean_emailversion}")

email_one = " student@School.com "
clean_email_one = email_one.strip().lower()
print(clean_email_one)
print(clean_email_one.find("@"))

email_two = "  User123@Example.com  "
pos_a = email_two.find("@")
username_two = email_two[0:pos_a].strip()
domain = email_two[pos_a + 1:]

print(email_two.strip().lower())
print(username_two)
print(domain)

word_one = "  Python  "
clean_word_one = word_one.strip()
print(clean_word_one[0])
print(clean_word_one[-1])
print(clean_word_one[0:3])


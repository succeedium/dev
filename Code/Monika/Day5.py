email = " Name@GMAIL.com  "
clean_email = email.strip().lower()
print(email)
print(clean_email)
if "@" in email:
    print("Email contains @.")
else:
    print("Email does not conatain @.")

email_one = "studentgmail.com"
if "@" in email_one:
        print("Email looks valid!")
else:
        print("Email looks invalid!")
        email_one = "student@gmail.com"
if "@" in email_one:
        print("Email looks valid!")
else:
        print("Email looks invalid!")
        email_one = "student@gmail.com"

email_two = "hello@test.ca"
at_pos = email_two.find("@")
print(email_two)
print(at_pos)
if "@" in email_two and {at_pos != -1}:
       print("@ found")
else: 
       print("@ not found!")


email_three = "  User123@Example.com  "
clean_email_three = email_three.strip().lower()
at_pos_three = clean_email_three.find("@")
username = clean_email_three[0:at_pos_three]
domain = clean_email_three[at_pos_three:]
print(at_pos_three)
print(username)
print(domain)

word = " Python "
clean_word = word.strip()
print(clean_word)
print(clean_word[0])
print(clean_word[-1])
print(clean_word[0:3])

client_name = " cBc "   
clean_client_name = client_name.strip().lower()
client_uppername = client_name.strip().upper()
print(client_name)
print(clean_client_name)
print(client_uppername)

if clean_client_name == "cbc":
       print("Name matches cbc.")

else:
       print("Name does not match cbc.")

amount = 12000
if amount >10000:
       print("large deal")
else: print("standard deal")
amount = 8000
if amount >10000:
       print("large deal")
else: print("standard deal")

email_four = " test@gmail.com"
print(email_four)
print(email_four[0])
if email_four[0] == " ":
       print("Email starts with a space.")
else:
       print("Email does not start with space.")

email_five = "person@yahoo.com"
atpos_five = email_five.find("@")
print(email_five[atpos_five:])
print(email_five[0:atpos_five])
domain_four = email_five[atpos_five:]
if domain_four == "@yahoo.com":
       print("Yahoo domain")
else: 
       print("Other domain")

client_name_six = " SmallCo "
email_six = "  SALES@SmallCo.com  "
amountm = 8000

clean_client_name_six = client_name.strip().lower()
clean_email_six = email_six.strip().lower()
print(f"Client {clean_client_name_six} uses {clean_email_six} and pays {amount} per year.")

if amount > 10000:
       print("Large client.")
else: 
       print("Smaller client.")

email_seven = "  manager@company.org  "
clean_email_seven = email_seven.strip().lower()
at_pos_seven = clean_email_seven.find("@")+ 1
print(clean_email_seven[at_pos_seven:])
domain_seven = clean_email_seven[at_pos_seven:]
if domain_seven == "company.org":
       print("Domain is equal to company.org")
else: print("Domain is not equal to company.org.")

email_eight = "  Admin@Mail.com  "
print(email_eight)
clean_email_eight = email_eight.strip().lower()
print(clean_email_eight)
contains_at = clean_email_eight.find("@")
if contains_at:
       print("email contains @.")
else: print("email does not contain @.")
print(clean_email_eight.find("@"))
print(clean_email_eight[0:contains_at])
print(clean_email_eight[contains_at:])
print(clean_email_eight.upper())
if contains_at:
       print("Email looks valid!")
else: 
       print("Email looks invalid.")








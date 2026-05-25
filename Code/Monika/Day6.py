#Task one
email = "name@gmail.com"
if "@" in email:
    print("Email has @.")
else: 
    print("Email is missing @")

#Task two

email = "name@gmail.com"
at_pos = email.find("@")
if at_pos != -1:
    print("Email has @.") 
else:
    print("Email is missing @.")
print(at_pos)

#Task three

email_two = "user@test.ca"

has_at = "@" in email_two
has_dot = "." in email_two

print(has_at)
print(has_dot)

if has_dot and has_at:
    print("Email has both symbols.")
else:
    print("Emaail is missing something.")

#Task four


Email_three = "  User@Test.com  "
clean_email_three = Email_three.strip().lower()
print(Email_three)
print(clean_email_three)

#Task Five

email_four = "hello@test.ca"
domain = email_four[email_four.find("@") + 1:]
if "@" in email_four:
    print(domain)
else:
    print("Invalid email.")

#Task six

email_five =  "first.last@gmail.com"
username = email_five[:email_five.find("@")]
if "." in email_five:
    print("Username has dot.")
else:
    print("Username has no dot.")

# Task eight

email_six = "uest.caser@t"
domain_two = email_six[email_six.find("@"):]
if "@" in email_six:
    if "." in email_six:
        print("Domain has dot.")
    else:
        print("Domain has no dot.")

# Task nine

email_seven = "  USER@GMAIL.com  "
clean_email_seven = email_seven.strip().lower()
domain_three = clean_email_seven[clean_email_seven.find("@"):]
if "@" in clean_email_seven:
    if "gmail" in domain_three:
        print("Gmail user") 
    elif "yahoo" in domain_three:
            print("Yahoo user")

    else:
        print("Other provider")
if clean_email_seven.find("@") == -1: 
     print("invalid email.")

# Task ten

email_eight = "  dOMinIKA@School.org  "
clean_email_eight = email_eight.strip().lower()
username_eight = clean_email_eight[:clean_email_eight.find("@")]
formal_username = clean_email_eight[0].upper() + clean_email_eight[1:clean_email_eight.find("@")]
if "@" in clean_email_eight:
    print(clean_email_eight)
    print(username_eight)
    print(formal_username)
else:
    print("invalid email.")

# Task eleven

email_nine = "  Admin@Mail.com  "
clean_email_nine = email_nine.strip().lower()
domaine_nine = clean_email_nine[clean_email_nine.find("@"):]
username_nine = clean_email_nine[:clean_email_nine.find("@")]
print(email_nine)
print(clean_email_nine)
if "@" in clean_email_nine:
    print("Email contains @.")
    print(domaine_nine)
    print(username_nine)

else:
    print("Email does not contain @.")
    print("cannot split invalid email.")


#Task twelve

email_ten = "  student@School.com  "
clean_ten = email_ten.strip().lower()

has_at = "@" in clean_ten
has_dot = "." in clean_ten

print(has_at)
print(has_dot)

if "@" in email_ten:
    domaine_ten = clean_ten[clean_ten.find("@")+1:]
    username_ten = clean_ten[:clean_ten.find("@")]
    print(f"Email {clean_ten} has username and domain {domaine_ten}")
else:
    print("Email looks invalid!")






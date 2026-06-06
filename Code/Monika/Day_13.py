print("""---------TASK ONE---------
      """)

# Store email as varible
email = "  Name@GMAIL.com  "
# Clean email so its easier to read
clean_email = email.strip().lower()
print(clean_email)

print("""---------TASK TWO---------
      """)

email = "  ADMIN@CBC.ca  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
domain = clean_email[at_pos + 1:]
print(clean_email)

print("""---------TASK THREE---------
      """)

email = "  User@Test.ca  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
domain = clean_email[at_pos + 1:]
print(domain)


print("""---------TASK FOUR---------
      """)

# Input data
email = "  User@Test.ca  "
# Clean data
clean_email = email.strip().lower()
# Check and extract
if "@" in clean_email:
    at_pos = clean_email.find("@")
    domain = clean_email[at_pos + 1:]
    username = clean_email[:at_pos]
    # Output
    print(f"Domain: {domain}")
    print(f"Username: {username}")
else: 
    print("invalid email")

print("""---------TASK FIVE--------
      """)
email = "  Sales@SmallCo.com  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
username = clean_email[:at_pos]
domain = clean_email[at_pos + 1:]

print(f"DEBUG CLEAN_EMAIL: {clean_email}")
print(f"DEBUG AT_POS: {at_pos}")
print(f"DEBUG USERNAME: {username}")
print(f"DEBUG DOMAIN: {domain}")

print("""---------TASK SIX--------
      """)

email ="  USER@Test.ca  "
# Cleans email so users input isn't case sensitive
clean_email = email.strip().lower()
if "@" in clean_email:
#Create functions before using them instead of on same line so ode is more tidy.
   at_pos = clean_email.find("@")
   domain = clean_email[at_pos + 1:]
   print(f"Domain: {domain}")
else:
 print("Invalid email")

print("""---------TASK SEVEN--------
      """)

def cleaned_email(email):
   clean_email = email.strip().lower()
   return clean_email


def looks_valid(email):
   if "@" in email:
      return True
   else: 
      return False
   

def get_domain(email):
   at_pos = email.find("@")
   domain = email[at_pos +1:]
   return domain

print(cleaned_email(email))
print(looks_valid(email))
print(get_domain(email))

print("""---------TASK EIGHT--------
      """)

emails = ["  ADMIN@CBC.ca  ", "bademail.com", " User@Test.ca "]

for email in emails:
   # Clean email incase input has uppercase letters
   clean_email = email.strip().lower()
   # Use helper variables to keep code neat and tidy.
   at_pos = clean_email.find("@")
   domain = clean_email[at_pos + 1:]
   username = clean_email[:at_pos]
   # Check if code is valid and only then return domain and username.
   if "@" in clean_email:
      print(username)
      print(domain)
   else:
      print("Email looks invalid.")

print("""---------TASK NINE--------
      """)
# List stores emails
emails = ["a@gmail.com", "bademail.com", "c@test.ca"]
# valid_count counts emails when going through loop
valid_count = 0
# Loop checks if email is valid by checking if it contains @
for email in emails:
    if "@" in email:
# Count increases only if the email it is checking is valid.
        valid_count = valid_count + 1

print(valid_count)

print("""---------TASK TEN --------
      """)
 
days = ["MoN","tuEs","WEd","ThURs","FrI"]
for day in days:
   if "e" in day.strip().lower():
     print(f"position of e is: {day.strip().lower().find("e")}")
   else:
      print("Day does not contain e.")

# List contains days of week.
days = ["MoN","tuEs","WEd","ThURs","FrI"]
#Loop checks if "e" in day and returns position.
for day in days: 
   clean_day = day.strip().lower()
   pos_of_e = clean_day.find("e")
   if "e" in clean_day:
      print(f"The position of e is {pos_of_e}")
# If there is no "e", loop prints "Cannot find "e"."
   else: print('Cannot find "e".')

   

    










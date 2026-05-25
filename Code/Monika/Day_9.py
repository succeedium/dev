print("TASK ONE ------------")
clients = ["DoorDash", "Veolia", "Pinterest", "NewsCorp"]
for client in clients:
    print(client)

print("TASK TWO ------------")
emails = ["  A@GMAIL.com  ", " B@YAHOO.com ", "c@Test.ca"]
for email in emails:
    print(email.strip().lower())

print("TASK THREE ------------")
emails_list = ["a@gmail.com", "bademail.com", "c@test.ca"]
for each_email in emails_list:
    print(each_email)
    if "@" in each_email:
        print("Valid looking")
    else:
        print("missing @")

print("TASK FOUR ------------")
emails_list2 = ["a@gmail.com", "bademail.com", "c@test.ca"]
for every_email in emails_list2:
    print(every_email)
    print(f"Position of @ is {every_email.find("@")}.")

print("TASK FIVE ------------")
email_list3 = ["a@gmail.com", "b@yahoo.com", "bademail.com", "c@test.ca"]
for this_email in email_list3:
    if "@" in this_email:
      print(this_email[this_email.find("@") + 1:])
    else: 
        print("invalid email")

print("TASK SIX ------------")
domain_text = "gmail.com,yahoo.com,test.ca"
domain_list = domain_text.split(",")
print(domain_list)
print(domain_list[0])
print(domain_list[1])
print(domain_list[2])

print("TASK SEVEN ------------")  

domain_text = "gmail.com,yahoo.com,test.ca"
domain_list = domain_text.split(",")
for domain in domain_list:
    print(domain)

print("TASK EIGHT ------------")  

email_ = "name@gmail.com"
parts = email_.split("@")
print(parts)
print(parts[0])
print(parts[1])

print("TASK NINE ------------") 

_email = "name@gmail.com"
at_pos = _email.find("@")
print(_email[:at_pos])
print(_email[at_pos+1:])

parts_of_email = _email.split("@")
print(parts_of_email[0])
print(parts_of_email[1])

print("TASK TEN ------------")

_emails = ["a@gmail.com", "b@yahoo.com", "c@test.ca"]
email_parts = None
for e in _emails:
    email_parts = e.split("@")
    print(email_parts[0])
    print(email_parts[1])

print("TASK ELEVEN ------------")

list_emails = ["a@gmail.com", "bademail.com", "c@test.ca"]

for value in list_emails:
    if "@" in value:
        print(value.split("@")[1])
    else: 
        print("cannot split invalid email")
    
print("TASK TWELVE ------------")
list_clients = ["CBC", "SmallCo", "News Corp"]
for client in list_clients:
    print(f"Client: {client}")

print("TASK THIRTEEN ------------")
statuses = ["trial", "paid", "expired", "lead"]
for status in statuses:
    if status == "trial":
        print("trial account")
    elif status == "paid":
        print("paid account")
    else: 
        print("other status")

print("TASK FOURTEEN ------------")
emails_list3 = ["  ADMIN@CBC.ca  ", "bademail.com", "user@test.ca", "SALES@SmallCo.com"]
for _email_ in email_list3:
    _email_ = _email_.strip().lower()
    print(_email_)
    if "@" in _email_:
        parts_email = _email_.split("@")
        print(parts_email[0])
        print(parts_email[1])
    else: 
        print("invalid email")

print("TASK FIFTEEN ------------")

client_name = "Big Blue Company"
client_name_parts = client_name.split(" ")
print(client_name_parts)
print(client_name_parts[0])
print(client_name_parts[1])
print(client_name_parts[2])
for client in client_name_parts:
    print(client)

print("TASK SIXTEEN ------------")

emails_text = "admin@cbc.ca,user@smallco.com,bademail.com,contact@newscorp.com"
emails = emails_text.split(",")
for email in emails:
    clean_email = email.strip().lower()
    print(f"Email: {clean_email}")
    if "@" in clean_email:
     email_parts = clean_email.split("@")
     print(f"Username: {email_parts[0]}")
     print(f"Domain: {email_parts[1]}")
    else:
       print("Invalid Email.")










print("Task 1 ------")

email_list = ["vlad@gmail.com","dominika@gmail.com","sam@yahoo.com","amabel@gmail.com","kristina@gmail.com"]
print(email_list)
print(email_list[0])
print(email_list[1])
print(email_list[-1])

print("Task 2 ------")

client_names = ["pinterest", "veolia", "DoorDash", "News Corp"]
print(client_names)
print(client_names[0])
print(client_names[1:3])
print(client_names[2:])

print("Task 3 ------")

Trial_domains = ["yahoo.com", "gmail.com", "icloud.com"]
print(Trial_domains[1])
print(Trial_domains[0:2])
print(Trial_domains[1:])

print("Task 4 ------")

second_email_list = ["  USER@GMAIL.com  ", "admin@test.ca", "contact@yahoo.com"]
first_email = second_email_list[0].strip().lower()
print(second_email_list[0])
print(first_email)

print("Task 5 ------")

third_email_list = ["a@gmail.com", "b@yahoo.com", "c@test.ca"]
at_pos = third_email_list[1].find("@")
domain = third_email_list[1][at_pos + 1:]
print(third_email_list[1])
print(domain)

print("Task 6 ------")

email_list_four = ["good@gmail.com", "bademail.com", "test@test.ca"]
if "@" in email_list_four[1]:
    print("Valid-looking email")
else:
    print("Missing @")

if "@" in email_list_four[2]:
    print("Valid-looking email")
else:
    print("Missing @")

print("Task 7 ------")
client_list = ["CBC", "DoorDash", "Pinterest"]
print(client_list[1])
print(client_list[1][0])
print(client_list[1][0:4])

print("Task 8 ------")

clients = ["  cBc  ", "  DoorDASH  ", "Pinterest"]
first_client = clients[0]
clean_firstc = first_client.strip().lower()
upper_firstc = first_client.strip().upper()
print(first_client)
print(clean_firstc)
print(upper_firstc)

print("Task 9 ------")

statuses_list = ["trial", "paid", "expired"]
status = statuses_list[0]
if "trial" in status:
    print("trial account")
else: 
    print("not trial")

print("Task 10 ------")

clients_names = ["CBC", "SmallCo", "News Corp"]
emails_lists5 = ["admin@cbc.ca", "user@smallco.com", "contact@newscorp.com"]
all_statuses = ["paid", "trial", "lead"]
index = 1
print(f"{clients_names[index]} uses {emails_lists5[index]} and has status {all_statuses[index]}.")
 
index = 0
print(f"{clients_names[index]} uses {emails_lists5[index]} and has status {all_statuses[index]}.")





print("Task 11 ------")

emails_6 = ["  ADMIN@CBC.ca  ", "bademail.com", "user@test.ca"]


index = 0
which_email = emails_6[index].strip().lower()

if "@" in which_email:
    at_pos6 = which_email.find("@")
    print(which_email[:at_pos6])
    print(which_email[at_pos6+1:])
    print(f"{which_email} uses @ symbol.")
else:
    print("invalid email")



index = 1
which_email = emails_6[index].strip().lower()

if "@" in which_email:
    at_pos6 = which_email.find("@")
    print(which_email[:at_pos6])
    print(which_email[at_pos6+1:])
    print(f"{which_email} uses @ symbol.")
else:
    print("invalid email")


index = 2
which_email = emails_6[index].strip().lower()

if "@" in which_email:
    at_pos6 = which_email.find("@")
    print(which_email[:at_pos6])
    print(which_email[at_pos6+1:])
    print(f"{which_email} uses @ symbol.")
else:
    print("invalid email")

print("Task 12 -----")
email_from7 = "name@gmail.com"
emails_7 = ["name@gmail.com", "admin@test.ca", "user@yahoo.com"]
print(email_from7[0:4])
print(emails_7[0:2])
# first print returned first 4 charecters of email_from7
# second print retured values 0:2 in the email list

print("Task 13 ------")

domains_13_list = ["gmail.com", "yahoo.com", "test.ca"]

if "gmail.com" in domains_13_list[0]:
    print("Google email!")
else: print("other email.")

print("Task 14 ------")

clients_14list = ["CBC", "SmallCo", "News Corp"]
emails_14list = ["  ADMIN@CBC.ca  ", "user@smallco.com", "contact@newscorp.com"]
statuses_14list = ["paid", "trial", "lead"]

client_14 = clients_14list[0]
email_14 = emails_14list[0]
status_14 = statuses_14list[0]
clean_email_14 = email_14.strip().lower()
username_14 = " "
domain_14 = " "
if "@" in clean_email_14:
    username_14 = clean_email_14[:clean_email_14.find("@")]
    domain_14 =  clean_email_14[clean_email_14.find("@"):]
    print(f"Client: {client_14}")
    print(f"Email: {client_14}")
    print(f"Username: {username_14}")
    print(f"Domain: {domain_14}")
    print(f"Status: {status_14}")


    















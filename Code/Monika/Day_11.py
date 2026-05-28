print("""------- TASK ONE -------
       """)

emails = []
emails.append("Mon@gmail.com")
emails.append("Monikas@yahoo.com")
emails.append("Dom.didenko@gmail.com")
emails.append("dominika@gmail.com")

print(emails)
print(len(emails))

print("""------- TASK TWO -------
       """)

clients = ["CBC", "SmallCo"]
clients.append("News Corp")
print(clients)

print("""------- TASK THREE -------
       """)

clients = ["CBC", "SmallCo", "News Corp"]
clients.insert(1,"DoorDah")

print(clients)

print("""------- TASK FOUR -------
       """)

emails = ["admin@cbc.ca", "user@smallco.com"]
more_emails = ["sales@newscorp.com", "help@test.ca"]
emails.extend(more_emails)
print(emails)

print("""------- TASK FIVE -------
       """)

emails = ["admin@cbc.ca"]
more_emails = ["sales@newscorp.com", "help@test.ca"]

emails.extend(more_emails)
print(emails)

#append inserts more_emails as a list into emails
#while extend takes each value from more_emails and inserts each of them as a sperate value in emails.

print("""------- TASK SIX -------
       """)

clients = ["CBC", "SmolCo", "News Corp"]
clients[1] = "SmallCo"

print(clients)

print("""------- TASK SEVEN -------
       """)

emails = ["admin@cbc.ca", "wrong-email", "contact@newscorp.com"]
emails[1] = "user@smallco.com"
print(emails)

print("""------- TASK EIGHT -------
       """)

clients = ["CBC", "SmallCo", "Test Client", "News Corp"]
if "Test Client" in clients:
    clients.remove("Test Client")
print(clients)

print("""------- TASK NINE -------
       """)
clients = ["CBC", "SmallCo", "News Corp"]
if "Test Client" in clients:
    clients.remove("Test Client")
else: print("Client not found")

print(clients)

print("""------- TASK TEN -------
       """)

clients = ["CBC", "SmallCo", "News Corp"]
removed_client = clients.pop(1)
print(removed_client)
print(clients)


print("""------- TASK ELEVEN -------
       """)

emails = ["admin@cbc.ca", "user@smallco.com", "contact@newscorp.com"]
removed_client = emails.pop()
print(removed_client)
print(emails)

print("""------- TASK TWELVE -------
       """)

clients = ["CBC", "SmallCo", "News Corp"]

del(clients[0])
print(clients)

print("""------- TASK THIRTEEN -------
       """)
domains = ["gmail.com", "yahoo.com", "gmail.com", "test.ca", "gmail.com"]
print(domains.count("gmail.com"))
print(domains.count("yahoo.com"))
print(domains.count("outlook.com"))

print("""------- TASK FOURTEEN -------
       """)

statuses = ["trial", "paid", "trial", "expired", "trial", "paid"]
print(statuses.count("trial"))
print(statuses.count("paid"))
print(statuses.count("expired"))
print(statuses.count("lead"))

print("""------- TASK FIFTEEN -------
       """)

clients = ["DoorDash", "CBC", "Pinterest", "SmallCo"]
print(clients)
clients.sort()
print(clients)

print("""------- TASK SIXTEEN -------
       """)

clients = ["CBC", "DoorDash", "Pinterest", "SmallCo"]
print(clients)
clients.reverse()
print(clients)

print("""------- TASK SEVENTEEN -------
       """)

clients = ["DoorDash", "CBC", "Pinterest", "SmallCo"]
clients.sort()
clients.reverse()
print(clients)

print("""------- TASK EIGHTEEN -------
       """)

email_list = []

email_list.append("ADMIN@CBC.ca")
email_list.append("bademail.com")
email_list.append("user@smallco.com")

more_emails = ["sales@newscorp.com", "  TEST@GMAIL.com  "]
email_list.extend(more_emails)

email_list[1] = "support@test.ca"

for email in email_list:
    clean_email = email.strip().lower()
    if "@" in clean_email:
        print(clean_email)

print("""------- TASK NINETEEN -------
       """)

clients = ["CBC", "Test Client", "SmallCo", "DoorDash", "CBC"]
print(clients)
print(clients.count("CBC"))
if "Test Client" in clients:
    clients.remove("Test Client")
else:
    print("Client not found.")

clients.append("News Corp")
clients.sort()
print(clients)

print("""------- TASK TWENTY -------
       """)

emails = []
emails.append("  A@GMAIL.com  ")
emails.append("bademail.com")
emails.append("C@Test.ca ")
emails.insert(0,"first@client.com" )
emails.extend( ["extra@yahoo.com", "wrong-email"])
if "wrong-email" in emails:
    emails.remove("wrong-email")
else:
    print("email not found.")
emails.sort()
for email in emails:
    clean_email = email.strip().lower()
    if "@" in clean_email:
        print(clean_email)















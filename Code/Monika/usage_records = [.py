usage_records = [
  {"email": "alice@smallco.com", "date": "2026-05-03"},
  {"email": "bob@smallco.com", "date": "2026-05-05"},
  {"email": "carol@smallco.com", "date": "2026-05-07"},
  {"email": "dave@smallco.com", "date": "2026-05-10"},
  {"email": "erin@trialdomain.com", "date": "2026-05-12"},
  {"email": "frank@trialdomain.com", "date": "2026-05-15"},
  {"email": "grace@startup.io", "date": "2026-05-18"},
  {"email": "henry@startup.io", "date": "2026-05-20"},
  {"email": "isabel@example.org", "date": "2026-05-22"},
  {"email": "jack@example.org", "date": "2026-05-25"},
  {"email": "karen@smallco.com", "date": "2026-05-27"},
  {"email": "liam@trialdomain.com", "date": "2026-05-29"},
  {"email": "maya@startup.io", "date": "2026-06-01"},
  {"email": "noah@example.org", "date": "2026-06-03"},
  {"email": "olivia@smallco.com", "date": "2026-06-05"},
  {"email": "peter@trialdomain.com", "date": "2026-06-07"},
  {"email": "quinn@startup.io", "date": "2026-06-09"},
  {"email": "rachel@example.org", "date": "2026-06-11"},
  {"email": "sam@smallco.com", "date": "2026-06-13"},
  {"email": "tom@trialdomain.com", "date": "2026-06-14"}
]


day_key = usage_records("date")
print(day_key)
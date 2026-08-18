"""Quick-start examples for fortisec."""

from fortisec import identify_hash, redact_logs, safe_join, shannon_entropy, validate_email

print(validate_email("admin@example.com"))
print(identify_hash("d41d8cd98f00b204e9800998ecf8427e"))
print(round(shannon_entropy("a9f8d7s6g5h4j3k2l1z0"), 2))
print(redact_logs("Authorization: Bearer secret-token from admin@example.com"))
print(safe_join("/tmp/uploads", "avatars", "me.png"))


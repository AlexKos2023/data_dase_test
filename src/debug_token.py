from pprint import pprint
from db import query_db

rows = query_db("""
    SELECT s.token, s.expires_at, u.email
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    ORDER BY u.email, s.expires_at DESC
""", fetch=True)

pprint(rows)
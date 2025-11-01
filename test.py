import psycopg2

conn = psycopg2.connect("postgresql://postgres:1234@localhost:5432/supabase_login")
print("✅ Connected successfully!")
conn.close()
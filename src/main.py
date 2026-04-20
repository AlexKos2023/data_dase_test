from db import open_create_BD, init_rbac_tables

PASSW = input("Введите пароль: ")

connection = open_create_BD(PASSW)
init_rbac_tables(connection)
connection.close()

print("База и таблицы созданы")

from db import open_create_BD, init_rbac_tables
from auth import (
    init_first_primary_admin,
    register_user,
    login_user,
    assign_role_to_user,
    delete_account,
    delete_user_by_id,
    get_current_user,
)


def print_result(title, result):
    print(f"\n--- {title} ---")
    print(result)


if __name__ == "__main__":
    conn = open_create_BD('Vostok72')
    init_rbac_tables(conn)
    conn.close()

    print_result(
        "Init primary admin",
        init_first_primary_admin('Главный', 'Админ', 'Системный', 'admin@mail.com', '123456')
    )

    print_result(
        "Register user",
        register_user('Иван', 'Иванов', 'Иванович', 'user@mail.com', '123456', '123456')
    )

    print_result(
        "Register moderator",
        register_user('Пётр', 'Петров', 'Петрович', 'mod@mail.com', '123456', '123456')
    )

    ok_user, msg_user, token_user = login_user('user@mail.com', '123456')
    ok_mod, msg_mod, token_mod = login_user('mod@mail.com', '123456')
    ok_admin, msg_admin, token_admin = login_user('admin@mail.com', '123456')

    print_result("Login user", (ok_user, msg_user, token_user))
    print_result("Login moderator", (ok_mod, msg_mod, token_mod))
    print_result("Login admin", (ok_admin, msg_admin, token_admin))

    if not (ok_user and ok_mod and ok_admin):
        raise SystemExit("Login failed")

    user_row = get_current_user(token_user)
    mod_row = get_current_user(token_mod)
    admin_row = get_current_user(token_admin)

    user_id = user_row['id'] if user_row else None
    mod_id = mod_row['id'] if mod_row else None
    admin_id = admin_row['id'] if admin_row else None

    print("\n=== ROLE TESTS ===")

    print("\n--- test_admin_can_manage_roles ---")
    print(assign_role_to_user(token_admin, 'user@mail.com', 'moderator'))

    print("\n--- test_moderator_cannot_manage_roles ---")
    print(assign_role_to_user(token_mod, 'user@mail.com', 'user'))

    print("\n--- test_admin_can_delete_user ---")
    if mod_id:
        print(delete_user_by_id(token_admin, mod_id))
    else:
        print((False, 'moderator не найден'))

    print("\n--- test_moderator_cannot_delete_user ---")
    if user_id:
        print(delete_user_by_id(token_mod, user_id))
    else:
        print((False, 'user не найден'))

    print("\n--- test_cannot_delete_primary_admin ---")
    if admin_id:
        print(delete_user_by_id(token_admin, admin_id))
    else:
        print((False, 'admin не найден'))

    print("\n--- test_user_delete_self ---")
    print(delete_account(token_user))

    print_result(
        "Register guest",
        register_user('Гость', 'Гостев', 'Гостевич', 'guest@mail.com', '123456', '123456')
    )

    ok_guest, msg_guest, token_guest = login_user('guest@mail.com', '123456')
    print_result("Login guest", (ok_guest, msg_guest, token_guest))

    if not ok_guest:
        raise SystemExit("Guest login failed")

    guest_row = get_current_user(token_guest)
    guest_id = guest_row['id'] if guest_row else None
    print_result("Guest current user", guest_row)
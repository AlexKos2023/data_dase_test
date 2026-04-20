from db import open_create_BD, init_rbac_tables
from auth import (
    init_first_primary_admin,
    register_user,
    login_user,
    assign_role_to_user,
)
from mock_views import create_post, get_posts, update_post, delete_post


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
        "Register user1",
        register_user('Иван', 'Иванов', 'Иванович', 'user1@mail.com', '123456', '123456')
    )

    print_result(
        "Register user2",
        register_user('Пётр', 'Петров', 'Петрович', 'user2@mail.com', '123456', '123456')
    )

    ok_admin, admin_msg, admin_token = login_user('admin@mail.com', '123456')
    print_result("Login admin", (ok_admin, admin_msg, admin_token))

    if not ok_admin:
        raise SystemExit("Admin login failed")

    print_result(
        "Assign user role to user1",
        assign_role_to_user(admin_token, 'user1@mail.com', 'user')
    )

    print_result(
        "Assign moderator role to user2",
        assign_role_to_user(admin_token, 'user2@mail.com', 'moderator')
    )

    ok1, msg1, token1 = login_user('user1@mail.com', '123456')
    ok2, msg2, token2 = login_user('user2@mail.com', '123456')

    print_result("Login user1", (ok1, msg1, token1))
    print_result("Login user2", (ok2, msg2, token2))

    if not ok1 or not ok2:
        raise SystemExit("Login failed")

    post1 = create_post(token1, 'Пост юзера 1', 'Текст поста юзера 1')
    print_result("User1 creates own post", post1)

    post2 = create_post(token2, 'Пост модератора', 'Текст поста модератора')
    print_result("User2 creates own post", post2)

    posts = get_posts(token1)
    print_result("User1 reads posts", posts)

    posts_data = posts.get('data', [])
    post_user1 = None
    post_user2 = None

    for p in posts_data:
        if p['author_email'] == 'user1@mail.com':
            post_user1 = p
        elif p['author_email'] == 'user2@mail.com':
            post_user2 = p

    if post_user1:
        print_result(
            "User1 edits own post",
            update_post(token1, post_user1['id'], 'Юзер 1 обновил', 'Новый текст юзера 1')
        )

    if post_user2:
        print_result(
            "User1 tries to edit moderator post",
            update_post(token1, post_user2['id'], 'Попытка чужого редактирования', 'Не должно пройти')
        )

    if post_user1:
        print_result(
            "Moderator edits user1 post",
            update_post(token2, post_user1['id'], 'Модер отредактировал', 'Текст после модератора')
        )

    if post_user2:
        print_result(
            "User1 tries to delete moderator post",
            delete_post(token1, post_user2['id'])
        )

    if post_user1:
        print_result(
            "Moderator deletes user1 post",
            delete_post(token2, post_user1['id'])
        )
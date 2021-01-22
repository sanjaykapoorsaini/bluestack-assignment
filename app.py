#!/usr/bin/env python

import rbac.acl

# create access control list
acl = rbac.acl.Registry()

# add Default roles
acl.add_role("admin")
acl.add_role("developer")

# add Default users
acl.add_user("admin", ["admin"])
acl.add_user("user1", ["developer"])

# add resources
acl.add_resource("resource-1")
acl.add_resource("resource-2")

# set rules
# Admin have all permissions
acl.allow("admin", "read", "resource-1")
acl.allow("admin", "write", "resource-1")
acl.allow("admin", "delete", "resource-1")

acl.allow("admin", "read", "resource-2")
acl.allow("admin", "write", "resource-2")
acl.allow("admin", "delete", "resource-2")

# Developer have read, write permission but not delete
acl.allow("developer", "read", "resource-1")
acl.allow("developer", "write", "resource-1")
acl.deny("developer", "delete", "resource-1")


def edit_role(user):
    role = input("which role you want to edit ")
    if acl.is_valid_role(role):
        allowed, denied = acl.get_role_permissions(role)
        print(
            f" Current permissions for {role} are: Allowed: {allowed}, Denied: {denied}"
        )
        print(f" All available resources are: {acl.get_all_resources()}")
        resource = input(" Enter resource name ")
        if acl.is_valid_resource(resource):
            operation = input(
                "  Enter permission name like read, write or delete ")
            allow_or_deny = input(
                "  Enter permission Type, Press 1 for Allow, 2 for deny "
            )
            if allow_or_deny == "1":
                acl.allow(role, operation, resource)
            elif allow_or_deny == "2":
                acl.deny(role, operation, resource)
            else:
                print("Wrong input {allow_or_deny}")
                start_intracting(user)
            allowed, denied = acl.get_role_permissions(role)
            print(
                f" Updated permissions for {role} are: Allowed: {allowed}, Denied: {denied}"
            )
        else:
            print(
                f" This {resource} is not a valid resource, you can try again")
            edit_role(user)
    else:
        print(f"{role} is not valid role")
        print(" Valid roles are: ", acl.get_all_roles())
        print(" Press X for restart: ")
        if role.lower() == "x":
            start_intracting(user)
        edit_role(user)


def create_user():
    user = input(" Type new user name ")
    role_list = []
    while True:
        role = input("  Please provide a role of new user ")
        if role == "1":
            break
        role_list.append(role)
        acl.add_role(role)
        print("  Press 1 if you are done with all roles ")

    acl.add_user(user, role_list)
    print(f"sucessfully created new uer {user} with role(s) {role_list}")


def login_user(user):
    user = input("Login with user name ")
    if acl.is_valid_user(user):
        start_intracting(user)
    else:
        print(f"{user} is not valid user")
        print("valid users with roles are: ", acl.get_all_users())
        login_user(user)


def view_role(user):
    print(f"All roles associated with {user} are {acl.get_user_role(user)}")


def view_resource(user):
    print(acl.get_user_resources(user))


def add_resource():
    resource = input(" Enter the name of new resource ")
    acl.add_resource(resource)
    print(f" Sucessfully created new resource {resource}")
    print(f" Updated resources list is {acl.get_all_resources()}")


def start_intracting(user):
    print()
    print()
    print(f"hi! you are logged in as {user}")
    print("press 1 for login as another user")
    if user == "admin":
        print("press 2 for create user")
        print("press 3 for edit role")
        print("press 4 for add resource")
    else:
        print("press 2 for view roles")
        print("press 3 for access resource")
    print("press 9 to exit")
    input_num = input()
    if input_num == "1":
        login_user(user)
    elif user == "admin" and input_num == "2":
        create_user()
        start_intracting(user)
    elif user == "admin" and input_num == "3":
        edit_role(user)
        print("sucessfully edited the role")
        start_intracting(user)
    elif user == "admin" and input_num == "4":
        add_resource()
        start_intracting(user)
    elif input_num == "2":
        view_role(user)
        start_intracting(user)
    elif input_num == "3":
        view_resource(user)
        start_intracting(user)
    elif input_num == "9":
        return
    else:
        print("Wrong input Try again")
        start_intracting(user)


if __name__ == "__main__":
    start_intracting("admin")

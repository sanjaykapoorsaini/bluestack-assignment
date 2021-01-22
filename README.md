# Assignment: Role Based Access Control
Implement a role based auth system. System should be able to assign a
role to a user and remove a role from a user.

Entities are USER, ACTION TYPE, RESOURCE, ROLE

ACTION TYPE defines the access level (Ex: READ, WRITE, DELETE)

Access to resources for users are controlled strictly by the role. One
user can have multiple roles. Given a user, action type and resource,
the system should be able to tell whether user has access or not.


## Quick Start

- By default two users are created Admin and user1
- Two resources are created resource-1, resource-2
- Admin has all access to both the resources, however user1 has only resource-1 access with read and write but not delete.
- Start the program using this command:
```
Python app.py
```

## With admin we have different options and with different users following options

- hi! you are logged in as admin
  - press 1 for login as another user
  - press 2 for create user
  - press 3 for edit role
  - press 4 for add resource
  - press 9 for exit


- hi! you are logged in as User1
    - press 1 for login as another user
    - press 2 for view roles
    - press 3 for access resource
    - press 9 for exit


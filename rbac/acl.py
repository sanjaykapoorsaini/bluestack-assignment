from __future__ import absolute_import

import itertools


__all__ = ["Registry"]


class Registry(object):
    """The registry of access control list."""

    def __init__(self):
        self._roles = {}
        self._resources = {}
        self._allowed = {}
        self._denied = {}
        self._users = {}

        # to allow additional short circuiting, track roles that only
        # ever deny access
        self._denial_only_roles = set()
        self._children = {}

    def get_all_roles(self):
        """Returns all roles."""
        return self._roles

    def get_role_permissions(self, role):
        """Returns all permission for specific role."""
        allowed = [i for i in self._allowed if i[0] == role]
        denied = [i for i in self._denied if i[0] == role]
        return allowed, denied

    def get_all_resources(self):
        """Returns all resources."""
        return self._resources

    def get_all_users(self):
        """Returns all users info."""
        return self._users

    def get_user_role(self, user):
        """Returns all roles associated with specific user."""
        return self.get_all_users()[user]

    def get_user_resources(self, user):
        """Returns all resources associated with specific user."""
        roles = self.get_user_role(user)
        user_resources = {"Allowed": [], "Denied": []}
        for role in roles:
            allowed, denied = self.get_role_permissions(role)
            user_resources["Allowed"].extend(allowed)
            user_resources["Denied"].extend(denied)
        return user_resources

    def is_valid_user(self, user):
        """Checks user validity."""
        return not user or user in self._users

    def is_valid_resource(self, resource):
        """Checks resource validity."""
        return not resource or resource in self._resources

    def is_valid_role(self, role):
        """Checks role validity."""
        return not role or role in self._roles

    def add_user(self, user, roles=[]):
        """
        Add a user with role.
        One user can have multiple roles.
        """
        # validation of role
        for role in roles:
            assert not role or role in self._roles

        self._users.setdefault(user, set())
        self._users[user].update(roles)

    def add_role(self, role, parents=[]):
        """Add a role or append parents roles to a special role.

        All added roles should be hashable.
        (http://docs.python.org/glossary.html#term-hashable)
        """
        self._roles.setdefault(role, set())
        self._roles[role].update(parents)
        for p in parents:
            self._children.setdefault(p, set())
            self._children[p].add(role)

        # all roles start as deny-only (unless one of its parents
        # isn't deny-only)
        if not parents or self._roles_are_deny_only(parents):
            self._denial_only_roles.add(role)

    def add_resource(self, resource, parents=[]):
        """Add a resource or append parents resources to a special resource.

        All added resources should be hashable.
        (http://docs.python.org/glossary.html#term-hashable)
        """
        self._resources.setdefault(resource, set())
        self._resources[resource].update(parents)

    def allow(self, role, operation, resource, assertion=None):
        """Add a allowed rule.

        The added rule will allow the role and its all children roles to
        operate the resource.
        """
        assert not role or role in self._roles
        assert not resource or resource in self._resources
        self._allowed[role, operation, resource] = assertion

        # if self._denied.get((role, operation, resource)) is None:
        #     del self._denied[role, operation, resource]

        # since we just allowed a permission, role and any children aren't
        # denied-only
        for r in itertools.chain([role], get_family(self._children, role)):
            self._denial_only_roles.discard(r)

    def deny(self, role, operation, resource, assertion=None):
        """Add a denied rule.

        The added rule will deny the role and its all children roles to
        operate the resource.
        """
        assert not role or role in self._roles
        assert not resource or resource in self._resources
        self._denied[role, operation, resource] = assertion
        # if self._allowed.get((role, operation, resource)):
        #     del self._allowed[role, operation, resource]

    def is_allowed(
        self, role, operation, resource, check_allowed=True, **assertion_kwargs
    ):
        """Check the permission.

        If the access is denied, this method will return False; if the access
        is allowed, this method will return True; if there is not any rule
        for the access, this method will return None.
        """
        assert not role or role in self._roles
        assert not resource or resource in self._resources

        roles = set(get_family(self._roles, role))
        operations = {None, operation}
        resources = set(get_family(self._resources, resource))

        def DefaultAssertion(*args, **kwargs):
            return True

        is_allowed = None
        default_assertion = DefaultAssertion

        for permission in itertools.product(roles, operations, resources):
            if permission in self._denied:
                assertion = self._denied[permission] or default_assertion
                if assertion(self, role, operation, resource, **assertion_kwargs):
                    return False  # denied by rule immediately

            if check_allowed and permission in self._allowed:
                assertion = self._allowed[permission] or default_assertion
                if assertion(self, role, operation, resource, **assertion_kwargs):
                    is_allowed = True  # allowed by rule

        return is_allowed

    def is_any_allowed(self, roles, operation, resource, **assertion_kwargs):
        """Check the permission with many roles."""
        is_allowed = None  # no matching rules
        for i, role in enumerate(roles):
            # if access not yet allowed and all remaining roles could
            # only deny access, short-circuit and return False
            if not is_allowed and self._roles_are_deny_only(roles[i:]):
                return False

            check_allowed = not is_allowed

            # if another role gave access,
            # don't bother checking if this one is allowed
            is_current_allowed = self.is_allowed(
                role,
                operation,
                resource,
                check_allowed=check_allowed,
                **assertion_kwargs
            )
            if is_current_allowed is False:
                return False  # denied by rule
            elif is_current_allowed is True:
                is_allowed = True
        return is_allowed

    def _roles_are_deny_only(self, roles):
        return all(r in self._denial_only_roles for r in roles)


def get_family(all_parents, current):
    """Iterate current object and its all parents recursively."""
    yield current
    yield from get_parents(all_parents, current)
    yield None


def get_parents(all_parents, current):
    """Iterate current object's all parents."""
    for parent in all_parents.get(current, []):
        yield parent
        yield from get_parents(all_parents, parent)

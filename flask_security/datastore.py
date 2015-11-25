# -*- coding: utf-8 -*-
"""
    flask_security.datastore
    ~~~~~~~~~~~~~~~~~~~~~~~~

    This module contains an user datastore classes.

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2015 by Senol Korkmaz.
    :license: MIT, see LICENSE for more details.
"""

from .utils import get_identity_attributes, string_types


class Datastore(object):
    def __init__(self, db):
        self.db = db

    def commit(self):
        pass

    def put(self, model):
        raise NotImplementedError

    def delete(self, model):
        raise NotImplementedError


class SQLAlchemyDatastore(Datastore):
    def commit(self):
        self.db.session.commit()

    def put(self, model):
        self.db.session.add(model)
        return model

    def delete(self, model):
        self.db.session.delete(model)


class MongoEngineDatastore(Datastore):
    def put(self, model):
        model.save()
        return model

    def delete(self, model):
        model.delete()


class PeeweeDatastore(Datastore):
    def put(self, model):
        model.save()
        return model

    def delete(self, model):
        model.delete_instance()


class UserDatastore(object):
    """Abstracted user datastore.

    :param user_model: A user model class definition
    :param role_model: A role model class definition
    :param group_model: A group model class definition
    """

    def __init__(self, user_model, role_model, group_model):
        self.user_model = user_model
        self.role_model = role_model
        self.group_model = group_model

    def _prepare_role_modify_args(self, user, role):
        if isinstance(user, string_types):
            user = self.find_user(email=user)
        if isinstance(role, string_types):
            role = self.find_role(role)
        return user, role

    def _prepare_group_modify_args(self, user, group):
        if isinstance(user, string_types):
            user = self.find_user(email=user)
        if isinstance(group, string_types):
            group = self.find_group(group)
        return user, group

    def _prepare_create_user_args(self, **kwargs):
        kwargs.setdefault('active', True)

        roles = kwargs.get('roles', [])
        for i, role in enumerate(roles):
            rn = role.name if isinstance(role, self.role_model) else role
            # see if the role exists
            roles[i] = self.find_role(rn)
        kwargs['roles'] = roles

        groups = kwargs.get('groups', [])
        for i, group in enumerate(groups):
            gn = group.name if isinstance(group, self.group_model) else group
            # see if the group exists
            groups[i] = self.find_group(gn)
        kwargs['groups'] = groups

        return kwargs

    def get_user(self, id_or_email):
        """Returns a user matching the specified ID or email address."""
        raise NotImplementedError

    def find_user(self, *args, **kwargs):
        """Returns a user matching the provided parameters."""
        raise NotImplementedError

    def find_role(self, *args, **kwargs):
        """Returns a role matching the provided name."""
        raise NotImplementedError

    def find_group(self, *args, **kwargs):
        """Returns a group matching the provided name."""
        raise NotImplementedError

    def add_role_to_user(self, user, role):
        """Adds a role to a user.

        :param user: The user to manipulate
        :param role: The role to add to the user
        """
        user, role = self._prepare_role_modify_args(user, role)
        if role not in user.roles:
            user.roles.append(role)
            self.put(user)
            return True
        return False

    def add_user_to_group(self, user, group):
        """Adds an user to a group.

        :param user: The user to manipulate
        :param group: The group to add the user to
        """
        user, group = self._prepare_group_modify_args(user, group)
        if group not in user.groups:
            user.groups.append(group)
            self.put(user)
            return True
        return False

    def remove_role_from_user(self, user, role):
        """Removes a role from a user.

        :param user: The user to manipulate
        :param role: The role to remove from the user
        """
        rv = False
        user, role = self._prepare_role_modify_args(user, role)
        if role in user.roles:
            rv = True
            user.roles.remove(role)
            self.put(user)
        return rv

    def remove_user_from_group(self, user, group):
        """Removes an user from a group.

        :param user: The user to manipulate
        :param group: The group to remove the the user from
        """
        rv = False
        user, group = self._prepare_group_modify_args(user, group)
        if group in user.groups:
            rv = True
            user.groups.remove(group)
            self.put(user)
        return rv

    def toggle_active(self, user):
        """Toggles a user's active status. Always returns True."""
        user.active = not user.active
        return True

    def deactivate_user(self, user):
        """Deactivates a specified user. Returns `True` if a change was made.

        :param user: The user to deactivate
        """
        if user.active:
            user.active = False
            return True
        return False

    def activate_user(self, user):
        """Activates a specified user. Returns `True` if a change was made.

        :param user: The user to activate
        """
        if not user.active:
            user.active = True
            return True
        return False

    def create_role(self, **kwargs):
        """Creates and returns a new role from the given parameters."""

        role = self.role_model(**kwargs)
        return self.put(role)

    def find_or_create_role(self, name, **kwargs):
        """Returns a role matching the given name or creates it with any
        additionally provided parameters.
        """
        kwargs["name"] = name
        return self.find_role(name) or self.create_role(**kwargs)

    def create_group(self, **kwargs):
        """Creates and returns a new group from the given parameters."""

        group = self.group_model(**kwargs)
        return self.put(group)

    def find_or_create_group(self, name, **kwargs):
        """Returns a group matching the given name or creates it with any
        additionally provided parameters.
        """
        kwargs["name"] = name
        return self.find_group(name) or self.create_group(**kwargs)

    def create_user(self, **kwargs):
        """Creates and returns a new user from the given parameters."""
        kwargs = self._prepare_create_user_args(**kwargs)
        user = self.user_model(**kwargs)
        return self.put(user)

    def delete_user(self, user):
        """Deletes the specified user.

        :param user: The user to delete
        """
        self.delete(user)


class SQLAlchemyUserDatastore(SQLAlchemyDatastore, UserDatastore):
    """A SQLAlchemy datastore implementation for Flask-Security that assumes the
    use of the Flask-SQLAlchemy extension.
    """
    def __init__(self, db, user_model, role_model, group_model):
        SQLAlchemyDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model, group_model)

    def get_user(self, identifier):
        if self._is_numeric(identifier):
            return self.user_model.query.get(identifier)
        for attr in get_identity_attributes():
            query = getattr(self.user_model, attr).ilike(identifier)
            rv = self.user_model.query.filter(query).first()
            if rv is not None:
                return rv

    def _is_numeric(self, value):
        try:
            int(value)
        except (TypeError, ValueError):
            return False
        return True

    def find_user(self, **kwargs):
        return self.user_model.query.filter_by(**kwargs).first()

    def find_role(self, role):
        return self.role_model.query.filter_by(name=role).first()

    def find_group(self, group):
        return self.group_model.query.filter_by(name=group).first()


class MongoEngineUserDatastore(MongoEngineDatastore, UserDatastore):
    """A MongoEngine datastore implementation for Flask-Security that assumes
    the use of the Flask-MongoEngine extension.
    """
    def __init__(self, db, user_model, role_model, group_model):
        MongoEngineDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model, group_model)

    def get_user(self, identifier):
        from mongoengine import ValidationError
        try:
            return self.user_model.objects(id=identifier).first()
        except ValidationError:
            pass
        for attr in get_identity_attributes():
            query_key = '%s__iexact' % attr
            query = {query_key: identifier}
            rv = self.user_model.objects(**query).first()
            if rv is not None:
                return rv

    def find_user(self, **kwargs):
        try:
            from mongoengine.queryset import Q, QCombination
        except ImportError:
            from mongoengine.queryset.visitor import Q, QCombination
        from mongoengine.errors import ValidationError

        queries = map(lambda i: Q(**{i[0]: i[1]}), kwargs.items())
        query = QCombination(QCombination.AND, queries)
        try:
            return self.user_model.objects(query).first()
        except ValidationError:  # pragma: no cover
            return None

    def find_role(self, role):
        return self.role_model.objects(name=role).first()

    def find_group(self, group):
        return self.group_model.objects(name=group).first()

    # TODO: Not sure why this was added but tests pass without it
    # def add_role_to_user(self, user, role):
    #     rv = super(MongoEngineUserDatastore, self).add_role_to_user(user, role)
    #     if rv:
    #         self.put(user)
    #     return rv


class PeeweeUserDatastore(PeeweeDatastore, UserDatastore):
    """A PeeweeD datastore implementation for Flask-Security that assumes
    the use of the Flask-Peewee extension.

    :param user_model: A user model class definition
    :param role_model: A role model class definition
    :param role_link: A model implementing the many-to-many user-role relation
    """
    def __init__(self, db, user_model, role_model, role_link, group_model, group_link):
        PeeweeDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model, group_model)
        self.UserRole = role_link
        self.UserGroup = group_link

    def get_user(self, identifier):
        try:
            return self.user_model.get(self.user_model.id == identifier)
        except ValueError:
            pass

        for attr in get_identity_attributes():
            column = getattr(self.user_model, attr)
            try:
                return self.user_model.get(column ** identifier)
            except self.user_model.DoesNotExist:
                pass

    def find_user(self, **kwargs):
        try:
            return self.user_model.filter(**kwargs).get()
        except self.user_model.DoesNotExist:
            return None

    def find_role(self, role):
        try:
            return self.role_model.filter(name=role).get()
        except self.role_model.DoesNotExist:
            return None

    def find_group(self, group):
        try:
            return self.group_model.filter(name=group).get()
        except self.group_model.DoesNotExist:
            return None

    def create_user(self, **kwargs):
        """Creates and returns a new user from the given parameters."""
        roles = kwargs.pop('roles', [])
        groups = kwargs.pop('groups', [])
        user = self.user_model(**self._prepare_create_user_args(**kwargs))
        user = self.put(user)
        for role in roles:
            self.add_role_to_user(user, role)
        for group in groups:
            self.add_user_to_group(user, group)
        self.put(user)
        return user

    def add_role_to_user(self, user, role):
        """Adds a role to a user.

        :param user: The user to manipulate
        :param role: The role to add to the user
        """
        user, role = self._prepare_role_modify_args(user, role)
        result = self.UserRole.select() \
            .where(self.UserRole.user == user.id, self.UserRole.role == role.id)
        if result.count():
            return False
        else:
            self.put(self.UserRole.create(user=user.id, role=role.id))
            return True

    def remove_role_from_user(self, user, role):
        """Removes a role from a user.

        :param user: The user to manipulate
        :param role: The role to remove from the user
        """
        user, role = self._prepare_role_modify_args(user, role)
        result = self.UserRole.select() \
            .where(self.UserRole.user == user, self.UserRole.role == role)
        if result.count():
            query = self.UserRole.delete().where(
                self.UserRole.user == user, self.UserRole.role == role)
            query.execute()
            return True
        else:
            return False

    def add_user_to_group(self, user, group):
        """Adds an user to a group.

        :param user: The user to manipulate
        :param group: The group to add the user to
        """
        user, group = self._prepare_group_modify_args(user, group)
        result = self.UserGroup.select() \
            .where(self.UserGroup.user == user.id, self.UserGroup.group == group.id)
        if result.count():
            return False
        else:
            self.put(self.UserGroup.create(user=user.id, group=group.id))
            return True

    def remove_user_from_group(self, user, group):
        """Removes an user from a group.

        :param user: The user to manipulate
        :param group: The group to remove the user from
        """
        user, group = self._prepare_group_modify_args(user, group)
        result = self.UserGroup.select() \
            .where(self.UserGroup.user == user, self.UserGroup.group == group)
        if result.count():
            query = self.UserGroup.delete().where(
                self.UserGroup.user == user, self.UserGroup.group == group)
            query.execute()
            return True
        else:
            return False

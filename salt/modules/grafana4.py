# -*- coding: utf-8 -*-
'''
Module for working with the Grafana v4 API

.. versionadded:: 2017.7.0

:depends: requests

:configuration: This module requires a configuration profile to be configured
    in the minion config, minion pillar, or master config.
    The module will use the 'grafana' key by default, if defined.

    For example:

    .. code-block:: yaml

        grafana:
            grafana_url: http://grafana.localhost
            grafana_user: admin
            grafana_password: admin
            grafana_timeout: 3
'''
from __future__ import absolute_import, print_function, unicode_literals

try:
    import requests
    HAS_LIBS = True
except ImportError:
    HAS_LIBS = False

from salt.ext.six import string_types


__virtualname__ = 'grafana4'


def __virtual__():
    '''
    Only load if requests is installed
    '''
    if HAS_LIBS:
        return __virtualname__
    else:
        return False, 'The "{0}" module could not be loaded: ' \
                      '"requests" is not installed.'.format(__virtualname__)


def _get_headers(profile):
    headers = {'Content-type': 'application/json'}
    if profile.get('grafana_token', False):
        headers['Authorization'] = 'Bearer {0}'.format(
            profile['grafana_token'])
    return headers


def _get_auth(profile):
    if profile.get('grafana_token', False):
        return None
    return requests.auth.HTTPBasicAuth(
        profile['grafana_user'],
        profile['grafana_password']
    )


def get_users(profile='grafana'):
    '''
    List all users.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.get_users
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    response = requests.get(
        '{0}/api/users'.format(profile['grafana_url']),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def get_user(login, profile='grafana'):
    '''
    Show a single user.

    login
        Login of the user.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.get_user <login>
    '''
    data = get_users(profile)
    for user in data:
        if user['login'] == login:
            return user
    return None


def get_user_data(user_id, profile='grafana'):
    '''
    Get user data.

    user_id
        Id of the user.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.get_user_data <user_id>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    response = requests.get(
        '{0}/api/users/{1}'.format(profile['grafana_url'], user_id),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def create_user(profile='grafana', **kwargs):
    '''
    Create a new user.

    login
        Login of the new user.

    password
        Password of the new user.

    email
        Email of the new user.

    name
        Optional - Full name of the new user.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.create_user login=<login> password=<password> email=<email>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    response = requests.post(
        '{0}/api/admin/users'.format(profile['grafana_url']),
        json=kwargs,
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def update_user(user_id, profile='grafana', org_id=None, **kwargs):
    '''
    Update an existing user.

    user_id
        Id of the user.

    login
        Optional - Login of the user.

    email
        Optional - Email of the user.

    name
        Optional - Full name of the user.

    org_id
        Optional - Default Organization of the user.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.update_user <user_id> login=<login> email=<email>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    response = requests.put(
        '{0}/api/users/{1}'.format(profile['grafana_url'], user_id),
        json=kwargs,
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    if org_id:
        response2 = requests.post(
            '{0}/api/users/{1}/using/{2}'.format(profile['grafana_url'], user_id, org_id),
            auth=_get_auth(profile),
            headers=_get_headers(profile),
            timeout=profile.get('grafana_timeout', 3),
        )
        if response2.status_code >= 400:
            response2.raise_for_status()
    return response.json()


def update_user_password(user_id, profile='grafana', **kwargs):
    '''
    Update a user password.

    user_id
        Id of the user.

    password
        New password of the user.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.update_user_password <user_id> password=<password>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    response = requests.put(
        '{0}/api/admin/users/{1}/password'.format(
            profile['grafana_url'], user_id),
        json=kwargs,
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def update_user_permissions(user_id, profile='grafana', **kwargs):
    '''
    Update a user password.

    user_id
        Id of the user.

    isGrafanaAdmin
        Whether user is a Grafana admin.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.update_user_permissions <user_id> isGrafanaAdmin=<true|false>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    response = requests.put(
        '{0}/api/admin/users/{1}/permissions'.format(
            profile['grafana_url'], user_id),
        json=kwargs,
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def delete_user(user_id, profile='grafana'):
    '''
    Delete a user.

    user_id
        Id of the user.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.delete_user <user_id>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    response = requests.delete(
        '{0}/api/admin/users/{1}'.format(profile['grafana_url'], user_id),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def get_user_orgs(user_id, profile='grafana'):
    '''
    Get the list of organisations a user belong to.

    user_id
        Id of the user.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.get_user_orgs <user_id>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    response = requests.get(
        '{0}/api/users/{1}/orgs'.format(profile['grafana_url'], user_id),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def delete_user_org(user_id, org_id, profile='grafana'):
    '''
    Remove a user from an organization.

    user_id
        Id of the user.

    org_id
        Id of the organization.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.delete_user_org <user_id> <org_id>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    response = requests.delete(
        '{0}/api/orgs/{1}/users/{2}'.format(
            profile['grafana_url'], org_id, user_id),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def get_orgs(profile='grafana'):
    '''
    List all organizations.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.get_orgs
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    response = requests.get(
        '{0}/api/orgs'.format(profile['grafana_url']),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def get_org(name, profile='grafana'):
    '''
    Show a single organization.

    name
        Name of the organization.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.get_org <name>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    response = requests.get(
        '{0}/api/orgs/name/{1}'.format(profile['grafana_url'], name),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def switch_org(org_name, profile='grafana'):
    '''
    Switch the current organization.

    name
        Name of the organization to switch to.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.switch_org <name>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    org = get_org(org_name, profile)
    response = requests.post(
        '{0}/api/user/using/{1}'.format(profile['grafana_url'], org['id']),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return org


def get_org_users(org_name=None, profile='grafana'):
    '''
    Get the list of users that belong to the organization.

    org_name
        Name of the organization.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.get_org_users <org_name>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    if org_name:
        switch_org(org_name, profile)
    response = requests.get(
        '{0}/api/org/users'.format(profile['grafana_url']),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def create_org_user(org_name=None, profile='grafana', **kwargs):
    '''
    Add user to the organization.

    loginOrEmail
        Login or email of the user.

    role
        Role of the user for this organization. Should be one of:
            - Admin
            - Editor
            - Read Only Editor
            - Viewer

    org_name
        Name of the organization in which users are added.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.create_org_user <org_name> loginOrEmail=<loginOrEmail> role=<role>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    if org_name:
        switch_org(org_name, profile)
    response = requests.post(
        '{0}/api/org/users'.format(profile['grafana_url']),
        json=kwargs,
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def update_org_user(user_id, org_name=None, profile='grafana', **kwargs):
    '''
    Update user role in the organization.

    user_id
        Id of the user.

    loginOrEmail
        Login or email of the user.

    role
        Role of the user for this organization. Should be one of:
            - Admin
            - Editor
            - Read Only Editor
            - Viewer

    org_name
        Name of the organization in which users are updated.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.update_org_user <user_id> <org_name> loginOrEmail=<loginOrEmail> role=<role>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    if org_name:
        switch_org(org_name, profile)
    response = requests.patch(
        '{0}/api/org/users/{1}'.format(profile['grafana_url'], user_id),
        json=kwargs,
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def delete_org_user(user_id, org_name=None, profile='grafana'):
    '''
    Remove user from the organization.

    user_id
        Id of the user.

    org_name
        Name of the organization in which users are updated.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.delete_org_user <user_id> <org_name>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    if org_name:
        switch_org(org_name, profile)
    response = requests.delete(
        '{0}/api/org/users/{1}'.format(profile['grafana_url'], user_id),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def get_org_address(org_name=None, profile='grafana'):
    '''
    Get the organization address.

    org_name
        Name of the organization in which users are updated.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.get_org_address <org_name>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    if org_name:
        switch_org(org_name, profile)
    response = requests.get(
        '{0}/api/org/address'.format(profile['grafana_url']),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def update_org_address(org_name=None, profile='grafana', **kwargs):
    '''
    Update the organization address.

    org_name
        Name of the organization in which users are updated.

    address1
        Optional - address1 of the org.

    address2
        Optional - address2 of the org.

    city
        Optional - city of the org.

    zip_code
        Optional - zip_code of the org.

    state
        Optional - state of the org.

    country
        Optional - country of the org.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.update_org_address <org_name> country=<country>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    if org_name:
        switch_org(org_name, profile)
    response = requests.put(
        '{0}/api/org/address'.format(profile['grafana_url']),
        json=kwargs,
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def get_org_prefs(org_name=None, profile='grafana'):
    '''
    Get the organization preferences.

    org_name
        Name of the organization in which users are updated.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.get_org_prefs <org_name>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    if org_name:
        switch_org(org_name, profile)
    response = requests.get(
        '{0}/api/org/preferences'.format(profile['grafana_url']),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def update_org_prefs(org_name=None, profile='grafana', **kwargs):
    '''
    Update the organization preferences.

    org_name
        Name of the organization in which users are updated.

    theme
        Selected theme for the org.

    homeDashboardId
        Home dashboard for the org.

    timezone
        Timezone for the org (one of: "browser", "utc", or "").

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.update_org_prefs <org_name> theme=<theme> timezone=<timezone>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    if org_name:
        switch_org(org_name, profile)
    response = requests.put(
        '{0}/api/org/preferences'.format(profile['grafana_url']),
        json=kwargs,
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def create_org(profile='grafana', **kwargs):
    '''
    Create a new organization.

    name
        Name of the organization.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.create_org <name>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    response = requests.post(
        '{0}/api/orgs'.format(profile['grafana_url']),
        json=kwargs,
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def update_org(org_id, profile='grafana', **kwargs):
    '''
    Update an existing organization.

    org_id
        Id of the organization.

    name
        New name of the organization.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.update_org <org_id> name=<name>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    response = requests.put(
        '{0}/api/orgs/{1}'.format(profile['grafana_url'], org_id),
        json=kwargs,
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def delete_org(org_id, profile='grafana'):
    '''
    Delete an organization.

    org_id
        Id of the organization.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.delete_org <org_id>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    response = requests.delete(
        '{0}/api/orgs/{1}'.format(profile['grafana_url'], org_id),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def get_datasources(org_name=None, profile='grafana'):
    '''
    List all datasources in an organisation.

    org_name
        Name of the organization.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.get_datasources <org_name>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    if org_name:
        switch_org(org_name, profile)
    response = requests.get(
        '{0}/api/datasources'.format(profile['grafana_url']),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def get_datasource(name, org_name=None, profile='grafana'):
    '''
    Show a single datasource in an organisation.

    name
        Name of the datasource.

    org_name
        Name of the organization.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.get_datasource <name> <org_name>
    '''
    data = get_datasources(org_name=org_name, profile=profile)
    for datasource in data:
        if datasource['name'] == name:
            return datasource
    return None


def create_datasource(org_name=None, profile='grafana', **kwargs):
    '''
    Create a new datasource in an organisation.

    name
        Name of the data source.

    type
        Type of the datasource ('graphite', 'influxdb' etc.).

    access
        Use proxy or direct.

    url
        The URL to the data source API.

    user
        Optional - user to authenticate with the data source.

    password
        Optional - password to authenticate with the data source.

    database
        Optional - database to use with the data source.

    basicAuth
        Optional - set to True to use HTTP basic auth to authenticate with the
        data source.

    basicAuthUser
        Optional - HTTP basic auth username.

    basicAuthPassword
        Optional - HTTP basic auth password.

    jsonData
        Optional - additional json data to post (eg. "timeInterval").

    isDefault
        Optional - set data source as default.

    withCredentials
        Optional - Whether credentials such as cookies or auth headers should
        be sent with cross-site requests.

    typeLogoUrl
        Optional - Logo to use for this datasource.

    org_name
        Name of the organization in which the data source should be created.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.create_datasource

    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    if org_name:
        switch_org(org_name, profile)
    response = requests.post(
        '{0}/api/datasources'.format(profile['grafana_url']),
        json=kwargs,
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def update_datasource(datasourceid, org_name=None, profile='grafana', **kwargs):
    '''
    Update a datasource.

    datasourceid
        Id of the datasource.

    name
        Name of the data source.

    type
        Type of the datasource ('graphite', 'influxdb' etc.).

    access
        Use proxy or direct.

    url
        The URL to the data source API.

    user
        Optional - user to authenticate with the data source.

    password
        Optional - password to authenticate with the data source.

    database
        Optional - database to use with the data source.

    basicAuth
        Optional - set to True to use HTTP basic auth to authenticate with the
        data source.

    basicAuthUser
        Optional - HTTP basic auth username.

    basicAuthPassword
        Optional - HTTP basic auth password.

    jsonData
        Optional - additional json data to post (eg. "timeInterval").

    isDefault
        Optional - set data source as default.

    withCredentials
        Optional - Whether credentials such as cookies or auth headers should
        be sent with cross-site requests.

    typeLogoUrl
        Optional - Logo to use for this datasource.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.update_datasource <datasourceid>

    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    response = requests.put(
        '{0}/api/datasources/{1}'.format(profile['grafana_url'], datasourceid),
        json=kwargs,
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    # temporary fix for https://github.com/grafana/grafana/issues/6869
    #return response.json()
    return {}


def delete_datasource(datasourceid, org_name=None, profile='grafana'):
    '''
    Delete a datasource.

    datasourceid
        Id of the datasource.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.delete_datasource <datasource_id>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    response = requests.delete(
        '{0}/api/datasources/{1}'.format(profile['grafana_url'], datasourceid),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def get_dashboard(slug, org_name=None, profile='grafana'):
    '''
    Get a dashboard.

    slug
        Slug (name) of the dashboard.

    org_name
        Name of the organization.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.get_dashboard <slug>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    if org_name:
        switch_org(org_name, profile)
    response = requests.get(
        '{0}/api/dashboards/db/{1}'.format(profile['grafana_url'], slug),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    data = response.json()
    if response.status_code == 404:
        return None
    if response.status_code >= 400:
        response.raise_for_status()
    return data.get('dashboard')


def delete_dashboard(slug, org_name=None, profile='grafana'):
    '''
    Delete a dashboard.

    slug
        Slug (name) of the dashboard.

    org_name
        Name of the organization.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.delete_dashboard <slug>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    if org_name:
        switch_org(org_name, profile)
    response = requests.delete(
        '{0}/api/dashboards/db/{1}'.format(profile['grafana_url'], slug),
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def create_update_dashboard(org_name=None, profile='grafana', **kwargs):
    '''
    Create or update a dashboard.

    dashboard
        A dict that defines the dashboard to create/update.

    overwrite
        Whether the dashboard should be overwritten if already existing.

    org_name
        Name of the organization.

    profile
        Configuration profile used to connect to the Grafana instance.
        Default is 'grafana'.

    CLI Example:

    .. code-block:: bash

        salt '*' grafana4.create_update_dashboard dashboard=<dashboard> overwrite=True org_name=<org_name>
    '''
    if isinstance(profile, string_types):
        profile = __salt__['config.option'](profile)
    if org_name:
        switch_org(org_name, profile)
    response = requests.post(
        "{0}/api/dashboards/db".format(profile.get('grafana_url')),
        json=kwargs,
        auth=_get_auth(profile),
        headers=_get_headers(profile),
        timeout=profile.get('grafana_timeout', 3),
    )
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()

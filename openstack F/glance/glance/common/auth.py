# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
auth模块的作用是为了让Openstack客户端从多种认证策略中选择一种作为认证策略,
包括无认证(默认)和Keystone (身份管理系统).

    > auth_plugin = AuthPlugin(creds)

    > auth_plugin.authenticate()

    > auth_plugin.auth_token
    abcdefg

    > auth_plugin.management_url
    http://service_endpoint/
"""
import json
import urlparse     #url解析

import httplib2     #网络访问

from glance.common import exception             #glance异常处理
import glance.openstack.common.log as logging   #glance日志  


LOG = logging.getLogger(__name__)


class BaseStrategy(object):                     #认证策略基类
    def __init__(self):
        self.auth_token = None
        # TODO(sirp): Should expose selecting public/internal/admin URL.
        self.management_url = None

    def authenticate(self):                     #认证方法
        raise NotImplementedError

    @property
    def is_authenticated(self):                 #是否已认证
        raise NotImplementedError

    @property
    def strategy(self):                         #认证策略
        raise NotImplementedError


class NoAuthStrategy(BaseStrategy):             #无认证策略
    def authenticate(self):                     
        pass

    @property
    def is_authenticated(self):                 #是否已认证：因为无认证策略，直接返回True
        return True

    @property
    def strategy(self):                         #认证策略：无认证策略，返回'noauth'
        return 'noauth'


class KeystoneStrategy(BaseStrategy):           #使用keystone认证
    MAX_REDIRECTS = 10                          #设置最大尝试认证次数为10次

    def __init__(self, creds, insecure=False):  #creds认证需要的信息，insecure是否使用ssl
        self.creds = creds
        self.insecure = insecure
        super(KeystoneStrategy, self).__init__()

    def check_auth_params(self):                 #检查认证参数 
        # 确保按要求提供认证参数
        for required in ('username', 'password', 'auth_url',
                         'strategy'):
            if required not in self.creds:
                raise exception.MissingCredentialError(required=required)
        if self.creds['strategy'] != 'keystone': #检查认证策略是否为keystone
            raise exception.BadAuthStrategy(expected='keystone',
                                            received=self.creds['strategy'])
        # 使用Keystone V2.0 还会检查tenant是否存在
        if self.creds['auth_url'].rstrip('/').endswith('v2.0'):
            if 'tenant' not in self.creds:
                raise exception.MissingCredentialError(required='tenant')

    def authenticate(self):
        """通过keystone服务进行认证.

        需要注意的一些情况:

        1. 我们是使用的什么版本的keystone? 
           v1使用包含在request headers中的键值对传递认证信息.
           v2使用包含在request body中的JSON数据传递认证信息.

        2. Keystone可能会使用305状态码返回一个重定向地址.

        3. 我们可能会在请求v2的情况下尝试请求v1. 如果这样的话,
            我们会重写url并包含/v2.0/，然后重试请求v2.
        """
        def _authenticate(auth_url):
            # If OS_AUTH_URL is missing a trailing slash add one
            if not auth_url.endswith('/'):
                auth_url += '/'
            token_url = urlparse.urljoin(auth_url, "tokens")
            # 1. Check Keystone version
            is_v2 = auth_url.rstrip('/').endswith('v2.0')        #auth_url是否以‘v2.0’结尾
            if is_v2:
                self._v2_auth(token_url)        #如果是'v2.0'结尾，调用_v2_auth
            else:
                self._v1_auth(token_url)        #如果不是'v2.0'结尾，调用_v1_auth

        self.check_auth_params()                #检查认证参数
        auth_url = self.creds['auth_url']
        for _ in range(self.MAX_REDIRECTS):     #循环最大尝试次数
            try:
                _authenticate(auth_url)         #调用认证方法
            except exception.AuthorizationRedirect as e:   #认证链接重定向
                # 2. Keystone may redirect us
                auth_url = e.url
            except exception.AuthorizationFailure: 
                # 3. In some configurations nova makes redirection to
                # v2.0 keystone endpoint. Also, new location does not
                # contain real endpoint, only hostname and port.
                if 'v2.0' not in auth_url:
                    auth_url = urlparse.urljoin(auth_url, 'v2.0/')  #如果'v2.00'不在auth_url中，则为其加上
            else:
                # If we sucessfully auth'd, then memorize the correct auth_url
                # for future use.
                self.creds['auth_url'] = auth_url
                break
        else:
            # Guard against a redirection loop
            raise exception.MaxRedirectsExceeded(redirects=self.MAX_REDIRECTS)   #重试已到最大次数

    def _v1_auth(self, token_url):       #v1认证方法
        creds = self.creds

        headers = {}
        headers['X-Auth-User'] = creds['username']
        headers['X-Auth-Key'] = creds['password']

        tenant = creds.get('tenant')
        if tenant:                                  #如果tenant有值，则为headers添加'X-Auth-Tenant'属性
            headers['X-Auth-Tenant'] = tenant

        resp, resp_body = self._do_request(token_url, 'GET', headers=headers)       #调用_do_request方法得到response对象和response body

        def _management_url(self, resp):
            for url_header in ('x-image-management-url',
                               'x-server-management-url',
                               'x-glance'):
                try:
                    return resp[url_header]     #遍历'x-image-management-url','x-server-management-url','x-glance'，如果存在则加入response中
                except KeyError as e:
                    not_found = e
            raise not_found

        if resp.status in (200, 204):
            try:
                self.management_url = _management_url(self, resp)
                self.auth_token = resp['x-auth-token']
            except KeyError:
                raise exception.AuthorizationFailure()
        elif resp.status == 305:
            raise exception.AuthorizationRedirect(resp['location'])
        elif resp.status == 400:
            raise exception.AuthBadRequest(url=token_url)
        elif resp.status == 401:
            raise exception.NotAuthenticated()
        elif resp.status == 404:
            raise exception.AuthUrlNotFound(url=token_url)
        else:
            raise Exception(_('Unexpected response: %s') % resp.status)

    def _v2_auth(self, token_url):      #v2认证方法

        creds = self.creds

        creds = {                                   #构造creds
            "auth": {
                "tenantName": creds['tenant'],
                "passwordCredentials": {
                    "username": creds['username'],
                    "password": creds['password']
                    }
                }
            }

        headers = {}
        headers['Content-Type'] = 'application/json'
        req_body = json.dumps(creds)                #转换成json格式并赋值给req_body

        resp, resp_body = self._do_request(         #使用post方式发送请求，得到resp,resp_body
                token_url, 'POST', headers=headers, body=req_body)

        if resp.status == 200:
            resp_auth = json.loads(resp_body)['access']
            creds_region = self.creds.get('region')
            self.management_url = get_endpoint(resp_auth['serviceCatalog'],  
                                               endpoint_region=creds_region)
            self.auth_token = resp_auth['token']['id']
        elif resp.status == 305:
            raise exception.RedirectException(resp['location'])
        elif resp.status == 400:
            raise exception.AuthBadRequest(url=token_url)
        elif resp.status == 401:
            raise exception.NotAuthenticated()
        elif resp.status == 404:
            raise exception.AuthUrlNotFound(url=token_url)
        else:
            raise Exception(_('Unexpected response: %s') % resp.status)

    @property
    def is_authenticated(self):
        return self.auth_token is not None

    @property
    def strategy(self):
        return 'keystone'

    def _do_request(self, url, method, headers=None, body=None):
        headers = headers or {}
        conn = httplib2.Http()          #通过httplib2.Http()发送请求
        conn.force_exception_to_status_code = True
        conn.disable_ssl_certificate_validation = self.insecure
        headers['User-Agent'] = 'glance-client'
        resp, resp_body = conn.request(url, method, headers=headers, body=body)
        return resp, resp_body


def get_plugin_from_strategy(strategy, creds=None, insecure=False):
    if strategy == 'noauth':
        return NoAuthStrategy()
    elif strategy == 'keystone':
        return KeystoneStrategy(creds, insecure)
    else:
        raise Exception(_("Unknown auth strategy '%s'") % strategy)


def get_endpoint(service_catalog, service_type='image', endpoint_region=None,
                 endpoint_type='publicURL'):
    """
    Select an endpoint from the service catalog

    We search the full service catalog for services
    matching both type and region. If the client
    supplied no region then any 'image' endpoint
    is considered a match. There must be one -- and
    only one -- successful match in the catalog,
    otherwise we will raise an exception.
    """
    endpoint = None
    for service in service_catalog:
        s_type = None
        try:
            s_type = service['type']
        except KeyError:
            msg = _('Encountered service with no "type": %s') % s_type
            LOG.warn(msg)
            continue

        if s_type == service_type:
            for ep in service['endpoints']:
                if endpoint_region is None or endpoint_region == ep['region']:
                    if endpoint is not None:
                        # This is a second match, abort
                        raise exception.RegionAmbiguity(region=endpoint_region)
                    endpoint = ep
    if endpoint and endpoint.get(endpoint_type):
        return endpoint[endpoint_type]
    else:
        raise exception.NoServiceEndpoint()

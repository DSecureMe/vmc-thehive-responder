#!/usr/bin/env python3
"""
 * Licensed to DSecure.me under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. DSeacure.me licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
"""

import re
import json
import requests

from cortexutils.responder import Responder

RESPONDER_TAG = 'downloaded asset data from VMC'
_RALPH_GET_DATA_CENTER_DATA = '{}://{}:{}/api/data-center-assets/?ethernet_set__ipaddress__address={}'
_RALPH_GET_VIRTUAL_SERVER_DATA = '{}://{}:{}/api/virtual-servers/?ip={}'


class VMC(Responder):

    def __init__(self):
        super().__init__()
        self._host = self.get_param(
            'config.vmc_host', 'localhost')
        self._port = self.get_param(
            'config.vmc_port', '80')
        self._insecure_connection = self.get_param(
            'config.vmc_isecure_connection', False)
        self._schema = self.get_param(
            'config.vmc_schema', 'http')
        self._token = self.get_param(
            'config.vmc_token', 'passwd')
        self.data_type = self.get_data()['_type']

    def operations(self, raw):
        print(self.data_type)
        if self.data_type in ['alert', 'task']:
            return [self.build_operation(F'AddTagTo{self.data_type.capitalize()}', tag=RESPONDER_TAG)]
        return super(VMC, self).operations(raw)

    def run(self):
        super().run()
        data = self.get_data()
        print(data)
        tags = data['tags']

        ip_address = self._find_ip_address(tags)
        ralph_config = self._get_ralph_connection_config(tags)

        if ip_address and ralph_config:
            self.report({
                'asset_data': self._get_data_from_ralph(ralph_config, ip_address),
                'vulnerabilities': self._get_vulns(ralph_config, ip_address)
            })
        elif not ip_address and not ralph_config:
            self.report({'error': 'missing ip address and tenant in tag'})
        elif not ralph_config:
            self.report({'error': 'missing tenant config'})
        elif not ip_address:
            self.report({'error': 'missing ip_address'})

    @staticmethod
    def _find_ip_address(tags):
        for tag in tags:
            if re.match(r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b', tag):
                return tag

        return None

    def _get_ralph_connection_config(self, tags):
        for tag in tags:
            tag = tag.split('-')[0]
            url = F'{self._schema}://{self._host}:{self._port}/api/v1/assets-manager/config?name={tag}'
            config = self._action('GET', url, {'Authorization': F'Token {self._token}'},
                                  verify=not self._insecure_connection)
            if config:
                return config
        return None

    def _get_data_from_ralph(self, ralph_config, ip_address):
        try:
            data = self._get_data_from_ralph_base(ralph_config, _RALPH_GET_DATA_CENTER_DATA, ip_address)
            if data:
                return data
            return self._get_data_from_ralph_base(ralph_config, _RALPH_GET_VIRTUAL_SERVER_DATA, ip_address)
        except Exception as e:
            print(e)
        return {}

    def _get_data_from_ralph_base(self, ralph_config, base_url, ip_address):
        url = base_url.format(
            ralph_config['schema'], ralph_config['host'], ralph_config['port'], ip_address
        )
        response = self._action('GET', url, headers={'Authorization': F'Token {self._get_ralph_token(ralph_config)}'},
                                verify=ralph_config['insecure'])
        return response['results']

    def _get_ralph_token(self, ralph_config):
        headers = {
            'Content-Type': 'application/json'
        }
        data = {
            'username': ralph_config['username'],
            'password': ralph_config['password']
        }
        url = F"{ralph_config['schema']}://{ralph_config['host']}:{ralph_config['port']}/api-token-auth/"
        result = self._action('POST', url, headers=headers, data=json.dumps(data), verify=ralph_config['insecure'])
        return result['token']

    def _get_vulns(self, ralph_config, ip_address):
        url = F'{self._schema}://{self._host}:{self._port}/api/v1/vulnerabilities?ip_address={ip_address}'
        if 'tenant' in ralph_config:
            url = F"{url}&tenant={ralph_config['tenant']}"
        return self._action('GET', url, {'Authorization': F'Token {self._token}'}, verify=not self._insecure_connection)

    @staticmethod
    def _action(method, url, headers, **kwargs):
        resp = requests.request(method, url, headers=headers, **kwargs)

        if resp.status_code != 200:
            return None

        return resp.json()


if __name__ == '__main__':
    VMC().run()

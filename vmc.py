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

import json
import requests
from cortexutils.responder import Responder

_VMC_GET_ASSET_MANAGER = '{}://{}:{}/api/v1/assets-manager/config?name={}'
_VMC_GET_VULNS = '{}://{}:{}/api/v1/vulnerabilities?ip_address={}'
_GET_RALPH_TOKEN = '{}://{}:{}/api-token-auth/'
_RALPH_GET_ASSET_DATA = '{}://{}:{}/api/data-center-assets/?ethernet_set__ipaddress__address={}'


class VMC(Responder):

    def __init__(self, job_directory=None):
        super().__init__(job_directory)
        self._host = self.get_param('config.vmc_host', 'localhost')
        self._port = self.get_param('config.vmc_port', '80')
        self._insecure_connection = self.get_param('config.vmc_isecure_connection', False)
        self._schema = self.get_param('config.vmc_schema', 'http')
        self._token = self.get_param('config.vmc_token', 'token')
        self.ip_address = self.get_param('data.sourceRef')

    def operations(self, raw):
        raw.append(self.build_operation('AddTagToAlert', tag='downloaded asset data from VMC'))
        return super().operations(raw)

    def run(self):
        super().run()
        data = self.get_data()
        report = {}
        for tag in data['tags']:

            try:
                ralph_config = self._get_ralph_connection_config(tag)
                report = {
                    'asset_data': self._get_data_from_ralph(ralph_config),
                    'vulnerabilities': self._get_vulns(ralph_config.get('tenant', None))
                }
            except Exception:
                pass

        if report:
            self.report(report)
        else:
            self.report({'asset_data': 'Not Found', 'vulnerabilities': 'Not Found'})

    def _get_ralph_connection_config(self, tag):
        url = _VMC_GET_ASSET_MANAGER.format(self._schema, self._host, self._port, tag)
        return self._action('GET', url, {'Authorization': F'Token {self._token}'}, verify=not self._insecure_connection)

    def _get_data_from_ralph(self, ralph_config):
        url = _RALPH_GET_ASSET_DATA.format(
            ralph_config['schema'], ralph_config['host'], ralph_config['port'], self.ip_address
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
        url = _GET_RALPH_TOKEN.format(
            ralph_config['schema'], ralph_config['host'], ralph_config['port']
        )
        result = self._action('POST', url, headers=headers, data=json.dumps(data), verify=ralph_config['insecure'])
        return result['token']

    def _get_vulns(self, tenant):
        url = _VMC_GET_VULNS.format(self._schema, self._host, self._port, self.ip_address)
        if tenant:
            url = '{}&tenant={}'.format(url, tenant)
        return self._action('GET', url, {'Authorization': F'Token {self._token}'}, verify=not self._insecure_connection)

    @staticmethod
    def _action(method, url, headers, **kwargs):
        try:
            resp = requests.request(method, url, headers=headers, **kwargs)
        except Exception as ex:
            raise Exception(F'Unable connect to {url} reason {ex}')

        if resp.status_code != 200:
            raise Exception(F'Failed to get data from {url}, status {resp.status_code}, {resp.content}')

        return resp.json()


if __name__ == '__main__':
    VMC().run()

#!/usr/bin/python

# Copyright: (c) 2018, Terry Jones <terry.jones@example.org>
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: my_test

short_description: This is my test module

# If this is part of a collection, you need to use semantic versioning,
# i.e. the version is of the form "2.5.0" and not "2.4".
version_added: "1.0.0"

description: This is my longer description explaining my test module.

options:
    name:
        description: This is the message to send to the test module.
        required: true
        type: str
    new:
        description:
            - Control to demo if the result of this module is changed or not.
            - Parameter description can be a list as well.
        required: false
        type: bool
# Specify this value according to your collection
# in format of namespace.collection.doc_fragment_name
extends_documentation_fragment:
    - my_namespace.my_collection.my_doc_fragment_name

author:
    - Your Name (@yourGitHubHandle)
'''

EXAMPLES = r'''
# Pass in a message
- name: Test with a message
  my_namespace.my_collection.my_test:
    name: hello world

# pass in a message and have changed true
- name: Test with a message and changed output
  my_namespace.my_collection.my_test:
    name: hello world
    new: true

# fail the module
- name: Test failure of the module
  my_namespace.my_collection.my_test:
    name: fail me
'''

RETURN = r'''
# These are examples of possible return values, and in general should use
other names for return values.
original_message:
    description: The original name param that was passed in.
    type: str
    returned: always
    sample: 'hello world'
message:
    description: The output message that the test module generates.
    type: str
    returned: always
    sample: 'goodbye'
'''

from ansible.module_utils.basic import AnsibleModule
import powerprotect


def run_module():
    module_args = dict(
        name=dict(type='str', required=True),
        username=dict(type='str'),
        cred_type=dict(default='KUBERNETES',
                             choices=['KUBERNETES', 'VCENTER']),
        password=dict(type='str', no_log=True),
        method=dict(type='str'),
        server=dict(type='str', required=True),
        token=dict(type='str'),
        state=dict(default='present', choices=['present', 'absent'])
    )

    result = dict(
        changed=False,
        original_message='',
        message='',
        credential=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    credential = powerprotect.Credential(
        name=module.params['name'],
        token=module.params['token'],
        server=module.params['server'],
        check_mode=module.check_mode)
    if module.params['state'] == 'absent':
        credential.delete_credential()
    if module.params['state'] == 'present':
        target_body = {'username': module.params['username'],
                       'name': module.params['name'],
                       'method': module.params['method'],
                       'password': module.params['password'],
                       'type': module.params['cred_type']
                       }
        credential.target_body = target_body
        credential.update_credential()
        credential.create_credential(**module.params)
    if credential.failure is True:
        module.fail_json(msg=credential.fail_msg,
                         response=credential.fail_response,
                         **result)
    result['changed'] = credential.changed
    result['credential'] = credential.body
    result['message'] = credential.msg
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()

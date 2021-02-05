#!/usr/bin/python

# Copyright: (c) 2018, Terry Jones <terry.jones@example.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
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
# These are examples of possible return values, and in general should use other names for return values.
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


class ProtectionPolicy:

    def __init__(self, **kwargs):
        self.exists = False
        self.deleted = False
        self.created = False
        self.updated = False
        self.changed = False
        self.check_mode = kwargs.get('check_mode', False)
        self.msg = ""
        self.failure = False
        self.fail_msg = ""
        self.name = kwargs['name']
        self.body = {}
        self.target_body = {}
        self.url = ""
        self.ppdm = kwargs['ppdm']
        self.get_rule()

    def get_rule(self):
        protection_rule = self.ppdm.get_protection_rule_by_name(self.name)
        if bool(protection_rule.response) is not False:
            self.exists = True
            self.body = protection_rule.response

    def delete_rule(self):
        if self.exists:
            return_value = self.ppdm.delete_protection_rule(self.body['id'])
            if return_value.success:
                self.changed = True
                self.deleted = True
                self.body = {}
                self.exists = False
                self.msg = f"Protection rule {self.name} deleted"
            elif return_value.success is False:
                self.failure = True
                self.fail_msg = return_value.fail_msg

    def create_rule(self, **kwargs):
        policy_name = kwargs['policy_name']
        intentory_type = kwargs['intentory_type']
        label = kwargs['label']
        if not self.exists:
            return_value = ppdm.create_protection_rule(rule_name=self.name,
                                                       policy_name=policy_name,
                                                       inventory_type=inventory_type,
                                                       label=label)
            if return_value.success:
                self.changed = True
                self.get_rule()
                self.created = True
                self.msg = f"Protection Rule {self.name} created"
            elif return_value.success is False:
                self.failure = True
                self.fail_msg = return_value.fail_msg

    def update_rule(self, **kwargs):
        policy_name = kwargs['policy_name']
        intentory_type = kwargs['intentory_type']
        label = kwargs['label']
        if (self.exists and
            self.ppdm.protection_rules_match(self.name, self.target_body) is False):
            self.body.update(self.target_body)
            return_value = ppdm.update_protection_rule(self.body)
            if return_value.success:
                self.changed = True
                self.get_rule()
                self.created = True
                self.msg = f"Protection Rule {self.name} updated"
            elif return_value.success is False:
                self.failure = True
                self.fail_msg = return_value.fail_msg




def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        name=dict(type='str', required=True),
        policy_name=dict(type='str'),
        inventory_type=dict(default='KUBERNETES', choices=['KUBERNETES', 'VMWARE_VIRTUAL_MACHINE']),
        label=dict(type='str'),
        priority=dict(type='str'),
        server=dict(type='str'),
        password=dict(type='str', no_log=True),
        token=dict(type='str'),
        state=dict(default='present', choices=['present', 'absent'])
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        original_message='',
        message=''
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    if module.params['name'] == 'fail me':
        module.fail_json(msg='You requested this to fail', **result)
    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    ppdm = powerprotect.Ppdm(server=module.params['server'],
                             password=module.params['password'])
    ppdm.login()
    protection_rule = ProtectionPolicy(name=module.params['name'], ppdm=ppdm)
    if module.params['state'] == 'absent':
        protection_rule.delete_rule()
    if module.params['state'] == 'present':
        target_body = {'actionResult': prot_policy_by_name.response['id'],
                       'name': module.params['name'],
                       'inventorySourceType': module.params['inventory_type'],
                       'conditions': [
                           {'assetAttributeName': 'userTags',
                            'operator': 'EQUALS',
                            'assetAttributeValue': module.params['label']}
                       ]}
        protection_rule.target_body = target_body
        protection_rule.create_rule(module.params)
        protection_rule.update_rule(module.params)
    result['changed'] = protection_rule.changed
    if protection_rule.failure is True:
        module.fail_json(msg=protection_rule.fail_msg, **result)
    result['message'] = protection_policy.msg
    module.exit_json(**result)

def main():
    run_module()


if __name__ == '__main__':
    main()

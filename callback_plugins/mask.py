from ansible_collections.community.general.plugins.callback.yaml import CallbackModule as CallbackModule_default
import collections

DOCUMENTATION = """
author: Jakub Wolynko <jakub@jakubwolynko.eu>
name: mask
type: awx_display
short_description: mask data, that match the regexp
description:
    - mask matched string with ***
extends_documentation_fragment:
  - default_callback
requirements:
  - set as stdout in configuration
options:
  sensitive_keywords:
    description:
        - a list of sensitive keywords to hide separated with a comma
    type: str
    env:
        - name: MASK_SENSITIVE_KEYWORDS
    ini:
        - section: callback_mask
          key: sensitive_keywords
    default: vault,token,pass,key
"""

EXAMPLES = r'''
ansible.cfg: >
  # Enable plugin
  [defaults]
  awx_display_callback = mask

  [callback_mask]
  # adding keywords here will override defaults
  sensitive_keywords = sops
'''

class CallbackModule(CallbackModule_default):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "awx_display"
    CALLBACK_NAME = "mask"

    def __init__(self):
        super(CallbackModule, self).__init__()
        self.sensitive_keywords = ''

    def set_options(self, task_keys=None, var_options=None, direct=None):

        super(CallbackModule, self).set_options(task_keys=task_keys, var_options=var_options, direct=direct)

        self.sensitive_keywords = self.get_option('sensitive_keywords').split(',')

        print("Debug form callback")

    def v2_runner_on_start(self, host, task):
        return True

    def _get_item_label(self, result):
        result = self.hide_password(result)
        if result.get("_ansible_no_log", False):
            item = "(censored due to no_log)"
        else:
            item = result.get("_ansible_item_label", result.get("item"))
        return item

    def mask_password(self, result):
        ret = {}
        for key, value in result.items():
            sensitive_content = False
            if isinstance(value, (collections.ChainMap, dict)):
                ret[key] = self.hide_password(value)
            else:
                # Each variable containing sensitive_keywords will be hidden from output
                for sensitive_keyword in self.sensitive_keywords:
                    if sensitive_keyword.lower() in key.lower():
                        ret[key] = "********"
                        sensitive_content = True
                if not sensitive_content:
                    ret[key] = value
        return ret

    def _dump_results(self, result, indent=None, sort_keys=True, keep_invocation=False):
        return super(CallbackModule, self)._dump_results(
            self.mask_password(result), indent, sort_keys, keep_invocation
        )

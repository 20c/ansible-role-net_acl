
def net_acl_iptables_line_regex(item):
    return '^.*INPUT.*comment "20CACL {{ item.name }}"\s+.*ACCEPT'


def net_acl_iptables_rule(item):
    """ formats an iptables rule """
    # defaults
    fmt = {
        'chain': '-A INPUT',
        'device': '',
        'protocol': ' -p tcp',
        'state': '',
        'identifier': ' -m comment --comment "20CACL {}"'.format(item['name']),
        'target': ' -j ACCEPT',
    }

    if item.get('device', None):
        fmt['device'] = ' -i {}'.format(item.device)
    if item.get('protocol', None):
        fmt['protocol'] = ' -p {}'.format(item.protocol)
    # FIXME parse for false
    if item.get('stateful', False) == True:
        fmt['state'] = ' --state NEW'
    if not item.get('ports', None):
        raise ValueError("missing ports")
    else:
        fmt['ports'] = ' -m multiport --dports={}'.format(','.join(map(str, item['ports'])))

    line = "{chain}{device}{protocol}{state}{ports}{identifier}{target}".format(**fmt)

    return line


class FilterModule(object):
     def filters(self):
         return {
            'net_acl_iptables_line_regex': net_acl_iptables_line_regex,
            'net_acl_ip4tables_rule': net_acl_iptables_rule,
            'net_acl_ip6tables_rule': net_acl_iptables_rule,
            }

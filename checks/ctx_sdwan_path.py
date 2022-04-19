#!/usr/bin/env python3

# cmk_ctx-sdwan - check-mk plugin for SNMP-based Cisco Digital-Optical-Monitoring monitoring
#
# Authors:
#   Thomas Liske <liske@ibh.de>
#	Philipp Kilian <kilian@ibh.de>
#
# Copyright Holder:
#   2022 (C) IBH IT-Service GmbH [http://www.ibh.de/]
#
# License:
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this package; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
#

import time
from typing import List, Mapping, NamedTuple
from .agent_based_api.v1 import register, Result, Service, SNMPTree, State, Metric, equals, get_rate, get_value_store
from .agent_based_api.v1.type_defs import CheckResult, StringTable, InventoryResult

ctx_sdwan_path_states = {
    0: [State.OK, 'undefined'],
    1: [State.CRIT, 'disabled'],
    2: [State.CRIT, 'dead'],
    3: [State.CRIT, 'bad'],
    4: [State.OK, 'good'],
}


class SDWANPath(NamedTuple):
    name: str
    idx: int
    state: int
    path_data: dict


def parse_ctxsdwan_path(string_table: List[StringTable]) -> List[SDWANPath]:
    paths = []
    for path in string_table[0]:
        paths.append(
            SDWANPath(
                idx=int(path[0]),
                name=path[1],
                state=int(path[2]),
                path_data={
                    'tx_bps': [float(path[3]), 1, True],
                    'tx_pps': [float(path[4]), 1, True],
                    'rx_bps': [float(path[5]), 1, True],
                    'rx_pps': [float(path[6]), 1, True],
                    'bowt': [float(path[7]), 0.1, False],
                    'jitter': [float(path[8]), 0.1, False],
                    'pps_lost': [float(path[9]), 1, True],
                    'pps_ooo': [float(path[10]), 1, True]
                }
            )
        )
    return paths


register.snmp_section(
    name="ctx_sdwan_path",
    parse_function=parse_ctxsdwan_path,
    fetch=[
        SNMPTree(
            # CITRIX-SD-WAN-MIB::sdWANStatsWANPathEntry
            base='.1.3.6.1.4.1.3845.31.4.2.2.16.3.1.1',
            oids=['2', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14']
        )
    ],
    detect=equals(".1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.3845.31.4")
)


def discovery_ctxsdwan_path(section: List[SDWANPath]) -> InventoryResult:
    for path in section:
        yield Service(item=path.name, parameters={"discovery_idx": path.idx})


# eval service state
def check_ctxsdwan_path(item, params: Mapping[str, int], section: List[SDWANPath]) -> CheckResult:
    found = False
    for path in section:
        if item == path.name and path.idx == params["discovery_idx"]:
            if path.state not in ctx_sdwan_path_states:
                yield Result(state=State.UNKNOWN, summary=f"Path state '{path.state}' is unknown")
                break

            yield Result(state=ctx_sdwan_path_states[path.state][0], summary=f"Path state is {ctx_sdwan_path_states[path.state][1]}({path.state})")
            this_time = int(time.time())
            yield Metric('state', path.state)
            value_store = get_value_store()

            for name, opts in path.path_data.items():
                if opts[2]:
                    replaced_name = name.replace('->', '_').replace('<-', '_')
                    yield Metric(name, get_rate(value_store, f"sdwan.path.{path.idx}.{replaced_name}", this_time, opts[0] * opts[1]))
                else:
                    yield Metric(name, opts[0] * opts[1])

    if not found:
        yield Result(state=State.UNKNOWN, summary=f"index '{params['discovery_idx']}' not found in SNMP table")


register.check_plugin(
    name="ctx_sdwan_path",
    service_name="SD-WAN Path %s",
    discovery_function=discovery_ctxsdwan_path,
    check_function=check_ctxsdwan_path,
    check_default_parameters={"discovery_idx": 0}
)

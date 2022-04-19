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
from typing import List, Any, Mapping, NamedTuple
from .agent_based_api.v1 import register, Result, Service, SNMPTree, State, Metric, equals, get_rate, OIDEnd, get_value_store
from .agent_based_api.v1.type_defs import CheckResult, StringTable, InventoryResult

ctx_sdwan_link_states = {
    0: [State.OK, 'undefined'],
    1: [State.WARN, 'disabled'],
    2: [State.CRIT, 'dead'],
    3: [State.WARN, 'bad'],
    4: [State.OK, 'good'],
}


class SDWANLink(NamedTuple):
    name: str
    idx: int
    state: int
    traffic_data: dict


def parse_ctxsdwan_link(string_table: List[StringTable]) -> List[SDWANLink]:
    links = []
    for link in string_table[0]:
        links.append(
            SDWANLink(
                name=link[1], 
                idx=int(link[0]), 
                state=int(link[2]),
                traffic_data={
                    'bps_tx': int(link[3]),
                    'pps_tx': int(link[4]),
                    'bps_rx': int(link[5]),
                    'pps_rx': int(link[6]),
                    'bps_drop': int(link[7]),
                    'pps_drop': int(link[8])
                }
            )
        )
    return links


register.snmp_section(
    name="ctx_sdwan_link",
    parse_function=parse_ctxsdwan_link,
    fetch=[
        # CITRIX-SD-WAN-MIB::sdWANStatsWANLinkEntry
        SNMPTree(
            base='.1.3.6.1.4.1.3845.31.4.2.2.15.2.1',
            oids=[OIDEnd(), '3', '4', '5', '6', '7', '8', '9', '10']
        )
    ],
    detect=equals(".1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.3845.31.4")
)


def discovery_ctxsdwan_link(section: List[SDWANLink]) -> InventoryResult:
    for link in section:
        yield Service(item=link.name, parameters={"discovery_idx": link.idx})


# eval service state
def check_ctxsdwan_link(item, params: Mapping[str, int], section: List[SDWANLink]) -> CheckResult:
    found = False
    for link in section:
        if link.name == item and link.idx == params["discovery_idx"]:
            found = True
            if link.state not in ctx_sdwan_link_states:
                yield Result(State.UNKNOWN, summary=f"Link state '{link.state}' is unknown")
                break

            yield Result(state=ctx_sdwan_link_states[link.state][0], summary=f"Link state is {ctx_sdwan_link_states[link.state][1]} ({link.state})")
            this_time = int(time.time())
            yield Metric("state", link.state)
            value_store = get_value_store()
            for name, value in link.traffic_data.items():
                yield Metric(name, get_rate(value_store, f"SD-WAN-Link.{link.idx}.{name}", this_time, value))
            break

    if not found:
        yield Result(State.UNKNOWN, summary=f"index '{params['discovery_idx']}' not found in SNMP table")


register.check_plugin(
    name="ctx_sdwan_link",
    service_name="SD-WAN Link %s",
    discovery_function=discovery_ctxsdwan_link,
    check_function=check_ctxsdwan_link,
    check_default_parameters={"discovery_idx": 0}
)

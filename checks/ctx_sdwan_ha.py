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

from typing import List, Any, Mapping
from .agent_based_api.v1 import register, Result, Service, SNMPTree, State, Metric, startswith
from .agent_based_api.v1.type_defs import CheckResult, StringTable, InventoryResult


ctx_sdwan_ha_states = {
    0: 'undefined',
    1: 'notConfigured',
    2: 'active',
    3: 'standby'
}


def parse_ctxsdwan_ha(string_table: List[StringTable]) -> int:
    if string_table[0][0][0]:
        return int(string_table[0][0][0])
    else:
        return 0


register.snmp_section(
    name="ctx_sdwan_ha",
    parse_function=parse_ctxsdwan_ha,
    fetch=[
        SNMPTree(
            base='.1.3.6.1.4.1.3845.31.4.2.2.12.1',
            oids=['9']
        )
    ],
    detect=startswith(".1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.3845.31")
)


def discovery_ctxsdwan_ha(section: int) -> InventoryResult:
    if section > 1:
        yield Service(item="HA State", parameters={"discovery_value": section})


def check_ctxsdwan_ha(item, params: Mapping[str, Any], section: int) -> CheckResult:
    c_state = State.OK
    if section != params["discovery_value"]:
        c_state = State.CRIT
        if section > 1:
            c_state = State.WARN

    yield Result(state=c_state, summary=f"HA state is {ctx_sdwan_ha_states[section]} ({section})")
    yield Metric('ha_state', section)


register.check_plugin(
    name="ctx_sdwan_ha",
    service_name="SD-WAN %s",
    discovery_function=discovery_ctxsdwan_ha,
    check_function=check_ctxsdwan_ha,
    check_default_parameters={"discovery_value": 0}
)

#!/usr/bin/env python3
"""Reduce passive unified logs to a path-free FairPlay IPC observation."""

import argparse
from bisect import bisect_left, bisect_right
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import PurePath
import re
from statistics import median
import subprocess


PROCESS_NAMES = ("akd", "adid", "fairplayd")
SERVICE = "com.apple.adid"
MICROSECOND = timedelta(microseconds=1)
CLIENT = re.compile(
    r"\[0x[0-9a-f]+\] activating connection: "
    r"mach=true listener=false peer=false name=com\.apple\.adid"
)
PEER = re.compile(
    r"\[(0x[0-9a-f]+)\] activating connection: "
    r"mach=false listener=false peer=true name=com\.apple\.adid"
    r"\.peer\[(\d+)\]\.(0x[0-9a-f]+)"
)
INVALIDATION = re.compile(
    r"\[(0x[0-9a-f]+)\] invalidated because the client process "
    r"\(pid (\d+)\) either cancelled the connection or exited"
)


def run(*command):
    env = dict(os.environ, LC_ALL="C", TZ="UTC")
    return subprocess.run(command, check=True, capture_output=True, text=True, env=env).stdout


def inventory():
    processes = {}
    for name in PROCESS_NAMES:
        processes[name] = {}
        for pid in run("/usr/bin/pgrep", "-x", name).splitlines():
            fields = run("/bin/ps", "-p", pid, "-o", "pid=", "-o", "lstart=", "-o", "comm=").split()
            started = datetime.strptime(" ".join(fields[1:6]), "%a %b %d %H:%M:%S %Y")
            if fields[0] != pid or PurePath(" ".join(fields[6:])).name != name:
                raise ValueError(f"Process changed during inventory: {name}")
            started_utc = started.replace(tzinfo=timezone.utc).isoformat()
            processes[name][int(pid)] = dict(pid=int(pid), started_utc=started_utc)
    return processes


def read_logs(start, end, predicate):
    output = run("/usr/bin/log", "show", "--start", f"@{int(start.timestamp())}",
                 "--end", f"@{int(end.timestamp())}", "--info", "--style", "json",
                 "--predicate", predicate)
    records = json.loads(output)
    return [record for record in records if record.get("eventType") == "logEvent"]


def summaries(events):
    points = Counter((PurePath(event["senderImagePath"]).name, event["senderImageUUID"],
                      event["senderProgramCounter"]) for event in events)
    return [dict(image=image, uuid=uuid, program_counter=pc, count=count)
            for (image, uuid, pc), count in sorted(points.items())]


def server_observations(events, akd_pid):
    active = {}
    pairs = {}
    by_pid = Counter()
    peer_events = []
    unmatched_invalidations = 0
    for event in events:
        message = event["eventMessage"]
        activation = PEER.fullmatch(message)
        if activation:
            pointer, pid, repeated_pointer = activation.groups()
            if pointer != repeated_pointer or pointer in active:
                raise ValueError("Inconsistent server object lifetime")
            active[pointer] = (int(pid), event)
            by_pid[int(pid)] += 1
            if int(pid) == akd_pid:
                peer_events.append(event)
            continue
        invalidation = INVALIDATION.fullmatch(message)
        if invalidation:
            pointer, pid = invalidation.groups()
            prior = active.pop(pointer, None)
            if prior is None:
                unmatched_invalidations += 1
                continue
            prior_pid, prior_event = prior
            if int(pid) != prior_pid:
                raise ValueError("Peer PID changed within one server object lifetime")
            pairs[prior_event["machTimestamp"]] = event
    return peer_events, pairs, by_pid, unmatched_invalidations, len(active)


def event_time(event):
    return datetime.fromisoformat(event["timestamp"]).astimezone(timezone.utc)


def installed_slice(events):
    path, = {event["processImagePath"] for event in events}
    uuid, = {event["processImageUUID"] for event in events}
    row, = [line.split(None, 3)[:3]
            for line in run("/usr/bin/dwarfdump", "--uuid", path).splitlines()
            if line.startswith(f"UUID: {uuid} ")]
    return dict(uuid=uuid, architecture=row[2].strip("()"))


def match_events(clients, peers, retirements, window_us):
    client_times = [event_time(event) for event in clients]
    peer_times = [event_time(event) for event in peers]
    width = window_us * MICROSECOND
    forward = [(bisect_left(peer_times, moment), bisect_right(peer_times, moment + width))
               for moment in client_times]
    backward = [(bisect_left(client_times, moment - width), bisect_right(client_times, moment))
                for moment in peer_times]
    matches = []
    for index, (lo, hi) in enumerate(forward):
        if hi - lo != 1 or backward[lo] != (index, index + 1):
            continue
        client_time = client_times[index]
        peer_time = peer_times[lo]
        retirement = retirements.get(peers[lo]["machTimestamp"])
        matches.append(dict(client_utc=client_time.isoformat(timespec="microseconds"),
                            peer_delay_us=(peer_time - client_time) // MICROSECOND,
                            server_object_lifetime_us=(
                                (event_time(retirement) - peer_time) // MICROSECOND
                                if retirement is not None else None)))
    return dict(window_us=window_us, uniquely_matched=len(matches),
                client_candidate_counts=dict(sorted(Counter(hi - lo for lo, hi in forward).items())),
                peer_candidate_counts=dict(sorted(Counter(hi - lo for lo, hi in backward).items()))), matches


def distribution(values):
    return dict(min=min(values), median=median(values), max=max(values)) if values else None


def audit(start, end):
    processes_before = inventory()
    xpc_predicate = (
        '(process == "akd" OR process == "adid" OR process == "fairplayd") '
        'AND subsystem == "com.apple.xpc" AND category == "connection"'
    )
    reverse_terms = ("com.apple.unfreed", "FairPlayIOKit", "rpc 502", "rpc502", "rpc 602", "rpc602")
    reverse_predicate = '(process == "fairplayd" OR senderImagePath ENDSWITH "FairPlayIOKit") AND ('
    reverse_predicate += " OR ".join(f'eventMessage CONTAINS[c] "{term}"' for term in reverse_terms)
    reverse_predicate += ")"
    records = sorted(read_logs(start, end, xpc_predicate), key=event_time)
    reverse_events = read_logs(start, end, reverse_predicate)
    daemon_events = read_logs(start, end, 'process == "fairplayd"')
    processes_after = inventory()
    boot_ids = {event["bootUUID"] for event in records}
    if len(boot_ids) != 1:
        raise ValueError("Expected one observed boot")
    by_process = {name: [] for name in PROCESS_NAMES}
    for event in records:
        name = PurePath(event["processImagePath"]).name
        by_process[name].append(event)
    clients = [event for event in by_process["akd"] if CLIENT.fullmatch(event["eventMessage"])]
    akd_pid, = {event["processID"] for event in clients}
    adid_pid, = {event["processID"] for event in by_process["adid"]}
    fairplayd_pid, = processes_before["fairplayd"]
    started = {}
    for name, pid in zip(PROCESS_NAMES, (akd_pid, adid_pid, fairplayd_pid)):
        process = processes_before[name][pid]
        if process != processes_after[name].get(pid):
            raise ValueError(f"Process inventory changed during observation: {name}")
        if datetime.fromisoformat(process["started_utc"]) >= start:
            raise ValueError(f"Process inventory does not predate the observation window: {name}")
        started[name] = process
    peers, retirements, by_pid, unmatched, open_objects = server_observations(by_process["adid"], akd_pid)
    sensitivity = []
    for window_us in (100, 250, 500, 1000, 5000, 20000):
        counts, _ = match_events(clients, peers, retirements, window_us)
        sensitivity.append(counts)
    _, matches = match_events(clients, peers, retirements, 1000)
    retirements_for_akd = [
        retirements[peer["machTimestamp"]] for peer in peers if peer["machTimestamp"] in retirements
    ]
    return dict(
        start_utc=start.isoformat(), end_utc=end.isoformat(), observed_boots=len(boot_ids),
        macos_build=run("/usr/bin/sw_vers", "-buildVersion").strip(),
        log_level="info", service=SERVICE, process_inventory=started, xpc_predicate=xpc_predicate,
        reverse_predicate=reverse_predicate, reverse_event_count=len(reverse_events),
        fairplayd_event_count=len(daemon_events),
        xpc_connection_events={name: len(events) for name, events in by_process.items()},
        fairplayd_named_adid_events=sum(SERVICE in event["eventMessage"]
                                       for event in by_process["fairplayd"]),
        akd_named_activations=len(clients), adid_akd_peer_activations=len(peers),
        adid_fairplayd_peer_activations=by_pid[fairplayd_pid],
        adid_other_peer_activations=sum(by_pid.values()) - len(peers),
        adid_object_retirements=len(retirements), unmatched_adid_invalidations=unmatched,
        adid_objects_open_at_end=open_objects, akd_slice=installed_slice(clients),
        adid_slice=installed_slice(peers),
        akd_activation_log_sites=summaries(clients), adid_activation_log_sites=summaries(peers),
        adid_invalidation_log_sites=summaries(retirements_for_akd), sensitivity=sensitivity,
        retained_window_us=1000, matches=matches,
        client_activations_utc=[event_time(client).isoformat(timespec="microseconds")
                                for client in clients],
        server_peer_activations_utc=[event_time(peer).isoformat(timespec="microseconds")
                                     for peer in peers],
        peer_delay_us=distribution([match["peer_delay_us"] for match in matches]),
        server_object_lifetime_us=distribution([match["server_object_lifetime_us"] for match in matches
                                                if match["server_object_lifetime_us"] is not None]),
    )


def utc(value):
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() != timedelta(0) or parsed.microsecond:
        raise argparse.ArgumentTypeError("Use an explicit UTC timestamp at whole-second resolution")
    return parsed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("start", type=utc)
    parser.add_argument("end", type=utc)
    bounds = parser.parse_args()
    if bounds.start >= bounds.end:
        parser.error("end must follow start")
    print(json.dumps(audit(bounds.start, bounds.end), indent=2, sort_keys=True))

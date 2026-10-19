"""Minimal local admin observations shared by additional research/atlas tests."""

from core import logged
from test_support import ConsoleFixture

A, B, C = "a" * 64, "b" * 64, "c" * 64
NOW = "2026-10-19T10:00:00+00:00"


class ObservedFixture(ConsoleFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.responses.update(
            getSelf={"key": A, "routing_entries": 1},
            getPeers={
                "peers": [{"key": B, "up": True, "inbound": False, "port": 1, "latency": 1e6}]
            },
            getTree={"tree": [{"key": B, "parent": A, "sequence": 1}]},
            getPaths={"paths": [{"key": C, "path": [1], "sequence": 1}]},
        )

    @logged
    def observation(self):
        from atlas.acquisition import local_snapshot

        return local_snapshot(self.ctx)

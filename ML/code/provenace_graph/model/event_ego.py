"""Event-only v5a augmentation of the frozen two-hop Process/Host ego graph.

The target Event is visible at decision time; every other fact remains strictly
earlier than the target. No File, Module, Registry or endpoint nodes are added.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from ML.code.provenace_graph.model.ego import ATTRIBUTES as BASE_ATTRIBUTES, EgoGraphs

RELATIONS = ('creates', 'communicates', 'communicates_reverse', 'hosts',
             'performs', 'performs_reverse')


class EventSchema:
    def __init__(self, vocabulary):
        vocabulary = json.loads(Path(vocabulary).read_text()) if isinstance(vocabulary, (str, Path)) else vocabulary
        self.action_tokens = tuple(sorted(t for t in vocabulary if t.startswith('action::')))
        self.object_tokens = tuple(sorted(t for t in vocabulary if t.startswith('object::')))
        if not self.action_tokens or not self.object_tokens:
            raise ValueError('Frozen vocabulary has no action/object feature columns')
        self.attributes = tuple(BASE_ATTRIBUTES) + ('node=event',) + tuple(
            'event::' + token for token in (*self.action_tokens, *self.object_tokens))
        self.action_cols = {vocabulary[token]: token for token in self.action_tokens}
        self.object_cols = {vocabulary[token]: token for token in self.object_tokens}
        self.attribute_index = {name: i for i, name in enumerate(self.attributes)}

    def from_columns(self, columns):
        present = set(map(int, columns))
        actions = [self.action_cols[column] for column in present if column in self.action_cols]
        objects = [self.object_cols[column] for column in present if column in self.object_cols]
        if len(actions) != 1 or len(objects) != 1:
            raise ValueError(f'Event requires exactly one action/object feature, got {actions}/{objects}')
        return actions[0], objects[0]

    def from_record(self, record):
        action = str(record.get('action') or '').strip().casefold()
        object_type = str(record.get('object') or '').strip().casefold()
        action_token = f'action::{action}' if f'action::{action}' in self.action_tokens else 'action::unknown'
        object_token = f'object::{object_type}'
        if action_token not in self.action_tokens or object_token not in self.object_tokens:
            raise ValueError('Target event action/object is outside the frozen Event schema')
        return action_token, object_token

    def augment(self, base, action_token, object_token):
        if action_token not in self.action_tokens or object_token not in self.object_tokens:
            raise ValueError('Unknown target Event type')
        old = np.asarray(base['x'], dtype=np.float32)
        if old.ndim != 2 or old.shape[1] != len(BASE_ATTRIBUTES):
            raise ValueError('Base ego graph attribute schema mismatch')
        if len(old) >= 65:
            raise ValueError('Event augmentation exceeds 65-node cap')
        x = np.zeros((len(old) + 1, len(self.attributes)), dtype=np.float32)
        x[:len(old), :len(BASE_ATTRIBUTES)] = old
        event = len(old)
        x[event, self.attribute_index['node=event']] = 1
        x[event, self.attribute_index['event::' + action_token]] = 1
        x[event, self.attribute_index['event::' + object_token]] = 1
        actor = int(base['root'])
        edges = tuple(base['edges']) + ((actor, event, 'performs'),
                                        (event, actor, 'performs_reverse'))
        if len(edges) != len(set(edges)):
            raise ValueError('Duplicate relation after Event augmentation')
        result = dict(base, x=x, edges=tuple(sorted(edges)), event_root=event,
                      event_type=(action_token, object_token))
        if 'node_keys' in base:
            result['node_keys'] = tuple(base['node_keys']) + ((None, 'target_event'),)
        return result


class EventEgoGraphs:
    def __init__(self, db, vocabulary, **kwargs):
        self.base = EgoGraphs(db, **kwargs)
        self.schema = EventSchema(vocabulary)

    def build(self, host, actor, timestamp_us, record):
        action, object_type = self.schema.from_record(record)
        return self.schema.augment(self.base.build(host, actor, timestamp_us), action, object_type)

#!/usr/bin/env python3
"""Regression tests for compact, structure-aware Host ML features."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "preprocess"))
from ecar_tokenizer import (
    COMMAND_FAMILIES, GROUPS, HOST_OBJECTS, HOST_OBJECT_FIELDS, MAX_COMMAND_CHARS,
    MAX_ENCODED_CHARS, POWERSHELL_ENCODED_RE, TOKENIZER_POLICY, classify_command_line,
    decode_powershell_payload, flatten_tokens, normalize_literals, tokenize_record,
    token_layers,
)
from command_syntax import lex, MAX_LEXEMES


def process(command: str, image: str = "cmd.exe", **properties: str) -> dict:
    return {"action": "CREATE", "object": "PROCESS", "properties": {
        "image_path": image, "command_line": command, **properties,
    }}


class EcarTokenizerTests(unittest.TestCase):
    def tokens(self, command: str, image: str = "cmd.exe") -> set[str]:
        return set(flatten_tokens(tokenize_record(process(command, image))[0]))

    def test_v5_canonical_aliases_preserve_roles_and_occurrences(self):
        tokens = flatten_tokens(tokenize_record(process('tool.exe /q /q', 'tool.exe'))[0])
        self.assertEqual(tokens.count('command_line::syntax::switch=/q'), 2)
        self.assertEqual(tokens.count('command_line::anchor::launcher=tool.exe'), 1)
        self.assertIn('command_line::anchor::command=tool.exe', tokens)
        self.assertIn('command_line::relation::command_switch=tool.exe->/q', tokens)
        self.assertFalse(any(t.startswith(('command_line::structure::switch=',
                                          'command_line::launcher=',
                                          'command_line::native::executable=')) for t in tokens))
        self.assertEqual(token_layers('command_line::syntax::switch=/q'), ('structure', 'syntax'))
        dll = self.tokens('rundll32.exe shell32.dll,Control_RunDLL', 'rundll32.exe')
        self.assertIn('command_line::anchor::dll=shell32.dll', dll)
        self.assertIn('command_line::anchor::entrypoint=control_rundll', dll)
        self.assertFalse(any(t.startswith(('command_line::rundll32::dll=',
                                          'command_line::rundll32::entry=')) for t in dll))

    def test_v5_dynamic_counters_and_hex_preserve_technical_names(self):
        a = self.tokens(r'tool.exe \\.\pipe\usgthrfltpipemssgthrpipe117_ 0x1234abcd', 'tool.exe')
        b = self.tokens(r'tool.exe \\.\pipe\usgthrfltpipemssgthrpipe252_ 0x9876fedc', 'tool.exe')
        self.assertEqual(a, b)
        self.assertIn('command_line::native::usgthrfltpipemssgthrpipe_number_value_', a)
        self.assertIn('command_line::native::hex_value', a)
        self.assertEqual(normalize_literals('kernel32.dll python3.exe winword.exe'),
                         'kernel32.dll python3.exe winword.exe')

    def test_v5_office_paths_preserve_location_and_hide_private_names(self):
        from ecar_tokenizer import _compact_path_tokens
        for user, filename in [('alice', 'private'), ('bob', 'different')]:
            path = rf'C:\Users\{user}\AppData\Roaming\Microsoft\Bibliography\Style\{filename}.XSL'
            tokens = _compact_path_tokens('file_path', path)
            self.assertIn('file_path::extension=.xsl', tokens)
            self.assertIn('file_path::category=appdata', tokens)
            self.assertIn('file_path::subcategory=roaming', tokens)
            self.assertIn('file_path::office_category=bibliography_style', tokens)
            self.assertFalse(any(user in t or filename in t for t in tokens))
        cases = [(r'C:\Program Files (x86)\Microsoft Office\Office15\WINWORD.EXE', 'installation'),
                 (r'C:\Program Files\Microsoft Office\root\Office16\STARTUP\x.dotm', 'startup'),
                 (r'%APPDATA%\Microsoft\Word\STARTUP\x.dotm', 'startup'),
                 (r'%APPDATA%\Microsoft\Templates\x.dotm', 'templates'),
                 (r'%APPDATA%\Microsoft\Proof\custom.dic', 'proofing'),
                 (r'%LOCALAPPDATA%\Microsoft\Office\UnsavedFiles\x.docm', 'recovery')]
        for path, role in cases:
            self.assertIn('file_path::office_category='+role, _compact_path_tokens('file_path', path))
        for path in (r'C:\Users\alice\Documents\office\x.xsl',
                     r'C:\Users\alice\AppData\Roaming\Microsoft\BibliographyFake\x.xsl'):
            self.assertFalse(any('office_category=' in t for t in _compact_path_tokens('file_path', path)))
        self.assertIn('new_path::extension=.xslt', _compact_path_tokens('new_path', r'C:\x.xslt'))

    def test_v5_registry_roles_are_bounded_and_private_values_absent(self):
        from ecar_tokenizer import _registry_tokens
        for sid in ('S-1-5-21-123-456-789-1001', 'S-1-5-21-987-654-321-1002'):
            key = rf'\REGISTRY\USER\{sid}\Software\Microsoft\Shared Tools\Proofing Tools\1.0\Custom Dictionaries\private@domain'
            tokens = _registry_tokens(key)
            self.assertEqual(set(tokens), {'registry::root=hku', 'registry::category=office_proofing',
                                          'registry::category=office_custom_dictionaries'})
        key = r'HKCU\Software\Microsoft\Office\16.0\Word\Security\Trusted Locations\Location1'
        tokens = _registry_tokens(key)
        self.assertTrue({'registry::category=office', 'registry::category=office_security',
                         'registry::category=office_trusted_locations'} <= set(tokens))
        self.assertNotIn('registry::category=office_trusted_locations', _registry_tokens(key.replace('Trusted Locations', 'Trusted LocationsFake')))
        for key, category in [
            (r'HKLM\Software\Microsoft\Office\Outlook\Addins\private', 'office_addins'),
            (r'HKLM\System\CurrentControlSet\Control\Lsa', 'lsa'),
            (r'HKLM\System\ControlSet001\Control\Terminal Server', 'remote_desktop'),
            (r'HKCR\CLSID\{private-uuid}\InprocServer32', 'com_server'),
            (r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders', 'shell_folders')]:
            self.assertIn('registry::category='+category, _registry_tokens(key))
        event = dict(object='REGISTRY', properties=dict(key=key, data='secret', value='private', image_path='reg.exe'))
        self.assertFalse(any('secret' in t or 'private' in t for t in flatten_tokens(tokenize_record(event)[0])))

    def test_v4_wsh_boundary_timeout_and_dll_review(self):
        tokens = self.tokens('cscript.exe //H:cscript //T:30 //S sample.js /silent', 'cscript.exe')
        self.assertIn('command_line::syntax::wsh_option=//h:cscript', tokens)
        self.assertIn('command_line::syntax::wsh_timeout=present', tokens)
        self.assertIn('command_line::syntax::script_argument_switch=/silent', tokens)
        self.assertIn('command_line::anchor::script_ext=.js', tokens)
        after = self.tokens('cscript.exe sample.js //T:30', 'cscript.exe')
        self.assertNotIn('command_line::syntax::wsh_timeout=present', after)
        for dll in ('comsvcs.dll', 'advpack.dll', 'ieadvpack.dll'):
            tokens = self.tokens(f'rundll32.exe {dll},MiniDump argument', 'rundll32.exe')
            self.assertIn(f'command_line::rundll32::review_dll={dll}', tokens)
            self.assertIn(f'command_line::relation::dll_entry={dll}->minidump', tokens)

    def test_v4_principal_buckets_and_no_literal_identity(self):
        from ecar_tokenizer import tokenize_principal
        cases = [(None, ['absent']), (' ', ['absent']),
                 (r'NT AUTHORITY\SYSTEM', ['nt_system']),
                 (r'NT AUTHORITY\NETWORK SERVICE', ['nt_authority']),
                 (r'NT SERVICE\secret', ['nt_service']),
                 (r'DOMAIN\sysadmin', ['domain_user', 'admin_account']),
                 (r'DOMAIN\privateperson', ['domain_user']),
                 ('S-1-5-18', ['local_or_unknown'])]
        for value, expected in cases:
            self.assertEqual(tokenize_principal(value), ['principal::'+x for x in expected])

    def test_v4_paths_and_normalized_stems(self):
        from ecar_tokenizer import _compact_path_tokens
        for folder in ('System32', 'SysWOW64'):
            for key in ('file_path', 'module_path'):
                tokens = _compact_path_tokens(key, rf'C:\Windows\{folder}\IPHLPAPI.DLL')
                self.assertIn(f'{key}::subcategory={folder.lower()}', tokens)
                self.assertIn(f'{key}::system_stem=iphlpapi', tokens)
        for path in (r'C:\Users\privateperson\Temp\private.dll', r'C:\ProgramData\private.dll', r'C:\Users\privateperson\System32\private.dll'):
            tokens = _compact_path_tokens('file_path', path)
            self.assertFalse(any('stem=' in t or 'private' in t for t in tokens))
        self.assertIn('file_path::subcategory=windows_temp', _compact_path_tokens('file_path', r'C:\Windows\Temp\x.exe'))
        self.assertIn('file_path::subcategory=user_temp', _compact_path_tokens('file_path', r'C:\Users\a\AppData\Local\Temp\x.exe'))
        tokens = _compact_path_tokens('file_path', r'C:\Windows\System32\01234567-89ab-cdef-0123-456789abcdef.dll')
        self.assertFalse(any('01234567' in t for t in tokens))

    def test_v4_shell_classes_are_bound_to_typename(self):
        for name, namespace, leaf in [('System.Net.WebClient', 'system.net', 'webclient'),
                                     ('System.CodeDom.Compiler.CompilerParameters', 'system.codedom', 'compilerparameters')]:
            payload = f'ParameterBinding(New-Object): name="TypeName"; value="{name}"'
            tokens = flatten_tokens(tokenize_record(dict(object='SHELL', properties=dict(payload=payload)))[0])
            self.assertIn('shell::class_namespace='+namespace, tokens)
            self.assertIn('shell::class_name='+leaf, tokens)
            for bad in (payload.replace('TypeName', 'Password'), payload.replace('New-Object', 'Write-Output'), name):
                tokens = flatten_tokens(tokenize_record(dict(object='SHELL', properties=dict(payload=bad)))[0])
                self.assertFalse(any('class_name=' in t for t in tokens))

    def test_v4_lineage_markers_require_actual_parent_child(self):
        def tokens(image, parent):
            return flatten_tokens(tokenize_record(process('cmd.exe /c echo python.exe ping.exe', image, parent_image_path=parent))[0])
        self.assertIn('command_line::cmd::self_spawn=true', tokens('cmd.exe', 'CMD.EXE'))
        marker = 'command_line::context::suspicious_parent=python->network_tool'
        self.assertIn(marker, tokens('ping.exe', 'python.exe'))
        self.assertNotIn(marker, tokens('cmd.exe', 'explorer.exe'))

    def test_pipeline_direction_survives_binary_features(self):
        a = self.tokens('cmd.exe /c "whoami | findstr admin"')
        b = self.tokens('cmd.exe /c "findstr admin | whoami"')
        self.assertIn("command_line::relation::pipeline=whoami->findstr", a)
        self.assertIn("command_line::relation::pipeline=findstr->whoami", b)
        self.assertNotEqual(a, b)

    def test_powershell_inline_anchors_and_literal_operators(self):
        tokens = self.tokens('powershell.exe -Command "Get-Process | Select-Object Name"', 'powershell.exe')
        self.assertIn('command_line::anchor::command=get-process', tokens)
        self.assertIn('command_line::anchor::command=select-object', tokens)
        self.assertIn('command_line::syntax::operator=pipe', tokens)
        self.assertIn('command_line::relation::pipeline=get-process->select-object', tokens)
        literal = self.tokens('powershell.exe -Command "Write-Output \'Get-Process | Select-Object\'"', 'powershell.exe')
        self.assertNotIn('command_line::syntax::operator=pipe', literal)
        self.assertNotIn('command_line::anchor::command=get-process', literal)

    def test_native_metacharacters_are_data(self):
        tokens = self.tokens('tool.exe https://example.invalid/?a=1&b=2', 'tool.exe')
        self.assertFalse(any('operator=' in token or 'pipeline=' in token for token in tokens))

    def test_cmd_caret_and_powershell_call_have_distinct_syntax(self):
        escaped = self.tokens('cmd.exe /c echo one ^| two')
        self.assertNotIn('command_line::syntax::operator=pipe', escaped)
        called = self.tokens('powershell.exe -Command "& \'whoami.exe\'"', 'powershell.exe')
        self.assertIn('command_line::syntax::operator=call', called)
        self.assertNotIn('command_line::syntax::operator=sequence', called)
        self.assertIn('command_line::anchor::command=whoami.exe', called)

    def test_switch_binding_stops_at_clause_boundary(self):
        tokens = self.tokens('cmd.exe /c schtasks.exe /p | whoami')
        self.assertNotIn('command_line::relation::switch_value=/p->password', tokens)
        self.assertIn('command_line::anchor::command=whoami', tokens)

    def test_python_interpreter_boundary_and_whitespace(self):
        for command in ('python.exe script.py -c "print(1)" -m pretend',
                        'python.exe -m app -c "print(1)"',
                        'python.exe -- script.py -c "print(1)"'):
            tokens = self.tokens(command, 'python.exe')
            self.assertNotIn('command_line::python::mode=-c', tokens)
            self.assertFalse(any('::ast=' in token for token in tokens))
            self.assertIn('command_line::syntax::script_argument_switch=-c', tokens)
        tokens = self.tokens('python.exe -W ignore -c "import os\nif True:\n    print(os.getcwd())"', 'python.exe')
        self.assertIn('command_line::python::ast=parse_success', tokens)
        self.assertIn('command_line::anchor::api=os.getcwd', tokens)
        self.assertIn('command_line::anchor::module=os', tokens)

    def test_known_credentials_are_typed_before_lexical_emission(self):
        def command(user, password):
            return f'schtasks.exe /query /s host /u {user} /p {password}'
        a = self.tokens(command('alice', '12345'), 'schtasks.exe')
        b = self.tokens(command('bob', 'secretpassword'), 'schtasks.exe')
        self.assertEqual(a, b)
        self.assertIn('command_line::relation::switch_value=/p->password', a)
        self.assertFalse(any('alice' in token or 'secretpassword' in token or 'network_port' in token for token in a | b))
        nested = self.tokens('cmd.exe /c ' + command('alice', 'secretpassword'))
        self.assertFalse(any('alice' in token or 'secretpassword' in token for token in nested))
        attached = self.tokens('runas.exe /user:alice tool.exe', 'runas.exe')
        self.assertFalse(any('alice' in token for token in attached))
        unknown = self.tokens('unknown.exe /p 12345', 'unknown.exe')
        self.assertFalse(any('/p->' in token for token in unknown))

    def test_invalid_and_missing_encoded_operands_are_masked_and_audited(self):
        for suffix in ('%%AbCd%%', ''):
            grouped, audit = tokenize_record(process('powershell.exe -EncodedCommand ' + suffix, 'powershell.exe'))
            tokens = flatten_tokens(grouped)
            self.assertEqual(audit['decode_status'], {'encoded_not_decoded': 1})
            self.assertIn('command_line::powershell::encoded_not_decoded', tokens)
            self.assertFalse(any('abcd' in token for token in tokens))

    def test_fallback_launcher_with_quoted_spaces_and_rundll_fragment(self):
        self.assertEqual(classify_command_line('"C:\\Program Files\\Python\\python.exe" -m http.server'), 'python')
        tokens = self.tokens('"C:\\Program Files\\Example\\a.dll",Entry', 'rundll32.exe')
        self.assertIn('command_line::anchor::dll=a.dll', tokens)
        self.assertIn('command_line::anchor::entrypoint=entry', tokens)

    def test_lexer_limits_and_incomplete_source_are_explicit(self):
        items, status = lex('arg ' * (MAX_LEXEMES + 10))
        self.assertLessEqual(len(items), MAX_LEXEMES)
        self.assertIn('lexeme_limit', status)
        tokens = self.tokens('powershell.exe -Command "Write-Output \'unterminated"', 'powershell.exe')
        self.assertIn('command_line::syntax::parse=unclosed_quote', tokens)
        self.assertTrue(any('unterminated' in token for token in tokens))

    def test_layer_tags_are_audit_only_and_overlap(self):
        self.assertEqual(token_layers('command_line::anchor::command=get-process'), ('anchor',))
        self.assertEqual(token_layers('command_line::structure::operator=pipe'), ('structure', 'syntax'))

    def test_all_seven_families_reach_tokenizer(self) -> None:
        examples = {
            "cmd": ("cmd.exe /c whoami", "cmd.exe"),
            "powershell": ("powershell -nop", "powershell.exe"),
            "python": ("python3 -m http.server", "python3.exe"),
            "wscript": ("wscript a.vbs", "wscript.exe"),
            "cscript": ("cscript //nologo a.vbs", "cscript.exe"),
            "rundll32": ("rundll32 a.dll,Entry", "rundll32.exe"),
            "native": ("whoami /groups", "whoami.exe"),
        }
        self.assertEqual(set(examples), set(COMMAND_FAMILIES))
        for family, (command, image) in examples.items():
            with self.subTest(family=family):
                self.assertEqual(classify_command_line(command, image), family)
                grouped, audit = tokenize_record(process(command, image))
                self.assertEqual(audit["command_family"], family)
                self.assertTrue(audit["eligible"])
                self.assertIn(f"command_line::family={family}", grouped["command_line"])

    def test_cmd_keeps_operators_nested_structure_and_switch_roles(self) -> None:
        grouped, _ = tokenize_record(process('cmd.exe /c "whoami | findstr admin" && echo 1 > out.txt'))
        tokens = set(grouped["command_line"])
        self.assertIn("command_line::structure::operator=and", tokens)
        self.assertIn("command_line::structure::operator=redirect_output", tokens)
        self.assertIn("command_line::structure::nested_operator=pipe", tokens)
        self.assertIn("command_line::relation::switch_value=/c->command_fragment", tokens)

    def test_process_lineage_uses_basename_and_retains_direction(self) -> None:
        grouped, _ = tokenize_record(process("cmd.exe /c whoami", r"C:\Windows\System32\cmd.exe",
                                             parent_image_path=r"C:\Windows\System32\services.exe"))
        tokens = flatten_tokens(grouped)
        self.assertIn("structure::action_object=create->process", tokens)
        self.assertIn("structure::process_lineage=services.exe->cmd.exe", tokens)
        self.assertIn("image_path::basename=cmd.exe", tokens)
        self.assertIn("image_path::category=system", tokens)
        self.assertFalse(any("::prefix=" in token or "::component=" in token for token in tokens))
        reversed_tokens, _ = tokenize_record(process("services.exe", "services.exe", parent_image_path="cmd.exe"))
        self.assertIn("structure::process_lineage=cmd.exe->services.exe", flatten_tokens(reversed_tokens))

    def test_flow_and_unknown_objects_are_excluded_even_with_command(self) -> None:
        for object_type in ("FLOW", "UNKNOWN_NEW_TYPE", None):
            record = process("cmd.exe /c shouldnotappear")
            record["object"] = object_type
            grouped, audit = tokenize_record(record)
            self.assertEqual(set(grouped), set(GROUPS))
            self.assertFalse(flatten_tokens(grouped))
            self.assertFalse(audit["eligible"])
            self.assertEqual(audit["excluded_reason"], "network_flow" if object_type == "FLOW" else "unknown_or_missing_object")

    def test_unlisted_fields_and_nested_values_never_enter_tokens(self) -> None:
        record = process("cmd.exe /c whoami")
        baseline, _ = tokenize_record(record)
        record.update(principal="DOMAIN\\SECRETUSER", actorID="actor-secret", objectID="object-secret",
                      hostname="host-secret", timestamp="2019-09-20T00:00:00Z", label=1)
        record["properties"].update({
            "user": "DOMAIN\\SECRETUSER", "src_ip": "172.17.18.19", "dest_ip": "8.8.8.8",
            "src_port": 49154, "dest_port": 443, "l4protocol": 6, "direction": "outbound",
            "size": 12999, "acuity_level": 5, "start_time": "today", "end_time": "tomorrow",
            "sid": "S-1-5-18", "pid": 77, "custom_new_field": {"secret-key": ["secret-value"]},
            "context_info": "HOST AND USER DUMP", "payload": "SHOULD NOT BE READ ON PROCESS",
        })
        original = copy.deepcopy(record)
        actual, _ = tokenize_record(record)
        baseline["principal"] = ["principal::domain_user"]
        self.assertEqual(actual, baseline)
        self.assertEqual(record, original)
        self.assertEqual(actual["principal"], ["principal::domain_user"])
        self.assertEqual(actual["property_key"], [])
        malformed, _ = tokenize_record({"action": "CREATE", "object": "PROCESS", "properties": {
            "image_path": {"nested": "secrets"}, "command_line": ["nested", "secrets"]}})
        self.assertEqual(len(flatten_tokens(malformed)), 4)

    def test_file_names_and_user_paths_abstract_but_actor_survives(self) -> None:
        def file_event(user: str, filename: str) -> dict:
            return {"action": "WRITE", "object": "FILE", "properties": {
                "image_path": r"C:\Windows\System32\cmd.exe",
                "file_path": rf"C:\Users\{user}\AppData\Local\Temp\{filename}.ps1",
                "size": 999999, "info_class": "INTERNAL_STATUS",
            }}
        first, _ = tokenize_record(file_event("alice", "unique-script-one"))
        second, _ = tokenize_record(file_event("bob", "another-file"))
        self.assertEqual(first, second)
        tokens = flatten_tokens(first)
        self.assertIn("file_path::category=temp", tokens)
        self.assertIn("file_path::extension=.ps1", tokens)
        self.assertIn("image_path::basename=cmd.exe", tokens)
        self.assertFalse(any("file_path::basename=" in token for token in tokens))

    def test_module_keeps_dll_and_actor_without_addresses(self) -> None:
        grouped, _ = tokenize_record({"action": "LOAD", "object": "MODULE", "properties": {
            "image_path": "rundll32.exe", "module_path": r"C:\Windows\System32\shell32.dll",
            "base_address": "0x00288383737", "size": 999,
        }})
        tokens = flatten_tokens(grouped)
        self.assertIn("module_path::basename=shell32.dll", tokens)
        self.assertIn("module_path::category=system", tokens)
        self.assertIn("image_path::basename=rundll32.exe", tokens)
        self.assertEqual(len(tokens), 10)

    def test_registry_uses_root_and_category_only(self) -> None:
        original = {"action": "EDIT", "object": "REGISTRY", "properties": {
            "image_path": "reg.exe", "key": r"\REGISTRY\MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\uniqueapp",
            "value": "secretvalue", "data": "secretpayload", "type": "REG_SZ",
        }}
        grouped, _ = tokenize_record(original)
        tokens = flatten_tokens(grouped)
        self.assertIn("registry::root=hklm", tokens)
        self.assertIn("registry::category=run", tokens)
        self.assertIn("image_path::basename=reg.exe", tokens)
        self.assertFalse(any("uniqueapp" in token or "secret" in token for token in tokens))
        original["properties"]["key"] = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\differentapp"
        second, _ = tokenize_record(original)
        self.assertEqual(grouped, second)

    def test_task_drops_name_user_and_process_identity(self) -> None:
        grouped, _ = tokenize_record({"action": "START", "object": "TASK", "properties": {
            "image_path": "schtasks.exe", "path": r"C:\Users\alice\job.ps1",
            "task_name": "unique secret task", "task_process_uuid": "secret-uuid", "user_name": "alice",
        }})
        tokens = flatten_tokens(grouped)
        self.assertIn("task_path::category=user_profile", tokens)
        self.assertIn("task_path::extension=.ps1", tokens)
        self.assertFalse(any("alice" in token or "secret" in token or "job" in token for token in tokens))

    def test_shell_recognized_payload_discards_values_and_context(self) -> None:
        grouped, audit = tokenize_record({"action": "COMMAND", "object": "SHELL", "properties": {
            "image_path": "powershell.exe", "context_info": "hostname=secret user=alice",
            "payload": 'CommandInvocation(Get-Service): "Get-Service"\nParameterBinding(Get-Service): name="Name"; value="secret-service"',
        }})
        tokens = flatten_tokens(grouped)
        self.assertIn("shell::invocation=get-service", tokens)
        self.assertIn("shell::parameter=name", tokens)
        self.assertIn("shell::parameter_role=name->literal", tokens)
        self.assertFalse(any("secret" in token or "alice" in token for token in tokens))
        unparsed, _ = tokenize_record({"action": "COMMAND", "object": "SHELL", "properties": {"payload": "random secret dump"}})
        self.assertIn("shell::payload=unparsed", flatten_tokens(unparsed))

    def test_schema_only_objects_and_unknown_actions_stay_finite(self) -> None:
        for object_type in ("USER_SESSION", "HOST", "SERVICE"):
            grouped, audit = tokenize_record({"action": "REMOTE_CREATE", "object": object_type,
                                             "properties": {"image_path": "secret.exe", "user": "alice"}})
            self.assertTrue(audit["eligible"])
            self.assertEqual(len(flatten_tokens(grouped)), 4)
        grouped, _ = tokenize_record({"action": "NEW_RANDOM_ACTION", "object": "PROCESS"})
        self.assertIn("action::unknown", grouped["action"])
        self.assertEqual(set(HOST_OBJECTS), set(HOST_OBJECT_FIELDS))
        self.assertIn("no account literals", TOKENIZER_POLICY["principals_and_accounts"])

    def test_python_ast_and_rundll32_relations(self) -> None:
        grouped, _ = tokenize_record(process('python.exe -c "import os; print(os.getcwd())"', "python.exe"))
        tokens = flatten_tokens(grouped)
        self.assertIn("command_line::python::ast=parse_success", tokens)
        self.assertIn("command_line::python::ast_node=import", tokens)
        self.assertIn("command_line::python::ast_edge=module->import", tokens)
        grouped, _ = tokenize_record(process('rundll32.exe shell32.dll,Control_RunDLL', "rundll32.exe"))
        self.assertIn("command_line::relation::launcher_target=library->entry_point", flatten_tokens(grouped))

    def test_decode_encodings_quotes_and_two_layers_without_raw_base64(self) -> None:
        for encoding in ("utf-16le", "utf-8"):
            for source in ("dir", "Write-Output 'hello'"):
                payload = base64.b64encode(source.encode(encoding)).decode()
                for layers in (1, 2):
                    if layers == 2:
                        payload = base64.b64encode(payload.encode(encoding)).decode()
                    with self.subTest(encoding=encoding, source=source, layers=layers):
                        result = decode_powershell_payload(payload)
                        self.assertEqual((result["text"], result["depth"]), (source, layers))
                        grouped, audit = tokenize_record(process(f'powershell -Encoded "{payload}"', "powershell.exe"))
                        self.assertEqual(audit["decode_status"], {f"encoded_decoded_depth_{layers}": 1})
                        self.assertFalse(any(payload.casefold() in token for token in flatten_tokens(grouped)))
                        self.assertIn("command_line::relation::switch_value=-encoded->encoded_command", grouped["command_line"])

    def test_real_partial_decode_and_invalid_payload_limits(self) -> None:
        fixture_path = Path(__file__).resolve().parents[2] / "analyst/sample/command_line_sample.json"
        if not fixture_path.exists():
            fixture_path = Path(__file__).resolve().parents[2] / "analyst/command_line_sample.json"
        records = json.loads(fixture_path.read_text())
        grouped, audit = tokenize_record(records[7])
        self.assertEqual(audit["decode_status"], {"encoded_partial_depth_1": 1})
        self.assertIn("command_line::powershell::decoded_partial", grouped["command_line"])
        payload = POWERSHELL_ENCODED_RE.search(records[7]["properties"]["command_line"]).group(1)
        result = decode_powershell_payload(payload)
        self.assertTrue(result["text"].startswith("IF($PSVErSIoNTabLe"))
        self.assertNotIn("\ufffd", result["text"])
        self.assertEqual(result["discarded_bytes"], 1)
        for payload in ("%%invalid%%", "a", "A" * (MAX_ENCODED_CHARS + 1)):
            self.assertIsNone(decode_powershell_payload(payload)["text"])

    def test_term_frequency_duplicates_and_cached_result_independence(self) -> None:
        record = process("cmd.exe /c echo repeatword repeatword")
        grouped, audit = tokenize_record(record)
        self.assertEqual(grouped["command_line"].count("command_line::cmd::repeatword"), 2)
        grouped["command_line"].append("injected")
        second, _ = tokenize_record(record)
        self.assertNotIn("injected", flatten_tokens(second))
        overlong, _ = tokenize_record(process("cmd.exe /c " + "z" * MAX_COMMAND_CHARS))
        self.assertIn("command_line::input=truncated", flatten_tokens(overlong))
        self.assertTrue(all(len(token) <= 160 and token == token.casefold() for token in flatten_tokens(overlong)))

    def test_noise_normalization_preserves_technical_names(self) -> None:
        self.assertEqual(normalize_literals("kernel32 python27 system32 sha256"), "kernel32 python27 system32 sha256")
        self.assertEqual(normalize_literals("microsoft.windowsstore_11701.1001.27.0_x64__8wekyb3d8bbwe"),
                         "microsoft.windowsstore_version_value_x64__identifier_value")
        self.assertEqual(normalize_literals("x_01234567-1234-1234-1234-0123456789ab"), "x_uuid_value")


if __name__ == "__main__":
    unittest.main()

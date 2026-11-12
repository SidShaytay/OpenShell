"""Publishing and confinement contracts for the live host tools share."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT=Path(__file__).resolve().parents[1]/'scripts/openshell-agent-tools'

class ToolTests(unittest.TestCase):
    def setUp(self):
        loader=importlib.machinery.SourceFileLoader('agent_tools',str(SCRIPT))
        spec=importlib.util.spec_from_loader(loader.name,loader)
        self.w=importlib.util.module_from_spec(spec); loader.exec_module(self.w)
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def test_host_launcher_does_not_shadow_native_installation(self):
        home=self.root/'home'; install=home/'.local/bin'; install.mkdir(parents=True)
        native=install/'claude'; native.write_bytes(b'\x7fELFfixture'); native.chmod(0o755)
        wrappers=self.root/'launchers'; wrappers.mkdir()
        wrapper=wrappers/'claude'; wrapper.write_text('#!/usr/bin/python3\nraise SystemExit("host-only launcher")\n'); wrapper.chmod(0o755)
        with patch.object(self.w.Path,'home',return_value=home),patch.dict(os.environ,{'PATH':str(wrappers)}):
            self.assertEqual(self.w.host_executable('claude'),native)

    def test_native_script_is_rejected_before_publishing(self):
        home=self.root/'home'; install=home/'.local/bin'; install.mkdir(parents=True)
        source=install/'claude'; source.write_text('#!/bin/sh\nexit 0\n'); source.chmod(0o755)
        with patch.object(self.w.Path,'home',return_value=home):
            with self.assertRaisesRegex(ValueError,'not a native ELF executable'):
                self.w.host_executable('claude')

    def test_publish_switches_atomically_and_keeps_previous_release(self):
        source=self.root/'source'; source.write_text('old')
        store=self.root/'tools'; store.mkdir()
        def build(dest): (dest/'tool').write_text(source.read_text())
        first=self.w.publish(store,'test',{'version':1},build)
        source.write_text('new')
        second=self.w.publish(store,'test',{'version':2},build)
        self.assertEqual((store/'test/current/tool').read_text(),'new')
        self.assertEqual((first/'tool').read_text(),'old')
        self.assertNotEqual(first,second)
        self.w.publish(store,'test',{'version':2},lambda _:self.fail('unchanged release rebuilt'))

    def test_failed_publish_leaves_current_untouched(self):
        store=self.root/'tools'; store.mkdir()
        self.w.publish(store,'test',{'version':1},lambda d:(d/'ok').touch())
        def fail(dest): raise RuntimeError('interrupted update')
        with self.assertRaises(RuntimeError): self.w.publish(store,'test',{'version':2},fail)
        self.assertTrue((store/'test/current/ok').exists())

    def test_dependency_closure_includes_nested_versions_and_excludes_other_packages(self):
        modules=self.root/'node_modules'
        def package(name,deps=None):
            path=modules/name; path.mkdir(parents=True)
            (path/'package.json').write_text(json.dumps({'name':name,'version':'1','dependencies':deps or {}}))
            return path
        pi=package('@earendil-works/pi-coding-agent',{'dep':'1'})
        package('dep',{'nested':'1'}); package('nested'); package('unrelated')
        closure=self.w.package_closure(pi)
        self.assertEqual({p.relative_to(modules).as_posix() for p in closure}, {'@earendil-works/pi-coding-agent','dep','nested'})
        (modules/'dep/node_modules/nested').mkdir(parents=True)
        (modules/'dep/node_modules/nested/package.json').write_text('{"name":"nested","version":"2"}')
        closure=self.w.package_closure(pi)
        self.assertIn(modules/'dep/node_modules/nested',closure)
        self.assertNotIn(modules/'nested',closure)

    def test_package_symlink_cannot_escape_installation(self):
        modules=self.root/'node_modules'; package=modules/'pi'; package.mkdir(parents=True)
        (package/'package.json').write_text('{"dependencies":{"escape":"1"}}')
        outside=self.root/'private'; outside.mkdir(); (outside/'package.json').write_text('{}')
        (modules/'escape').symlink_to(outside)
        with self.assertRaisesRegex(ValueError,'outside'): self.w.package_closure(package)

    def test_verification_does_not_inherit_host_credentials_environment(self):
        code="import os; assert 'HOST_SECRET_FIXTURE' not in os.environ; print('version 1')"
        with patch.dict(os.environ,{'HOST_SECRET_FIXTURE':'private'}):
            self.w.verify(['/usr/bin/python3','-c',code])
        with self.assertRaisesRegex(ValueError,'validation failed'):
            self.w.verify(['/usr/bin/false'])

    def test_libraries_keep_lookup_names_instead_of_resolved_filenames(self):
        target=self.root/'libsample.so.1.2'; target.write_text('library')
        alias=self.root/'libsample.so.1'; alias.symlink_to(target.name)
        result=subprocess.CompletedProcess([],0,f'libsample.so.1 => {alias} (0x123)\n','')
        with patch.object(self.w.subprocess,'run',return_value=result):
            self.assertEqual(self.w.library_files(self.root/'node'),[alias])

    def test_launcher_reselects_release_without_replacing_running_files(self):
        store=self.root/'tools'; store.mkdir()
        self.w.install_launchers(store)
        def build(version):
            def populate(dest):
                (dest/'bin').mkdir(); executable=dest/'bin/codex'
                executable.write_text('#!/bin/sh\nprintf "%s" '+version+'\n'); executable.chmod(0o755)
            return populate
        old=self.w.publish(store,'codex',{'version':'one'},build('one'))
        self.assertEqual(subprocess.check_output([store/'bin/codex'],text=True),'one')
        self.w.publish(store,'codex',{'version':'two'},build('two'))
        self.assertEqual(subprocess.check_output([store/'bin/codex'],text=True),'two')
        self.assertEqual(subprocess.check_output([old/'bin/codex'],text=True),'one')

if __name__=='__main__': unittest.main()

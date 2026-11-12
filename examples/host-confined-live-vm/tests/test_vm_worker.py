"""Host-side tests: these exercise the worker sandbox, not guest permissions."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

loader = importlib.machinery.SourceFileLoader('vm_worker', str(Path(__file__).resolve().parents[1]/'scripts'/'openshell-vm-worker'))
spec = importlib.util.spec_from_loader(loader.name, loader)
w = importlib.util.module_from_spec(spec)
loader.exec_module(w)
build_loader = importlib.machinery.SourceFileLoader('vm_build', str(Path(__file__).resolve().parents[1]/'scripts'/'build-confined-driver'))
build_spec = importlib.util.spec_from_loader(build_loader.name, build_loader)
b = importlib.util.module_from_spec(build_spec)
build_loader.exec_module(b)


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.projects = self.base/'projects'; self.projects.mkdir()
        self.project = self.projects/'chosen'; self.project.mkdir()
        self.sibling = self.projects/'sibling'; self.sibling.mkdir()
        (self.sibling/'canary').write_text('outside')
        self.state = self.base/'driver'; self.state.mkdir()
        self.runtime = self.base/'runtime'; self.runtime.mkdir()
        for name in ['root', 'overlay', 'console']:
            (self.state/name).write_text('fixture')
        self.args = ['--internal-run-vm', '--vm-root-disk', str(self.state/'root'),
                     '--vm-overlay-disk', str(self.state/'overlay'),
                     '--vm-console-output', str(self.state/'console'),
                     '--vm-mount', str(self.project)+'\tosfs0\trw']
        for name, value in [('ROOT', self.projects), ('DRIVER_STATE', self.state), ('RUNTIME', self.runtime)]:
            context = patch.object(w, name, value); context.start(); self.addCleanup(context.stop)

    def test_only_selected_project_is_exposed(self):
        command, fds = w.sandbox_command(self.args, ['/usr/bin/true'])
        self.addCleanup(lambda: [os.close(fd) for fd in fds])
        self.assertIn(str(self.project), command)
        self.assertNotIn(str(self.projects), command)
        self.assertNotIn(str(self.sibling), command)
        for option in ['--unshare-all', '--disable-userns', '--clearenv', '--cap-drop']:
            self.assertIn(option, command)

    def test_share_outside_projects_and_parent_root_are_refused(self):
        for source in [self.base, self.projects, self.sibling/'..']:
            with self.subTest(source=source), self.assertRaises(ValueError):
                w.sandbox_command(self.args[:-1]+[str(source)+'\tosfs0\trw'])

    def test_unknown_flags_and_backend_are_refused(self):
        for extra in [['--vm-backend', 'qemu'], ['--unexpected', '/']]:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                w.sandbox_command(self.args+extra)

    def test_no_extra_project_shares(self):
        with self.assertRaises(ValueError):
            w.sandbox_command(self.args+['--vm-mount', str(self.sibling)+'\tosfs1\trw'])

    def test_tools_share_is_exact_and_read_only(self):
        tools=self.base/'agent-tools'; tools.mkdir()
        args=self.args+['--vm-mount',str(tools)+'\tosfs1\tro']
        with patch.object(w,'TOOLS',tools):
            command,fds=w.sandbox_command(args,['/usr/bin/true'])
            for fd in fds: os.close(fd)
            self.assertIn('--ro-bind-fd',command)
            self.assertIn(str(tools),command)
            for source,mode,tag in [(tools,'rw','osfs1'),(self.sibling,'ro','osfs1'),(tools,'ro','osfs2')]:
                with self.subTest(source=source,mode=mode,tag=tag),self.assertRaises(ValueError):
                    w.sandbox_command(self.args+['--vm-mount',f'{source}\t{tag}\t{mode}'])

    def test_running_worker_sees_host_tools_updates_but_cannot_write(self):
        tools=self.base/'agent-tools'; tools.mkdir(); (tools/'version').write_text('one')
        args=self.args+['--vm-mount',str(tools)+'\tosfs1\tro']
        code="""import pathlib,sys
root=pathlib.Path(sys.argv[1])
assert (root/'version').read_text()=='one'
try: (root/'forbidden').write_text('write')
except OSError: pass
else: raise AssertionError('tools share was writable')
print('ready',flush=True)
sys.stdin.readline()
assert (root/'version').read_text()=='two'
print('updated',flush=True)
"""
        with patch.object(w,'TOOLS',tools):
            command,fds=w.sandbox_command(args,['/usr/bin/python3','-c',code,str(tools)])
        try:
            process=subprocess.Popen(command,pass_fds=fds,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        finally:
            for fd in fds: os.close(fd)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        self.assertEqual(process.stdout.readline().strip(),'ready')
        (tools/'next').write_text('two'); (tools/'next').replace(tools/'version')
        stdout,stderr=process.communicate('continue\n',timeout=10)
        self.assertEqual(process.returncode,0,stderr)
        self.assertIn('updated',stdout)

    def test_disks_cannot_name_host_files_or_symlinks(self):
        (self.state/'escape').symlink_to(self.sibling/'canary')
        for outside in [self.sibling/'canary', self.state/'escape']:
            argv=self.args.copy(); argv[argv.index('--vm-root-disk')+1]=str(outside)
            with self.subTest(outside=outside), self.assertRaises(ValueError):
                w.sandbox_command(argv)

    def test_ancestor_symlink_swap_cannot_change_the_project_share(self):
        parent=self.projects/'parent'; nested=parent/'child'; nested.mkdir(parents=True)
        (self.sibling/'child').mkdir()
        self.args[-1]=str(nested)+'\tosfs0\trw'
        original=w.checked_path
        def swap(value,*args,**kwargs):
            result=original(value,*args,**kwargs)
            if str(value)==str(nested):
                parent.rename(self.projects/'original-parent'); parent.symlink_to(self.sibling)
            return result
        with patch.object(w,'checked_path',side_effect=swap),self.assertRaises(OSError):
            _,fds=w.sandbox_command(self.args)
            self.addCleanup(lambda: [os.close(fd) for fd in fds])

    def test_rebuild_installs_matching_provenance_with_the_driver(self):
        binary=self.base/'new-driver'; binary.write_bytes(b'compiled fixture')
        provenance=self.base/'provenance.json'; provenance.write_text('{"version":"0.1.7"}\n')
        vendor=self.base/'vendor'; vendor.mkdir()
        for name in ['openshell-supervisor','openshell-prover']: (vendor/name).write_text('fixture')
        with patch.object(b.Path,'home',return_value=self.base/'install-home'):
            dest=b.install_driver(binary,provenance,vendor)
        self.assertEqual((dest/'openshell-driver-vm').read_bytes(),binary.read_bytes())
        self.assertEqual((dest/'provenance.json').read_bytes(),provenance.read_bytes())
        self.assertEqual((dest/'provenance.json').stat().st_mode & 0o777,0o600)

    def test_install_check_refuses_a_changed_driver(self):
        import hashlib, json
        home=self.base/'home'; confined=home/'.local/libexec/openshell/v0.1.7-confined'
        confined.mkdir(parents=True); binary=confined/'openshell-driver-vm'; binary.write_bytes(b'fixture')
        (confined/'provenance.json').write_text(json.dumps({'version':'0.1.7','driver_sha256':hashlib.sha256(b'fixture').hexdigest()}))
        config=home/'.config/openshell/servers/vm/gateway.toml'; config.parent.mkdir(parents=True)
        config.write_text('[openshell.drivers.vm]\ndriver_dir = '+json.dumps(str(confined))+'\nallow_driver_config = true\nenable_bind_mounts = true\n[openshell.drivers.vm.resource_admission]\nenabled = false\n')
        unit=home/'.config/systemd/user/openshell-vm.service'; unit.parent.mkdir(parents=True)
        unit.write_text('Environment="OPENSHELL_VM_HOST_LAUNCHER='+str(home)+'/.local/bin/openshell-vm-worker"\n')
        with patch.object(w,'HOME',home):
            w.check_install()
            binary.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'provenance'): w.check_install()

    def test_host_worker_cannot_escape_via_paths_symlinks_or_proc(self):
        (self.project/'escape').symlink_to(self.sibling)
        source = '''import os, pathlib, socket, sys, subprocess
project, sibling, parent = map(pathlib.Path, sys.argv[1:])
assert os.getppid()>1, 'vendor procguard must not see PID 1 as its parent'
(project/'worker-write').write_text('live')
assert (project/'worker-write').read_text() == 'live'
for path in [sibling/'canary', project/'escape/canary', project/'../sibling/canary', pathlib.Path('/proc/1/root')/str(sibling).lstrip('/')/'canary']:
    try:
        path.read_text()
    except (OSError, PermissionError):
        pass
    else:
        raise AssertionError('outside file reachable: '+str(path))
# Also inspect descriptors in the namespace parent/reaper, not just this child.
# A setup descriptor retaining an old host mount must not provide a back door.
relative_canaries=[(sibling/'canary').relative_to(parent) for parent in sibling.parents]
relative_canaries.append(pathlib.Path('../sibling/canary'))
for process in pathlib.Path('/proc').iterdir():
    if not process.name.isdigit(): continue
    try: descriptors=list((process/'fd').iterdir())
    except OSError: continue
    for descriptor in descriptors:
        for relative in relative_canaries:
            try: (descriptor/relative).read_text()
            except OSError: pass
            else: raise AssertionError('host mount descriptor leaked: '+str(descriptor))
status=pathlib.Path('/proc/self/status').read_text()
assert 'CapEff:\\t0000000000000000' in status
assert 'NoNewPrivs:\\t1' in status
assert not pathlib.Path('/run/user/1000/podman/podman.sock').exists()
assert 'OSH_HOST_ONLY_CANARY' not in os.environ
assert subprocess.run(['/usr/bin/unshare','-Ur','/usr/bin/true'],capture_output=True).returncode != 0
# No inherited directory descriptor may retain the host root or parent tree.
for fd in pathlib.Path('/proc/self/fd').iterdir():
    if fd.name.isdigit() and int(fd.name)>2:
        try: assert not pathlib.Path(os.readlink(fd)).is_dir(), str(fd)
        except FileNotFoundError: pass
print('HOST_WORKER_CONFINEMENT_OK')
'''
        command, fds = w.sandbox_command(self.args, ['/usr/bin/python3', '-I', '-c', source, str(self.project), str(self.sibling), str(self.base)])
        try:
            with patch.dict(os.environ,{'OSH_HOST_ONLY_CANARY':'must-not-enter-worker'}):
                result = subprocess.run(command, pass_fds=fds, text=True, capture_output=True)
        finally:
            for fd in fds: os.close(fd)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('HOST_WORKER_CONFINEMENT_OK', result.stdout)
        self.assertEqual((self.project/'worker-write').read_text(), 'live')


if __name__ == '__main__':
    unittest.main()

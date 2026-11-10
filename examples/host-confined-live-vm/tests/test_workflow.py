import importlib.machinery
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

loader=importlib.machinery.SourceFileLoader('workflow',str(Path(__file__).resolve().parents[1]/'scripts'/'openshell-project'))
spec=importlib.util.spec_from_loader(loader.name,loader); w=importlib.util.module_from_spec(spec); loader.exec_module(w)

class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.host=self.root/'projects'/'test'; self.host.mkdir(parents=True)
        self.source=self.root/'review'; self.source.mkdir()
    def test_external_symlink_rejected(self):
        (self.host/'escape').symlink_to('/etc/passwd')
        with self.assertRaises(ValueError): w.audit(self.host)
    def test_external_hardlink_rejected(self):
        import os
        outside=self.root/'outside'; outside.write_text('x'); os.link(outside,self.host/'linked')
        with self.assertRaises(ValueError): w.audit(self.host)
    def test_secret_rejected(self):
        (self.host/'.env.production').write_text('placeholder')
        with self.assertRaises(ValueError): w.audit(self.host)
    def session(self):
        folder=self.root/'state'/'project-test'; folder.mkdir(parents=True)
        m={'host':str(self.host),'gateway':'vm','runtime':'vm','baseline':w.manifest(self.host),'review':str(self.source),'result':w.manifest(self.source)}
        (folder/'session.json').write_text(json.dumps(m)); return folder
    def call_apply(self):
        original=w.audit
        with patch.object(w,'STATE',self.root/'state'),patch.object(w,'ROOT',self.root/'projects'),patch.object(w,'audit',lambda r,labels=False:original(r)):
            w.review('project-test',True)
    def test_add_modify_delete(self):
        (self.host/'modified').write_text('before'); (self.host/'removed').write_text('delete me')
        (self.source/'modified').write_text('after'); (self.source/'added').write_text('new')
        folder=self.session(); self.call_apply()
        self.assertEqual((self.host/'modified').read_text(),'after'); self.assertFalse((self.host/'removed').exists())
        self.assertEqual((self.host/'added').read_text(),'new'); self.assertEqual(next(folder.glob('before-apply-*/removed')).read_text(),'delete me')
    def test_apply_does_not_import_snapshot_xattrs(self):
        import os
        (self.source/'added').write_text('new')
        os.setxattr(self.source/'added', 'user.osh-snapshot', b'review-only')
        self.session(); self.call_apply()
        self.assertEqual((self.host/'added').read_text(), 'new')
        self.assertNotIn('user.osh-snapshot', os.listxattr(self.host/'added'))

    def test_dependency_trees_are_excluded_from_audit_and_copyback(self):
        import shutil
        (self.host/'source.ts').write_text('source')
        dependencies=self.host/'node_modules'/'sdk'/'credentials'
        dependencies.mkdir(parents=True)
        (dependencies/'auth.json').write_text('host dependency fixture')
        (self.host/'node_modules'/'external').symlink_to('/etc')
        w.audit(self.host)
        self.assertEqual(set(w.manifest(self.host)), {'source.ts'})
        snapshot=self.root/'snapshot'
        shutil.copytree(self.host,snapshot,symlinks=True,ignore=shutil.ignore_patterns(*w.PROJECT_EXCLUDES))
        self.assertFalse((snapshot/'node_modules').exists())
        (self.source/'source.ts').write_text('source')
        generated=self.source/'node_modules'/'generated'
        generated.mkdir(parents=True); (generated/'auth.json').write_text('guest dependency fixture')
        self.session(); self.call_apply()
        self.assertFalse((self.host/'node_modules'/'generated').exists())
        self.assertEqual((dependencies/'auth.json').read_text(),'host dependency fixture')

    def test_dependency_credentials_source_directory_is_audited_not_rejected(self):
        source=self.host/'node_modules'/'sdk'/'lib'/'credentials'; source.mkdir(parents=True)
        (source/'index.js').write_text('export {};\n')
        w.audit(self.host,include_dependencies=True,include_git=True)
        (source/'credentials.json').write_text('fixture')
        with self.assertRaises(ValueError): w.audit(self.host,include_dependencies=True,include_git=True)

    def test_live_bind_audit_still_checks_dependency_tree(self):
        dependencies=self.host/'node_modules'
        dependencies.mkdir(); (dependencies/'auth.json').write_text('fixture')
        with self.assertRaises(ValueError):
            w.audit(self.host,include_dependencies=True)

    def test_host_conflict_rejected(self):
        (self.host/'file').write_text('before'); (self.source/'file').write_text('agent')
        self.session(); (self.host/'file').write_text('concurrent')
        with self.assertRaises(ValueError): self.call_apply()
        self.assertEqual((self.host/'file').read_text(),'concurrent')
    def test_review_tamper_rejected(self):
        (self.source/'file').write_text('agent'); self.session(); (self.source/'file').write_text('changed')
        with self.assertRaises(ValueError): self.call_apply()
        self.assertFalse((self.host/'file').exists())

    def test_unrelated_host_edit_allowed(self):
        (self.host/'agent-file').write_text('before'); (self.source/'agent-file').write_text('after')
        (self.host/'host-file').write_text('before'); (self.source/'host-file').write_text('before')
        self.session(); (self.host/'host-file').write_text('host changed')
        self.call_apply()
        self.assertEqual((self.host/'host-file').read_text(),'host changed')
        self.assertEqual((self.host/'agent-file').read_text(),'after')
    def test_apply_idempotent(self):
        (self.host/'file').write_text('before'); (self.source/'file').write_text('after')
        self.session(); self.call_apply(); self.call_apply()
        self.assertEqual((self.host/'file').read_text(),'after')
    def test_delete_blocks_unapplied_vm_work(self):
        (self.host/'file').write_text('before'); (self.source/'file').write_text('after')
        self.session()
        with patch.object(w,'STATE',self.root/'state'),patch.object(w,'collect'),patch.object(w,'run') as run:
            with self.assertRaises(ValueError): w.delete_session('project-test')
            run.assert_not_called()
        self.assertEqual((self.host/'file').read_text(),'before')
        self.assertEqual((self.source/'file').read_text(),'after')
    def test_delete_after_apply(self):
        (self.host/'file').write_text('same'); (self.source/'file').write_text('same')
        self.session()
        with patch.object(w,'STATE',self.root/'state'),patch.object(w,'collect'),patch.object(w,'run') as run:
            w.delete_session('project-test'); run.assert_called_once()
    def test_defaults(self):
        with patch.object(w,'launch') as launch:
            w.main([]); a=launch.call_args.args[0]
            self.assertEqual((a.runtime,a.agent),('vm','shell'))
            w.main(['vm']); a=launch.call_args.args[0]
            self.assertEqual((a.runtime,a.agent),('vm','shell'))
            w.main(['pi']); self.assertEqual((launch.call_args.args[0].runtime,launch.call_args.args[0].agent),('vm','pi'))
            w.main(['podman']); self.assertEqual(launch.call_args.args[0].runtime,'podman')
            w.main(['--runtime','podman']); self.assertEqual(launch.call_args.args[0].runtime,'podman')

    def test_podman_project_mount_does_not_replace_reserved_workspace(self):
        from types import SimpleNamespace
        with patch.object(w,'STATE',self.root/'state'), patch.object(w,'ROOT',self.root/'projects'), patch.object(w,'audit'), patch.object(w,'output',return_value=w.LABEL), patch.object(w,'provision_agents'), patch.object(w,'run') as run, patch.object(w.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as invoke:
            w.main(['podman','--project',str(self.host),'shell','-c','pwd'])
        create=next(c.args[0] for c in run.call_args_list if 'create' in c.args[0])
        config=json.loads(create[create.index('--driver-config-json')+1])
        self.assertEqual(config['podman']['mounts'][0]['target'],str(self.host))
        execute=next(c.args[0] for c in invoke.call_args_list if 'exec' in c.args[0])
        self.assertIn(str(self.host),execute)

    def test_vm_uses_live_project_without_snapshot_or_copyback(self):
        from types import SimpleNamespace
        with patch.object(w,'STATE',self.root/'state'), patch.object(w,'ROOT',self.root/'projects'), patch.object(w,'audit') as audit, patch.object(w,'provision_agents'), patch.object(w,'vm_exit') as exit_vm, patch.object(w,'manifest',side_effect=AssertionError('no live hashing')), patch.object(w,'run') as run, patch.object(w.subprocess,'run',return_value=SimpleNamespace(returncode=0)):
            w.main(['--project',str(self.host),'shell','-c','pwd'])
        create=next(c.args[0] for c in run.call_args_list if 'create' in c.args[0])
        config=json.loads(create[create.index('--driver-config-json')+1])
        mounts=config['vm']['mounts']
        self.assertEqual(len(mounts),1)
        self.assertEqual(mounts[0]['source'],str(self.host))
        self.assertEqual(mounts[0]['target'],str(self.host))
        self.assertFalse(mounts[0]['read_only'])
        audit.assert_called_once_with(self.host,labels=False,include_dependencies=True,include_git=True)
        exit_vm.assert_not_called()
        self.assertFalse(any('upload' in c.args[0] for c in run.call_args_list))
        record=next((self.root/'state').glob('*/session.json'))
        self.assertEqual(json.loads(record.read_text())['project_mode'],'live')

    def test_live_vm_reentry_does_not_collect_or_prompt(self):
        from types import SimpleNamespace
        folder=self.add_named_session('test-a1b2c3')
        record=folder/'session.json'; m=json.loads(record.read_text())
        m.update(project_mode='live',agent_setup=w.AGENT_SETUP_VERSION,workdir=str(Path('/workspace')/'project'))
        record.write_text(json.dumps(m))
        with patch.object(w,'STATE',self.root/'state'), patch.object(w,'live_names',return_value={'test-a1b2c3'}), patch.object(w,'vm_exit') as exit_vm, patch.object(w.subprocess,'run',return_value=SimpleNamespace(returncode=0)):
            w.enter('test-a1b2c3')
        exit_vm.assert_not_called()

    def test_live_vm_refuses_review_and_deletes_without_copyback(self):
        folder=self.session(); record=folder/'session.json'
        m=json.loads(record.read_text()); m['project_mode']='live'; record.write_text(json.dumps(m))
        with patch.object(w,'STATE',self.root/'state'),patch.object(w,'run') as run:
            with self.assertRaisesRegex(ValueError,'live'): w.collect('project-test')
            with self.assertRaisesRegex(ValueError,'live'): w.review('project-test',True)
            run.assert_not_called()
            w.delete_session('project-test')
            run.assert_called_once()

    def test_project_policy_adds_only_the_selected_canonical_path(self):
        policy=w.project_policy(self.host)
        self.assertIn('    - '+json.dumps(str(self.host))+'\n',policy)
        self.assertEqual(policy.count('network_policies:'),1)

    def test_live_git_absolute_metadata_inside_selected_project_is_valid(self):
        metadata=self.host/'.git'/'worktrees'/'main'; metadata.mkdir(parents=True)
        worktree=self.host/'main'; worktree.mkdir()
        (worktree/'.git').write_text('gitdir: '+str(metadata)+'\n')
        w.audit(self.host,include_dependencies=True,include_git=True)

    def test_live_audit_includes_git_and_dependency_paths(self):
        (self.host/'.git').mkdir(); (self.host/'.git'/'escape').symlink_to('/etc')
        with self.assertRaises(ValueError): w.audit(self.host,include_dependencies=True,include_git=True)

    def test_live_audit_refuses_external_gitdir(self):
        (self.host/'.git').write_text('gitdir: ../outside\n')
        with self.assertRaisesRegex(ValueError,'Git metadata'): w.audit(self.host,include_dependencies=True,include_git=True)

    def test_project_image_default_and_cli_override(self):
        module=self.root/'module'; (module/'projects').mkdir(parents=True)
        (module/'projects'/'test.toml').write_text('path = '+json.dumps(str(self.host))+'\nimage = "localhost/pilot:test"\n')
        with patch.object(w,'ROOT',self.root/'projects'), patch.object(w,'MODULE',module), patch.object(w,'run') as run:
            w.main(['--project',str(self.host),'--check'])
            self.assertEqual(run.call_args.args[0],['podman','image','exists','localhost/pilot:test'])
            w.main(['--project',str(self.host),'--image','localhost/override:test','--check'])
            self.assertEqual(run.call_args.args[0],['podman','image','exists','localhost/override:test'])

    def test_candidate_image_cli(self):
        with patch.object(w,'launch') as launch:
            w.main(['--image','localhost/openshell-agent-dev:browser-test'])
            self.assertEqual(launch.call_args.args[0].image,'localhost/openshell-agent-dev:browser-test')

    def add_named_session(self,name,runtime='vm'):
        folder=self.root/'state'/name; folder.mkdir(parents=True)
        (folder/'session.json').write_text(json.dumps({'host':str(self.host),'gateway':runtime,'runtime':runtime,'baseline':{}}))
        return folder

    def test_session_slug_uses_project_name_and_six_random_hex(self):
        self.assertEqual(w.session_slug(Path('/var/mnt/data/projects/iCloud_MD!')),'icloud-md')
        self.assertEqual(w.session_slug(Path('/var/mnt/data/projects/---')),'project')
        long_name=w.session_slug(Path('/var/mnt/data/projects/非常に長いプロジェクト名abcdefghijk'))
        full_name=long_name+'-'+'a1b2c3'
        self.assertLessEqual(len(full_name),19)
        self.assertTrue(w.is_named_session(full_name))
        self.assertNotIn('--',full_name)
        self.assertTrue(re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*',long_name))

    def test_resolve_new_full_slug_or_short_id_and_legacy_prefix(self):
        folder=self.add_named_session('icloud-md-a1b2c3')
        self.add_named_session('project-abcdef1234')
        with patch.object(w,'STATE',self.root/'state'):
            self.assertEqual(w.meta('icloud-md-a1b2c3')[0],folder)
            self.assertEqual(w.meta('project-abcdef1234')[0].name,'project-abcdef1234')
            self.assertEqual(w.resolve_session('icloud-md-a1b2c3'),'icloud-md-a1b2c3')
            self.assertEqual(w.resolve_session('icloud-md'),'icloud-md-a1b2c3')
            self.assertEqual(w.resolve_session('a1b2c3'),'icloud-md-a1b2c3')
            self.assertEqual(w.resolve_session('abcdef'),'project-abcdef1234')

    def test_listing_continues_past_a_stopped_gateway(self):
        from types import SimpleNamespace
        import subprocess
        def invoke(args,**kwargs):
            code=1 if 'podman' in args else 0
            if code and kwargs.get('check'): raise subprocess.CalledProcessError(code,args)
            return SimpleNamespace(returncode=code,stdout='No sandboxes found.\n',stderr='unavailable')
        with patch.object(w.subprocess,'run',side_effect=invoke) as calls,patch.object(w,'live_names',return_value=set()):
            w.list_sessions()
        self.assertTrue(any('vm' in c.args[0] for c in calls.call_args_list))

    def test_default_reentry_works_when_unused_podman_gateway_is_stopped(self):
        self.add_named_session('test-a1b2c3')
        def listed(runtime):
            if runtime=='podman': raise ValueError('podman gateway unavailable')
            return {'test-a1b2c3'}
        with patch.object(w,'STATE',self.root/'state'),patch.object(w.Path,'cwd',return_value=self.host),patch.object(w,'live_names',side_effect=listed):
            self.assertEqual(w.resolve_session(),'test-a1b2c3')

    def test_resolve_short_id_collision_is_reported(self):
        self.add_named_session('icloud-md-abcdef')
        self.add_named_session('other-project-abcdef')
        with patch.object(w,'STATE',self.root/'state'):
            with self.assertRaisesRegex(ValueError,'ambiguous'): w.resolve_session('abcdef')

    def test_live_names_match_recorded_sessions_only(self):
        self.add_named_session('icloud-md-a1b2c3')
        listed=type('R',(),{'returncode':0,'stdout':'icloud-md-a1b2c3\nproject-unrelated\nother-123abc\n'})()
        with patch.object(w,'STATE',self.root/'state'),patch.object(w.subprocess,'run',return_value=listed):
            self.assertEqual(w.live_names('vm'),{'icloud-md-a1b2c3'})
    def test_legacy_alias_mapping(self):
        self.assertEqual(w.cli('openshell','status')[2],'vm')
        self.assertEqual(w.cli('podman-v012','status')[2],'podman')

    def test_exit_yes_applies(self):
        (self.source/'file').write_text('changed'); self.session()
        with patch.object(w,'STATE',self.root/'state'),patch.object(w,'collect'),patch('builtins.input',return_value='yes'),patch.object(w,'review') as review:
            w.vm_exit('project-test'); review.assert_called_once_with('project-test',True)
    def test_exit_no_needs_second_confirmation(self):
        (self.source/'file').write_text('agent'); self.session()
        with patch.object(w,'STATE',self.root/'state'),patch.object(w,'collect'),patch('builtins.input',side_effect=['no','no']),patch.object(w,'run') as run:
            w.vm_exit('project-test'); run.assert_not_called()
        self.assertTrue((self.source/'file').exists())
    def test_exit_discard_deletes_download(self):
        (self.source/'file').write_text('agent'); folder=self.session()
        download=folder/'download-test'; download.mkdir(); (download/'file').write_text('agent')
        with patch.object(w,'STATE',self.root/'state'),patch.object(w,'collect'),patch('builtins.input',side_effect=['no','discard']),patch.object(w,'run') as run:
            w.vm_exit('project-test'); run.assert_called_once()
        self.assertFalse(download.exists()); self.assertTrue(json.loads((folder/'session.json').read_text())['discarded'])
    def test_exit_without_input_retains(self):
        self.session()
        with patch.object(w,'STATE',self.root/'state'),patch.object(w,'collect'),patch('builtins.input',side_effect=EOFError),patch.object(w,'run') as run:
            w.vm_exit('project-test'); run.assert_not_called()
    def test_conflict_guidance(self):
        (self.host/'file').write_text('before'); (self.source/'file').write_text('agent'); self.session(); (self.host/'file').write_text('host')
        with self.assertRaisesRegex(ValueError,'diff -u --'): self.call_apply()

    def test_agent_bundle_excludes_host_auth(self):
        home=self.root/'home'; skills=home/'.agents/skills/user-docs'; skills.mkdir(parents=True); (skills/'SKILL.md').write_text('skill')
        # Only manually selected skills may enter the guest, never a source library.
        library=home/'.agents/skills-library-test/unselected'; library.mkdir(parents=True); (library/'SKILL.md').write_text('unselected')
        pi=home/'.pi/agent'; pi.mkdir(parents=True); (pi/'settings.json').write_text('{"packages": [], "secret": "exclude"}'); (pi/'auth.json').write_text('must not copy')
        self.session()
        def inspect(args,**kwargs):
            if 'upload' in args:
                bundle=Path(args[-2]); self.assertTrue((bundle/'skills/user-docs/SKILL.md').exists()); self.assertFalse((bundle/'pi-agent/auth.json').exists())
                self.assertFalse((bundle/'skills/unselected').exists())
                self.assertIn('osh allow SESSION',(bundle/'browser/AGENTS.playwright-cli.md').read_text())
                settings=json.loads((bundle/'pi-agent/settings.json').read_text()); self.assertNotIn('secret',settings)
                self.assertEqual(settings['defaultProvider'],'llama-swap')
                self.assertEqual(settings['defaultModel'],'gemma-4-e4b')
                self.assertEqual(settings['llama-swap']['fallbackModel'],'qwen3.8-27b')
            elif args[-2]=='-c' and 'for skill in ' in args[-1]:
                import subprocess
                setup=args[-1]; marker='if [ -L /home/agent/.codex/skills/.system ]'
                start=setup.index(marker) if marker in setup else setup.index('for skill in ')
                end=setup.index('\ndone',start)+len('\ndone')
                source=self.root/'selected-skills'; (source/'user-docs').mkdir(parents=True)
                dest=self.root/'codex-skills'; dest.mkdir(); (dest/'.system').symlink_to(source/'.system')
                loop=setup[start:end].replace('/sandbox/osh-agent-setup/skills',str(source)).replace('/home/agent/.codex/skills',str(dest))
                subprocess.run(['bash','-ec',loop],check=True)
                self.assertTrue((dest/'user-docs').is_symlink())
                self.assertFalse((dest/'.system').is_symlink(), 'missing system skills must not leave a dangling link')
        with patch.object(w.Path,'home',return_value=home),patch.object(w,'STATE',self.root/'state'),patch.object(w,'run',side_effect=inspect):
            w.provision_agents('project-test','vm')

    def test_reentry_refreshes_legacy_agent_setup_before_running_pi(self):
        for setup,expected_calls in [(True,1),(2,1),(w.AGENT_SETUP_VERSION,0)]:
            with self.subTest(setup=setup):
                record={'gateway':'vm','runtime':'vm','agent_setup':setup,'host':str(self.host)}
                result=type('R',(),{'returncode':0})()
                with patch.object(w,'meta',return_value=(self.root,record)),patch.object(w,'live_names',return_value={'test'}),patch.object(w,'provision_agents') as provision,patch.object(w.subprocess,'run',return_value=result),patch.object(w,'vm_exit'):
                    w.enter('test','pi')
                    self.assertEqual(provision.call_count,expected_calls)

    def test_exit_unchanged_never_prompts_or_deletes(self):
        self.session()
        with patch.object(w,'STATE',self.root/'state'),patch.object(w,'collect'),patch('builtins.input') as prompt,patch.object(w,'run') as run:
            w.vm_exit('project-test'); prompt.assert_not_called(); run.assert_not_called()

    def test_https_origin_only(self):
        self.assertEqual(w.https_origin('HTTPS://Docs.Example.com/'),('https://docs.example.com','docs.example.com',443))
        self.assertEqual(w.https_origin('https://docs.example.com:8443'),('https://docs.example.com:8443','docs.example.com',8443))
        for value in ['http://docs.example.com','https://docs.example.com/page','https://docs.example.com/?q=x','https://user@docs.example.com','https://127.0.0.1','https://*.example.com']:
            with self.subTest(value=value),self.assertRaises(ValueError): w.https_origin(value)

    def test_allow_is_chromium_scoped_and_saved(self):
        folder=self.session()
        with patch.object(w,'STATE',self.root/'state'),patch.object(w,'live_names',return_value={'project-test'}),patch.object(w,'output',return_value='/opt/chromium/chrome'),patch.object(w,'run') as run:
            w.allow_origin('project-test','https://docs.example.com')
        args=run.call_args.args[0]
        self.assertIn('--binary',args); self.assertEqual(args[args.index('--binary')+1],'/opt/chromium/chrome')
        self.assertIn('--add-endpoint',args); self.assertIn('docs.example.com:443:read-write:rest:enforce',args)
        self.assertIn('--wait',args)
        saved=json.loads((folder/'session.json').read_text())
        self.assertIn('https://docs.example.com',saved['browser_origins'])

    def test_allow_rejects_invalid_origin_before_policy(self):
        self.session()
        with patch.object(w,'STATE',self.root/'state'),patch.object(w,'live_names',return_value={'project-test'}),patch.object(w,'output',return_value='/opt/chromium/chrome'),patch.object(w,'run') as run:
            for origin in ['http://docs.example.com','https://docs.example.com/private/path','https://127.0.0.1']:
                with self.subTest(origin=origin),self.assertRaises(ValueError): w.allow_origin('project-test',origin)
            run.assert_not_called()

    def test_revoke_only_removes_osh_managed_origin(self):
        folder=self.session(); record=json.loads((folder/'session.json').read_text()); record['browser_origins']={'https://docs.example.com':{'rule':'osh_browser_123','binary':'/opt/chromium/chrome'}}; (folder/'session.json').write_text(json.dumps(record))
        with patch.object(w,'STATE',self.root/'state'),patch.object(w,'live_names',return_value={'project-test'}),patch.object(w,'run') as run:
            w.revoke_origin('project-test','https://docs.example.com/')
            self.assertIn('--remove-rule',run.call_args.args[0]); self.assertIn('osh_browser_123',run.call_args.args[0])
            with self.assertRaises(ValueError): w.revoke_origin('project-test','https://other.example.com')
            self.assertEqual(run.call_count,1)
        self.assertEqual(json.loads((folder/'session.json').read_text())['browser_origins'],{})

    def test_forward_services_bind_host_loopback(self):
        self.session()
        with patch.object(w,'STATE',self.root/'state'),patch.object(w,'live_names',return_value={'project-test'}),patch.object(w,'run') as guest,patch.object(w.subprocess,'run',return_value=type('R',(),{'returncode':0})()) as forward:
            w.forward_service('project-test',3000,13000)
        guest.assert_not_called()
        args=forward.call_args.args[0]
        self.assertEqual(args[args.index('--local')+1],'127.0.0.1:13000')
        self.assertIn('--target-port',args); self.assertIn('3000',args)

    def test_browser_view_starts_desktop_and_tunnels_localhost(self):
        self.session()
        with patch.object(w,'STATE',self.root/'state'),patch.object(w,'live_names',return_value={'project-test'}),patch.object(w,'run') as guest,patch.object(w.subprocess,'run',return_value=type('R',(),{'returncode':0})()) as forward:
            w.browser_view('project-test')
        self.assertIn('agent-desktop',guest.call_args.args[0]); self.assertIn('start',guest.call_args.args[0])
        self.assertIn('127.0.0.1:6080',forward.call_args.args[0])

if __name__=='__main__': unittest.main()

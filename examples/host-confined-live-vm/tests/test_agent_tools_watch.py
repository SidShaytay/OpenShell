import importlib.machinery
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch,MagicMock

loader=importlib.machinery.SourceFileLoader('tools_watch',str(Path(__file__).resolve().parents[1]/'scripts/openshell-agent-tools-watch'))
spec=importlib.util.spec_from_loader(loader.name,loader)
w=importlib.util.module_from_spec(spec)

class WatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): loader.exec_module(w)

    def test_watch_plan_is_small_and_never_includes_system_library_tree(self):
        plan=w.watch_plan()
        self.assertGreaterEqual(len(plan),5)
        self.assertLessEqual(len(plan),10)
        self.assertNotIn(Path('/usr/lib64'),dict(plan))
        self.assertEqual(w.SYNC_INTERVAL,6*60*60)

    def test_only_selected_names_trigger_and_nested_changes_are_not_watched(self):
        with tempfile.TemporaryDirectory() as temp,w.Watcher() as watch:
            root=Path(temp); nested=root/'package'; nested.mkdir()
            watch.add(root,{'agent'})
            (root/'unrelated').write_text('ignore')
            (nested/'agent').write_text('ignore')
            self.assertFalse(watch.changed(0.05))
            (root/'agent').write_text('update')
            self.assertTrue(watch.changed(1))
            self.assertEqual(len(watch.paths),1)

    def test_replaced_symlink_is_observed_without_following_target(self):
        with tempfile.TemporaryDirectory() as temp,w.Watcher() as watch:
            root=Path(temp); watched=root/'bin'; watched.mkdir()
            outside=root/'private'; outside.mkdir()
            (watched/'agent').symlink_to(outside)
            watch.add(watched,{'agent'})
            (outside/'secret').write_text('private')
            self.assertFalse(watch.changed(0.05))
            (watched/'new').symlink_to('release-two')
            (watched/'new').replace(watched/'agent')
            self.assertTrue(watch.changed(1))

    def test_six_hour_timeout_triggers_sync_without_file_events(self):
        watcher=MagicMock(); watcher.__enter__.return_value=watcher
        watcher.changed.return_value=False
        with patch.object(w,'Watcher',return_value=watcher),patch.object(w,'watch_plan',return_value=[]),patch.object(w.time,'monotonic',side_effect=[0,0,w.SYNC_INTERVAL]),patch.object(w,'publish',side_effect=[None,RuntimeError('stop after fallback')]) as publish:
            with self.assertRaisesRegex(RuntimeError,'stop after fallback'): w.main()
        self.assertEqual(publish.call_count,2)
        watcher.changed.assert_called_once_with(w.SYNC_INTERVAL)

    def test_unfiltered_release_directory_observes_new_version(self):
        with tempfile.TemporaryDirectory() as temp,w.Watcher() as watch:
            root=Path(temp); watch.add(root,None)
            (root/'2.2.0').write_text('binary')
            self.assertTrue(watch.changed(1))

if __name__=='__main__': unittest.main()

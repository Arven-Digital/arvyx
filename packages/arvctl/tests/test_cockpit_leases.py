import base64
import unittest
from test_cockpit import CockpitTests


class LeaseTests(CockpitTests):
    def test_takeover_rejects_old_writer_and_detach(self):
        sid = self.open()['id']
        self.service.start(sid, actor='operator', environment='host')
        first = self.service.attach(sid, actor='operator')['attachment']
        with self.assertRaisesRegex(ValueError, 'already attached'):
            self.service.attach(sid, actor='operator')
        second = self.service.attach(sid, actor='operator', takeover=True)['attachment']
        self.assertNotEqual(first, second)
        with self.assertRaisesRegex(ValueError, 'stale attachment'):
            self.service.resize(sid, rows=25, columns=80, actor='operator', attachment=first)
        for operation in ('write', 'detach'):
            with self.assertRaisesRegex(ValueError, 'stale attachment'):
                if operation == 'write':
                    self.service.write(sid, 'forbidden', actor='operator', attachment=first)
                else:
                    self.service.detach(sid, actor='operator', attachment=first)
        self.assertTrue(self.service.write(sid, 'echo valid\n', actor='operator', attachment=second)['accepted'])

    def test_binary_frames_preserve_split_utf8_and_controls(self):
        sid = self.open()['id']
        self.service.start(sid, actor='operator', environment='host')
        token = self.service.attach(sid, actor='operator')['attachment']
        with self.service.lock:
            live = self.service.live[sid]
            live['output'] = bytearray(b'\xe2\x82')
            live['offset'] = 0
            frame = self.service.read(sid, actor='operator', binary=True)
            self.assertEqual(base64.b64decode(frame['data']), b'\xe2\x82')
            live['output'].extend(b'\xac\x00\x1b')
            frame = self.service.read(sid, cursor=frame['cursor'], actor='operator', binary=True)
            self.assertEqual(base64.b64decode(frame['data']), b'\xac\x00\x1b')
        ack = self.service.write(sid, data=base64.b64encode(b'\xc3').decode('ascii'), actor='operator', attachment=token)
        self.assertEqual(ack['accepted_bytes'], 1)
        with self.assertRaises(ValueError):
            self.service.write(sid, data='not base64!', actor='operator', attachment=token)
        with self.assertRaises(ValueError):
            self.service.read(sid, actor='operator', cursor=True)
        with self.assertRaisesRegex(ValueError, 'ahead'):
            self.service.read(sid, actor='operator', cursor=10000000)


def load_tests(loader, tests, pattern):
    # Reuse the fixture without multiplying inherited baseline test counts.
    return unittest.TestSuite(LeaseTests(name) for name in LeaseTests.__dict__ if name.startswith('test_'))

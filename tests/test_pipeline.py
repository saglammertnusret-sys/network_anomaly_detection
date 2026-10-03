import csv
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import numpy as np
from network_monitor.features import Window, parse_packet, CSV_FIELDS
from network_monitor.model import train, read_windows, score, load_model, transform
from network_monitor.capture import live_windows, pcap_windows

class PipelineTests(unittest.TestCase):
    def test_ipv4_ipv6_and_window_statistics(self):
        a = parse_packet('1\t100\t10.0.0.1\t10.0.0.2\t\t\t1234\t443\t\t\t1\n')
        b = parse_packet('2\t300\t\t\t::1\t::2\t\t\t53\t5500\t\n')
        window = Window(); window.add(a); window.add(b)
        row = window.row(0, 10)
        self.assertEqual(row['bytes_per_second'], 40)
        self.assertEqual(row['mean_packet_bytes'], 200)
        self.assertEqual(row['std_packet_bytes'], 100)
        self.assertEqual(row['unique_addresses'], 4)
        self.assertEqual(row['tcp_fraction'], .5)
        self.assertEqual(row['udp_fraction'], .5)
        self.assertEqual(row['syn_fraction'], .5)
        self.assertTrue(all(v == 0 for k,v in Window().row(0,10).items() if k not in ('window_start','window_seconds')))

    def test_chronological_split_scaler_and_reload(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            subprocess.run([sys.executable, '-m','network_monitor.cli','demo-data','--output',str(d/'data')],check=True,capture_output=True)
            report = train(d/'data'/'normal.csv',d/'run')
            bundle = load_model(d/'run'/'model.joblib')
            _, matrix, _ = read_windows(d/'data'/'normal.csv')
            np.testing.assert_allclose(bundle['scaler'].mean_, transform(matrix[:216]).mean(axis=0))
            calibration = score(bundle,matrix[218:288])
            self.assertAlmostEqual(bundle['threshold'],np.quantile(calibration,.05))
            self.assertEqual(report['split']['normal_holdout'],70)
            self.assertIsNone(report['attack_detection_metrics'])
            with self.assertRaisesRegex(ValueError,'not empty'):
                train(d/'data'/'normal.csv',d/'run')

    def test_invalid_or_overlapping_windows_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'bad.csv'
            row = Window().row(0,10)
            for second in (dict(row), {**row,'window_start':10,'packets_per_second':'nan'}):
                with path.open('w',newline='') as handle:
                    writer=csv.DictWriter(handle,fieldnames=CSV_FIELDS)
                    writer.writeheader();writer.writerow(row);writer.writerow(second)
                with self.assertRaises(ValueError): read_windows(path)

    def test_contaminated_baseline_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'bad.csv'
            with path.open('w',newline='') as handle:
                writer=csv.DictWriter(handle,fieldnames=[*CSV_FIELDS,'label'])
                writer.writeheader()
                for i in range(100):writer.writerow({**Window().row(i*10,10),'label':'ATTACK' if i==80 else 'NORMAL'})
            with self.assertRaisesRegex(ValueError,'non-normal'): train(path,Path(d)/'run')

    def test_quiet_capture_closes_and_emits_idle_windows(self):
        with tempfile.TemporaryDirectory() as d:
            fake=Path(d)/'fake.py';fake.write_text('import time\nwhile True: time.sleep(.1)\n')
            with patch('network_monitor.capture.field_arguments',return_value=[sys.executable,str(fake)]):
                rows=list(live_windows('1',.1,.3))
            self.assertEqual(len(rows),3)
            self.assertTrue(all(r['packets_per_second']==0 for r in rows))

    def test_offline_parser_idle_windows_and_partial_tail(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);pcap=d/'dummy.pcap';pcap.touch()
            fake=d/'fake.py'
            lines=['0\t100\t1.1.1.1\t2.2.2.2\t\t\t1\t2\t\t\t0',
                   '25\t200\t1.1.1.1\t2.2.2.2\t\t\t1\t2\t\t\t0']
            fake.write_text('print('+repr('\n'.join(lines))+')\n')
            with patch('network_monitor.capture.field_arguments',return_value=[sys.executable,str(fake)]):
                rows=list(pcap_windows(pcap,10))
            self.assertEqual(len(rows),2)
            self.assertEqual(rows[0]['packets_per_second'],.1)
            self.assertEqual(rows[1]['packets_per_second'],0)

    def test_live_packets_cross_windows_without_hanging(self):
        with tempfile.TemporaryDirectory() as d:
            fake=Path(d)/'fake.py'
            line='1\t100\t1.1.1.1\t2.2.2.2\t\t\t1\t2\t\t\t0'
            fake.write_text('import time\ntime.sleep(.02)\nwhile True:\n print('+repr(line)+',flush=True)\n time.sleep(.02)\n')
            with patch('network_monitor.capture.field_arguments',return_value=[sys.executable,str(fake)]):
                rows=list(live_windows('1',.1,.3))
            self.assertEqual(len(rows),3)
            self.assertTrue(all(r['packets_per_second']>0 for r in rows))

    def test_capture_failure_is_not_normal_idle_traffic(self):
        with tempfile.TemporaryDirectory() as d:
            fake=Path(d)/'fake.py'
            fake.write_text('import sys\nprint("Capture permission denied",file=sys.stderr)\nsys.exit(2)\n')
            with patch('network_monitor.capture.field_arguments',return_value=[sys.executable,str(fake)]):
                with self.assertRaises(ValueError): list(live_windows('1',.2,.4))

if __name__=='__main__':unittest.main()

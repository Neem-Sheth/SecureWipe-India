#!/usr/bin/env python3
# coding: utf-8

import sys
import os
import json

# Ensure src is importable when running this script from the repository root
sys.path.insert(0, os.path.join(os.getcwd(), 'src'))

from core.engine import SecureWipeEngine


from core.engine import WipeLevel
def main():
    eng = SecureWipeEngine()
    devs = eng.detect_storage_devices()
    print('devices', len(devs))
    if devs:
        first = devs[0]
        # write a deliberately mismatched lock to ensure the engine refuses the wipe
        lock = {
            'path': 'Z:\\',
            'physical_device': '\\\\.\\PhysicalDrive999',
            'created_by': 'test',
            'created_at': 0
        }
        os.makedirs('config', exist_ok=True)
        with open('config/lock.json', 'w', encoding='utf-8') as f:
            json.dump(lock, f)
        res = eng.wipe_device(first['path'], WipeLevel.CLEAR)
        print('wipe attempted, success=', getattr(res, 'success', None), 'error=', getattr(res, 'error_message', None))
    else:
        print('no devices')


if __name__ == '__main__':
    main()

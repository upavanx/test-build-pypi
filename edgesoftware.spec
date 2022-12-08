# -*- mode: python ; coding: utf-8 -*-

block_cipher = None
import os

a = Analysis(['edgesoftware/edgesoftware.py'],
             pathex=[os.getcwd()],
             binaries=[],
             datas=[('lanternrocksdk-linux-3.0.90/python/lanternrock/linux/libintel-ias3.so', 'lanternrock/linux')],
             hiddenimports=['pkg_resources.py2_warn', 'termcolor', 'click', 'colorama',
                 'esb_common', 'esb_common.logger', 'esb_common.locale', 'psutil',
                 'wget', 'lsb_release', 'filecmp', 'esb_common.util', 'inputimeout',
                 'urllib3.exceptions', 'json', 'platform', 'pathlib', 'scp',
                 'paramiko', 'ruamel.yaml', 'multiprocessing', 'pexpect', 'inquirer'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='edgesoftware',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True )

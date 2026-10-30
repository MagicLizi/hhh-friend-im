#!/usr/bin/env python3
"""用现有服务器源码和指定 SDK，在仓库外运行群成员名片端到端测试。"""
import argparse
import io
from pathlib import Path
import re
import subprocess
import tarfile
import shutil

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--server', type=Path, required=True)
parser.add_argument('--server-ref', default='HEAD')
parser.add_argument('--server-working-tree', action='store_true', help='测试尚未提交的服务器源码，必须使用新的输出目录')
parser.add_argument('--sdk', type=Path, required=True, help='hhh-im-protocol 源码目录')
parser.add_argument('--desktop-host', type=Path, help='仅准备双桌面测试后端，传 HHH 源码目录；不使用真实账号')
parser.add_argument('--out', type=Path, required=True, help='仓库外的独立测试目录')
args = parser.parse_args()
plugin = Path(__file__).resolve().parents[1]
out, sdk, server = args.out.resolve(), args.sdk.resolve(), args.server.resolve()
if any(out.is_relative_to(repo) or repo.is_relative_to(out) for repo in (plugin, sdk, server)):
    parser.error('测试目录不能与插件、SDK 或服务器源码互相包含')
if not (sdk / 'src/contacts.rs').is_file():
    parser.error('SDK 必须包含成员名片协议')
server_copy = out / 'server-source'
if args.server_working_tree:
    if server_copy.exists(): parser.error('测试未提交源码时请使用新的输出目录，避免混入旧文件')
    server_copy.mkdir(parents=True)
    for directory in ('src', 'tests', 'plugin-e2e'):
        shutil.copytree(server/directory, server_copy/directory, ignore=shutil.ignore_patterns('target','.git','.tmp'))
    for name in ('Cargo.toml','Cargo.lock'):
        shutil.copy2(server/name,server_copy/name)
else:
    archive = subprocess.check_output(['git', 'archive', args.server_ref], cwd=server)
    with tarfile.open(fileobj=io.BytesIO(archive)) as files:
        files.extractall(server_copy, filter='data')
manifest = (server_copy / 'Cargo.toml').read_text(encoding='utf8')
for name in ('core', 'client'):
    manifest = manifest.replace(f'path = "../hhh-friend-im/{name}"', f'path = "{(plugin/name).as_posix()}"')
(server_copy / 'Cargo.toml').write_text(manifest, encoding='utf8', newline='')
harness = out / 'harness'
(harness / 'tests').mkdir(parents=True, exist_ok=True)
manifest = (server_copy / 'plugin-e2e/Cargo.toml').read_text(encoding='utf8')
for old, new in (('..', server_copy), ('../../hhh-friend-im', plugin), ('../../hhh-friend-im/client', plugin/'client')):
    manifest = manifest.replace(f'path = "{old}"', f'path = "{new.as_posix()}"')
manifest = re.sub(r'hhh-im-protocol = \{ git = [^\n]+', f'hhh-im-protocol = {{ path = "{sdk.as_posix()}" }}', manifest)
manifest += f'\n[patch."https://github.com/MagicLizi/hhh-im-sdk"]\nhhh-im-protocol = {{ path = "{sdk.as_posix()}" }}\n'
if args.desktop_host:
    host = args.desktop_host.resolve()
    credential = host / 'hhh-host/src/credential_store.rs'
    if not credential.is_file(): parser.error('HHH 目录缺少隔离凭据入口')
    extra = '\nkeyring = { version = "4", features = ["v1", "windows-native-keyring-store"] }\nwindows-sys = { version = "0.61", features = ["Win32_Foundation", "Win32_Security", "Win32_System_Threading"] }\nserde = { version = "1", features = ["derive"] }\ntracing = "0.1"\n'
    manifest = manifest.replace('[dev-dependencies]', '[dev-dependencies]' + extra)
(harness / 'Cargo.toml').write_text(manifest, encoding='utf8', newline='')
header = f'#[path = "{(server_copy/"tests/common/mod.rs").as_posix()}"] mod common;\n'
header += f'#[path = "{(server_copy/"plugin-e2e/tests/host/mod.rs").as_posix()}"] mod host;\n'
(harness/'tests/group_contacts.rs').write_text(header+(plugin/'tests/scenarios/group_contacts.rs').read_text(encoding='utf8'), encoding='utf8', newline='')
if args.desktop_host:
    (harness/'examples').mkdir(exist_ok=True)
    header = f'#![allow(dead_code, unexpected_cfgs)]\n#[path = "{(server_copy/"tests/common/mod.rs").as_posix()}"] mod common;\n'
    header += f'#[path = "{credential.as_posix()}"] mod credential_store;\n'
    (harness/'examples/approval-desktop.rs').write_text(header+(plugin/'tests/scenarios/desktop_approval.rs').read_text(encoding='utf8'),encoding='utf8',newline='')
    subprocess.run(['cargo','build','--manifest-path',str(harness/'Cargo.toml'),'--example','approval-desktop'],check=True)
else:
    subprocess.run(['cargo', 'test', '--manifest-path', str(harness/'Cargo.toml'), '--test', 'group_contacts', '--', '--nocapture'], check=True)

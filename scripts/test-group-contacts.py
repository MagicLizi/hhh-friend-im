#!/usr/bin/env python3
"""用现有服务器源码和指定 SDK，在仓库外运行群成员名片端到端测试。"""
import argparse
import io
from pathlib import Path
import re
import subprocess
import tarfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--server', type=Path, required=True)
parser.add_argument('--server-ref', default='HEAD')
parser.add_argument('--sdk', type=Path, required=True, help='hhh-im-protocol 源码目录')
parser.add_argument('--out', type=Path, required=True, help='仓库外的独立测试目录')
args = parser.parse_args()
plugin = Path(__file__).resolve().parents[1]
out, sdk, server = args.out.resolve(), args.sdk.resolve(), args.server.resolve()
if any(out.is_relative_to(repo) or repo.is_relative_to(out) for repo in (plugin, sdk, server)):
    parser.error('测试目录不能与插件、SDK 或服务器源码互相包含')
if not (sdk / 'src/contacts.rs').is_file():
    parser.error('SDK 必须包含成员名片协议')
server_copy = out / 'server-source'
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
(harness / 'Cargo.toml').write_text(manifest, encoding='utf8', newline='')
header = f'#[path = "{(server_copy/"tests/common/mod.rs").as_posix()}"] mod common;\n'
header += f'#[path = "{(server_copy/"plugin-e2e/tests/host/mod.rs").as_posix()}"] mod host;\n'
(harness/'tests/group_contacts.rs').write_text(header+(plugin/'tests/scenarios/group_contacts.rs').read_text(encoding='utf8'), encoding='utf8', newline='')
subprocess.run(['cargo', 'test', '--manifest-path', str(harness/'Cargo.toml'), '--test', 'group_contacts', '--', '--nocapture'], check=True)

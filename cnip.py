#!/usr/bin/env python3
"""cnip — 1Panel OpenResty mainland-China IP access policy manager.

Python 3.8+, standard library only. Intended to run as root on Linux.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set, Tuple

VERSION = '1.0.1'
CONF_DEST = '/usr/local/openresty/nginx/conf/conf.d'
NGINX = '/usr/local/openresty/nginx/sbin/nginx'
GLOBAL_FILENAME = '00-cnip-managed.conf'
GLOBAL_HEADER = '# Managed by cnip v1; do not edit manually.'
GUARD_HEADER = '# Managed by cnip v1; included only in selected server blocks.'
GEO_HEADER = '# cnip mainland-China IP database (IPdeny)'
MAP_HEADER = '# Managed by cnip v1; exact host matches'
EXTRA_HEADER = '# Managed by cnip v1; user-allowed CIDRs'
GUARD_LINE = '    include /www/.cnip/guard.conf; # CNIP-MANAGED'
GUARD_PATH = '/www/.cnip/guard.conf'
OLD_GUARDS = ('/www/cn-allow.conf', '/www/.cn-only-v2/guard.conf')
URLS = {
    4: 'https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone',
    6: 'https://www.ipdeny.com/ipv6/ipaddresses/aggregated/cn-aggregated.zone',
}
BACKUPS = Path('/var/backups/cnip')
LOCK = Path('/run/lock/cnip.lock')
SYSTEMD_SERVICE = Path('/etc/systemd/system/cnip-update.service')
SYSTEMD_TIMER = Path('/etc/systemd/system/cnip-update.timer')


class CnipError(Exception):
    pass


def execute(args: Sequence[str], check: bool = True, timeout: float = 30) -> subprocess.CompletedProcess:
    try:
        p = subprocess.run(args, capture_output=True, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise CnipError(f'命令在 {timeout:g} 秒内未完成，已停止等待：{" ".join(args)}。请检查 Docker / OpenResty / 网络连接后重试。') from e
    except FileNotFoundError as e:
        raise CnipError(f'找不到命令：{args[0]}') from e
    if check and p.returncode:
        raise CnipError(f'命令失败：{" ".join(args)}\n{(p.stderr or p.stdout).strip()}')
    return p


def domain_name(name: str) -> str:
    name = name.lower().strip().rstrip('.')
    if len(name) > 253 or not re.fullmatch(
        r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+',
        name,
    ):
        raise CnipError('域名无效。请输入完整域名，例如 example.com（不带 https://）。')
    return name


def cidr_value(raw: str) -> str:
    try:
        net = ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError as e:
        raise CnipError(f'IP / CIDR 格式无效：{raw}') from e
    if net.prefixlen == 0:
        raise CnipError('禁止放行全部互联网地址（/0）。')
    return str(net)


@dataclass
class Environment:
    container: str
    webroot: Path
    confdir: Path

    @property
    def storage(self) -> Path:
        return self.webroot / '.cnip'

    @property
    def statefile(self) -> Path:
        return self.storage / 'state.json'

    @property
    def globalconf(self) -> Path:
        return self.confdir / GLOBAL_FILENAME

    def nginx(self, *args: str) -> subprocess.CompletedProcess:
        return execute(['docker', 'exec', self.container, NGINX, *args])


def find_environments() -> List[Environment]:
    # List metadata first: unrelated containers must not require individual inspect calls.
    listing = execute(['docker', 'ps', '--format', '{{.ID}}\t{{.Image}}\t{{.Names}}'], timeout=15).stdout
    selected = os.environ.get('CNIP_CONTAINER', '').strip()
    ids = []
    for row in listing.splitlines():
        fields = row.split('\t')
        if len(fields) != 3:
            raise CnipError('Docker 容器列表格式异常，请检查 docker ps 是否正常。')
        cid, image, name = fields
        if (selected and name == selected) or (not selected and 'openresty' in (image + ' ' + name).lower()):
            ids.append(cid)
    if not ids:
        return []
    objects = json.loads(execute(['docker', 'inspect', *ids], timeout=15).stdout)
    environments: List[Environment] = []
    for obj in objects:
        name = obj.get('Name', '').lstrip('/')
        mounts = {m['Destination'].rstrip('/'): m['Source'] for m in obj.get('Mounts', [])
                  if m.get('Type') == 'bind' and m.get('Source')}
        if '/www' in mounts and CONF_DEST in mounts:
            env = Environment(name, Path(mounts['/www']), Path(mounts[CONF_DEST]))
            if env.webroot.is_dir() and env.confdir.is_dir():
                environments.append(env)
    return environments


def environment() -> Environment:
    candidates = find_environments()
    selected = os.environ.get('CNIP_CONTAINER', '').strip()
    if selected:
        candidates = [e for e in candidates if e.container == selected]
    if not candidates:
        raise CnipError('未找到符合条件的 1Panel OpenResty 容器（需要 /www 和 conf.d 的绑定挂载）。')
    if len(candidates) != 1:
        raise CnipError('发现多个 OpenResty 容器：' + ', '.join(e.container for e in candidates) +
                        '。请设置 CNIP_CONTAINER=容器名 再执行 cnip。')
    return candidates[0]


def initial_state() -> dict:
    return {'owner': 'cnip', 'schema': 1, 'domains': [], 'extra_allow': [],
            'acme_exempt': True, 'ip_updated_at': None, 'ipv4_count': 0, 'ipv6_count': 0}


def load_state(env: Environment) -> dict:
    if not env.statefile.exists():
        return initial_state()
    try:
        state = json.loads(env.statefile.read_text(encoding='utf-8'))
        if state['owner'] != 'cnip' or state['schema'] != 1:
            raise ValueError('unknown schema')
        state['domains'] = sorted(set(domain_name(x) for x in state['domains']))
        state['extra_allow'] = sorted(set(cidr_value(x) for x in state['extra_allow']))
        if not isinstance(state['acme_exempt'], bool):
            raise ValueError('bad acme_exempt')
        return state
    except (ValueError, KeyError, TypeError) as e:
        raise CnipError('现有状态文件损坏或版本不兼容，请勿覆盖：' + str(env.statefile)) from e


def require_owned(path: Path, header: str) -> None:
    if path.is_symlink():
        raise CnipError(f'拒绝覆盖符号链接：{path}')
    if path.exists() and not path.read_text(encoding='utf-8').startswith(header):
        raise CnipError(f'发现非 cnip 管理的同名文件，拒绝覆盖：{path}')


def owned_files(env: Environment) -> Dict[Path, str]:
    return {
        env.globalconf: GLOBAL_HEADER,
        env.storage / 'guard.conf': GUARD_HEADER,
        env.storage / 'china.geo': GEO_HEADER,
        env.storage / 'extra.geo': EXTRA_HEADER,
        env.storage / 'domains.map': MAP_HEADER,
    }


def put_file(path: Path, data: str) -> None:
    if path.is_symlink():
        raise CnipError(f'拒绝覆盖符号链接：{path}')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.cnip-', dir=str(path.parent))
    try:
        if path.exists():
            stat = path.stat()
            os.fchmod(fd, stat.st_mode & 0o777)
            os.fchown(fd, stat.st_uid, stat.st_gid)
        else:
            os.fchmod(fd, 0o644)
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def tokenize(text: str) -> List[Tuple[str, int, int]]:
    """Nginx lexer: comments and quotes do not introduce block braces."""
    toks = []
    i, n = 0, len(text)
    while i < n:
        if text[i].isspace():
            i += 1
            continue
        if text[i] == '#':
            j = text.find('\n', i)
            i = n if j == -1 else j + 1
            continue
        if text[i] in '{};':
            toks.append((text[i], i, i + 1))
            i += 1
            continue
        start = i
        quoted = ''
        while i < n:
            ch = text[i]
            if quoted:
                if ch == '\\' and i + 1 < n:
                    i += 2
                    continue
                if ch == quoted:
                    quoted = ''
                i += 1
                continue
            if ch in "\"'":
                quoted = ch
                i += 1
                continue
            if ch == '\\' and i + 1 < n:
                i += 2
                continue
            if ch.isspace() or ch in '#{};':
                break
            i += 1
        if i == start:
            i += 1
        toks.append((text[start:i], start, i))
    return toks


def server_blocks(text: str) -> List[Tuple[int, int, Set[str]]]:
    tokens = tokenize(text)
    blocks = []
    for i, (value, _, _) in enumerate(tokens):
        if value != 'server' or i + 1 >= len(tokens) or tokens[i + 1][0] != '{':
            continue
        opener = i + 1
        nesting, j = 1, opener + 1
        names: Set[str] = set()
        directive_depth = 1
        while j < len(tokens) and nesting:
            tok = tokens[j][0]
            if tok == '{':
                nesting += 1
            elif tok == '}':
                nesting -= 1
                j += 1
                continue
            if nesting == directive_depth and tok == 'server_name':
                k = j + 1
                while k < len(tokens) and tokens[k][0] != ';':
                    if tokens[k][0] in '{}':
                        break
                    names.add(tokens[k][0].strip('"\'').lower().rstrip('.'))
                    k += 1
            j += 1
        if nesting != 0:
            raise CnipError('网站配置的 server 大括号未闭合。')
        blocks.append((tokens[opener][2], tokens[j - 1][1], names))
    return blocks


def updates_for_domains(env: Environment, selected: Set[str], required: Optional[str] = None) -> Dict[Path, str]:
    updates: Dict[Path, str] = {}
    found = False
    for path in sorted(env.confdir.glob('*.conf')):
        if path == env.globalconf or path.is_symlink():
            continue
        content = path.read_text(encoding='utf-8')
        changes: List[Tuple[int, int, str]] = []
        for start, end, names in server_blocks(content):
            if required and required in names:
                found = True
            block = content[start:end]
            must_guard = bool(names & selected)
            existing_marked = re.search(r'(?m)^[ \t]*include[ \t]+/www/\.cnip/guard\.conf;[ \t]*#[ \t]*CNIP-MANAGED[ \t]*\r?\n?', block)
            if must_guard:
                for legacy in OLD_GUARDS:
                    if re.search(r'\binclude\s+' + re.escape(legacy) + r'\s*;', block):
                        raise CnipError(f'{path} 存在旧版限制规则 {legacy}。请先迁移旧规则再启用。')
                if not existing_marked:
                    if re.search(r'\binclude\s+' + re.escape(GUARD_PATH) + r'\s*;', block):
                        raise CnipError(f'{path} 存在未标记的 cnip include，拒绝重复修改。')
                    changes.append((start, start, '\n' + GUARD_LINE + '\n'))
            elif existing_marked:
                changes.append((start + existing_marked.start(), start + existing_marked.end(), ''))
        for a, b, replacement in sorted(changes, reverse=True):
            content = content[:a] + replacement + content[b:]
        if changes:
            updates[path] = content
    if required and not found:
        raise CnipError(f'未在 {env.confdir} 的网站 server_name 中找到 {required}。请先在 1Panel 创建该域名。')
    return updates


def download_database(quiet: bool = False) -> Tuple[str, int, int]:
    rows: List[str] = []
    counts = {}
    with tempfile.TemporaryDirectory(prefix='cnip-download-') as tmp:
        for version in (4, 6):
            url = os.environ.get(f'CNIP_IPV{version}_URL', URLS[version])
            path = Path(tmp) / f'ipv{version}.txt'
            if not quiet:
                print(f'正在下载 IPv{version} 中国 IP 库（最多等待 110 秒，可按 Ctrl+C 取消）……', flush=True)
            execute(['curl', '-fL', '-sS', '--retry', '1', '--retry-delay', '1',
                     '--connect-timeout', '10', '--max-time', '45', '--max-redirs', '5',
                     '--proto', '=https', '--proto-redir', '=https', '--tlsv1.2',
                     url, '-o', str(path)], timeout=110)
            if path.stat().st_size < 1024 or path.stat().st_size > 8 * 1024 * 1024:
                raise CnipError(f'IPv{version} 数据文件大小异常，停止启用。')
            networks = set()
            for line in path.read_text(encoding='utf-8').splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=True)
                except ValueError as e:
                    raise CnipError(f'IPv{version} 数据格式异常：{line}') from e
                if net.version != version or net.prefixlen == 0:
                    raise CnipError(f'IPv{version} 数据混杂/过宽：{line}')
                networks.add(net)
            if len(networks) < 100:
                raise CnipError(f'IPv{version} 仅获得 {len(networks)} 条地址段，拒绝部署。')
            counts[version] = len(networks)
            rows.extend(f'{net} 1;' for net in sorted(networks, key=lambda x: (int(x.network_address), x.prefixlen)))
            if not quiet:
                print(f'  IPv{version}：已验证 {counts[version]} 条地址段', flush=True)
    return GEO_HEADER + '\n127.0.0.1 1;\n::1 1;\n' + '\n'.join(rows) + '\n', counts[4], counts[6]


def generate_configs(state: dict) -> Dict[str, str]:
    acme = '    ~^/\\.well-known/acme-challenge/ 1;\n' if state['acme_exempt'] else ''
    global_conf = (GLOBAL_HEADER + '\n'
        'geo $cnip_v1_ip_ok {\n    default 0;\n'
        '    include /www/.cnip/china.geo;\n    include /www/.cnip/extra.geo;\n}\n'
        'map $uri $cnip_v1_acme_ok {\n    default 0;\n' + acme + '}\n'
        'map "$host:$cnip_v1_ip_ok:$cnip_v1_acme_ok" $cnip_v1_deny {\n'
        '    default 0;\n    include /www/.cnip/domains.map;\n}\n')
    return {
        'global': global_conf,
        'guard': GUARD_HEADER + '\nif ($cnip_v1_deny) { return 403; }\n',
        'extra': EXTRA_HEADER + '\n' + ''.join(f'{p} 1;\n' for p in state['extra_allow']),
        'map': MAP_HEADER + '\n' + ''.join(f'"{d}:0:0" 1;\n' for d in state['domains']),
        'state': json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + '\n',
    }


def backup_snapshot(paths: Sequence[Path], action: str) -> Path:
    BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    folder = BACKUPS / f'{stamp}-{action}'
    folder.mkdir(mode=0o700)
    entries = []
    for path in sorted(set(paths)):
        if path.is_symlink():
            raise CnipError(f'目标文件为符号链接，禁止修改：{path}')
        existed = path.is_file()
        if existed:
            to = folder / 'originals' / path.relative_to('/')
            to.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copy2(path, to)
        entries.append({'path': str(path), 'existed': existed})
    (folder / 'manifest.json').write_text(json.dumps({'version': 1, 'action': action,
        'timestamp': dt.datetime.now(dt.timezone.utc).isoformat(), 'files': entries}, indent=2), encoding='utf-8')
    return folder


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
        return True
    except ValueError:
        return False


def restore_snapshot(folder: Path, env: Environment) -> None:
    manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8'))
    if manifest.get('version') != 1:
        raise CnipError('备份版本不匹配。')
    allowed = [env.webroot.resolve(), env.confdir.resolve()]
    for row in manifest['files']:
        path = Path(row['path'])
        if not path.is_absolute() or not any(_within(path, root) for root in allowed):
            raise CnipError('备份清单包含不允许恢复的路径：' + str(path))
        original = folder / 'originals' / path.relative_to('/')
        if row['existed'] and not original.is_file():
            raise CnipError('备份文件丢失：' + str(original))
    for row in manifest['files']:
        path = Path(row['path'])
        if row['existed']:
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(folder / 'originals' / path.relative_to('/'), path)
        else:
            path.unlink(missing_ok=True)


def nginx_verify(env: Environment, require_global: bool) -> None:
    env.nginx('-t')
    if require_global:
        dump = env.nginx('-T').stdout
        expected = f'# configuration file {CONF_DEST}/{GLOBAL_FILENAME}:'
        if expected not in dump:
            raise CnipError('全局 cnip 配置未被 Nginx http 上下文加载，不能确保限制生效。')


def transact(env: Environment, new_state: dict, action: str,
             new_geo: Optional[str] = None, delete_all: bool = False,
             required: Optional[str] = None) -> Path:
    if env.storage.is_symlink():
        raise CnipError('cnip 数据目录不允许是符号链接。')
    env.storage.mkdir(mode=0o755, parents=True, exist_ok=True)
    stat = env.storage.stat()
    if stat.st_uid != os.geteuid() or stat.st_mode & 0o022:
        raise CnipError('cnip 数据目录必须由 root 拥有，且不能允许组或其他用户写入。')
    for path, header in owned_files(env).items():
        require_owned(path, header)
    if env.statefile.is_symlink():
        raise CnipError('状态文件不允许是符号链接。')
    print('正在检查现有 OpenResty 配置……', flush=True)
    env.nginx('-t')
    configs = generate_configs(new_state)
    selected = set(new_state['domains'])
    modifications = updates_for_domains(env, selected, required=required)
    planned: Dict[Path, Optional[str]] = dict(modifications)
    paths = owned_files(env)
    if delete_all:
        for path in paths:
            planned[path] = None
        planned[env.statefile] = None
    else:
        if new_geo is None and not (env.storage / 'china.geo').exists():
            raise CnipError('尚未下载 IP 库，请先执行 add 或 update。')
        planned[env.globalconf] = configs['global'] if selected else None
        planned[env.storage / 'guard.conf'] = configs['guard']
        planned[env.storage / 'extra.geo'] = configs['extra']
        planned[env.storage / 'domains.map'] = configs['map']
        planned[env.statefile] = configs['state']
        if new_geo is not None:
            planned[env.storage / 'china.geo'] = new_geo
    folder = backup_snapshot(list(planned), action)
    print(f'已备份：{folder}，正在写入并验证配置……', flush=True)
    try:
        for path, value in planned.items():
            if value is None:
                path.unlink(missing_ok=True)
            else:
                put_file(path, value)
        nginx_verify(env, bool(selected))
        print('配置检查通过，正在重载 OpenResty……', flush=True)
        env.nginx('-s', 'reload')
    except (Exception, KeyboardInterrupt):
        print('⚠️ 应用失败，正在恢复修改前配置……', file=sys.stderr)
        restore_snapshot(folder, env)
        try:
            env.nginx('-t')
            env.nginx('-s', 'reload')
            print('已恢复修改前的配置。', file=sys.stderr)
        except Exception as e:
            print(f'⚠️ 恢复后仍需人工检查：{e}', file=sys.stderr)
        raise
    return folder


def do_add(env: Environment, name: str, quiet: bool = False) -> None:
    name = domain_name(name)
    state = load_state(env)
    if name in state['domains']:
        print(f'{name} 已受保护。可运行 cnip doctor 检查配置，或 cnip repair 修复规则。')
        return
    # Check target before downloading data.
    updates_for_domains(env, set(state['domains']) | {name}, required=name)
    geo = None
    if not (env.storage / 'china.geo').exists():
        geo, state['ipv4_count'], state['ipv6_count'] = download_database(quiet)
        state['ip_updated_at'] = dt.datetime.now(dt.timezone.utc).isoformat()
    state['domains'] = sorted(set(state['domains']) | {name})
    backup = transact(env, state, 'add', geo, required=name)
    print(f'✅ 已为 {name} 启用仅中国大陆 IP 访问，备份：{backup}')


def do_remove(env: Environment, name: str) -> None:
    name = domain_name(name)
    state = load_state(env)
    if name not in state['domains']:
        print(f'{name} 没有启用 cnip 限制。')
        return
    state['domains'].remove(name)
    backup = transact(env, state, 'remove')
    print(f'✅ 已取消 {name} 的 cnip 限制，备份：{backup}')


def do_update(env: Environment, quiet: bool = False) -> None:
    state = load_state(env)
    if not state['domains']:
        if quiet:
            return
        print('尚未启用域名限制：本次只初始化 IP 库，不会开启任何域名限制。', flush=True)
    geo, state['ipv4_count'], state['ipv6_count'] = download_database(quiet)
    state['ip_updated_at'] = dt.datetime.now(dt.timezone.utc).isoformat()
    backup = transact(env, state, 'update', geo)
    if not quiet:
        print(f'✅ IP 库已更新并重载 OpenResty，备份：{backup}')


def do_allow(env: Environment, action: str, value: str) -> None:
    value = cidr_value(value)
    state = load_state(env)
    if not state['domains']:
        raise CnipError('请先给一个域名启用限制，再管理自定义 IP 放行。')
    allowed = set(state['extra_allow'])
    if action == 'add':
        if value in allowed:
            print(f'{value} 已在自定义放行列表中，无需重复添加。')
            return
        allowed.add(value)
    else:
        if value not in allowed:
            print(f'{value} 不在自定义放行列表中，无需删除。')
            return
        allowed.remove(value)
    state['extra_allow'] = sorted(allowed)
    folder = transact(env, state, 'allow-' + action)
    print(f'✅ 已{ "放行" if action == "add" else "删除放行" } {value}，备份：{folder}')


def do_acme(env: Environment, enabled: bool) -> None:
    state = load_state(env)
    if not state['domains']:
        raise CnipError('还没有受保护的域名。')
    state['acme_exempt'] = enabled
    folder = transact(env, state, 'acme')
    print(f'✅ ACME HTTP-01 验证路径例外：{ "已开启" if enabled else "已关闭" }，备份：{folder}')


def do_repair(env: Environment) -> None:
    state = load_state(env)
    if not state['domains']:
        raise CnipError('无受保护域名。')
    for name in state['domains']:
        updates_for_domains(env, set(state['domains']), required=name)
    folder = transact(env, state, 'repair')
    print(f'✅ 已重新同步配置，备份：{folder}')


def do_list(env: Environment) -> None:
    state = load_state(env)
    print('OpenResty：', env.container)
    print('宿主机网站目录：', env.webroot)
    print('Nginx 配置目录：', env.confdir)
    print('受保护域名（仅允许中国大陆 IP）：')
    for domain in state['domains']:
        print('  •', domain)
    if not state['domains']:
        print('  （无）')
    print(f'IP 地址库：IPv4 {state["ipv4_count"]} 段 / IPv6 {state["ipv6_count"]} 段')
    print('最近更新：', state['ip_updated_at'] or '尚未更新')
    print('额外放行 IP：', ', '.join(state['extra_allow']) or '（无）')
    print('ACME HTTP-01 验证路径例外：', '开' if state['acme_exempt'] else '关')


def do_doctor(env: Environment) -> None:
    state = load_state(env)
    print(f'cnip {VERSION} | 容器：{env.container}')
    print('挂载：', env.webroot, '-> /www')
    print('网站配置：', env.confdir, '->', CONF_DEST)
    print('Nginx 配置检查中……')
    nginx_verify(env, bool(state['domains']))
    print('✅ Nginx -t 成功，全局 cnip 配置加载正常。' if state['domains'] else '✅ Nginx -t 成功。')
    for name in state['domains']:
        updates = updates_for_domains(env, set(state['domains']), required=name)
        if updates:
            print(f'⚠️ {name} 的部分 server 缺失 cnip 标记，请运行 cnip repair。')
        else:
            print(f'✅ {name} 的 server 标记完整。')
    if state['ip_updated_at']:
        try:
            last = dt.datetime.fromisoformat(state['ip_updated_at'])
            if (dt.datetime.now(dt.timezone.utc) - last).days > 30:
                print('⚠️ IP 库超过 30 天未更新。')
        except ValueError:
            print('⚠️ IP 更新时间格式异常。')
    if not state['acme_exempt']:
        print('⚠️ 已关闭 ACME 路径例外，HTTP-01 续期可能失败。')
    print('注意：这里只检查配置，不能代替从境外/境内网络实际访问测试。')


def backup_dirs() -> List[Path]:
    return sorted((x for x in BACKUPS.glob('*') if x.is_dir() and (x / 'manifest.json').is_file()), reverse=True) if BACKUPS.is_dir() else []


def do_backups() -> None:
    dirs = backup_dirs()
    print('最近 20 份配置备份：')
    for path in dirs[:20]:
        print('  ', path.name)
    if not dirs:
        print('  （无）')
    print('目录：', BACKUPS)


def do_restore(env: Environment, name: str) -> None:
    if Path(name).name != name or not re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9]{6}-[a-z0-9-]+', name):
        raise CnipError('备份名称不合法。使用 cnip backups 查看。')
    folder = BACKUPS / name
    if not (folder / 'manifest.json').is_file():
        raise CnipError('找不到此备份：' + name)
    manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8'))
    roots = [env.webroot.resolve(), env.confdir.resolve()]
    paths = [Path(x['path']) for x in manifest['files']]
    if manifest.get('version') != 1 or any(
        not path.is_absolute() or not any(_within(path, root) for root in roots) for path in paths
    ):
        raise CnipError('备份清单包含非本站目录下的路径，已拒绝恢复。')
    rollback = backup_snapshot(paths, 'pre-restore')
    try:
        restore_snapshot(folder, env)
        state = load_state(env)
        nginx_verify(env, bool(state['domains']))
        env.nginx('-s', 'reload')
    except (Exception, KeyboardInterrupt):
        restore_snapshot(rollback, env)
        with contextlib.suppress(Exception):
            env.nginx('-t')
            env.nginx('-s', 'reload')
        raise
    print(f'✅ 已恢复 {name}，如需撤销本次恢复：cnip restore {rollback.name}')


def systemd_action(action: str) -> None:
    if action == 'status':
        if not Path('/run/systemd/system').is_dir():
            print('当前环境未运行 systemd，自动更新定时器不可用。')
            return
        p = execute(['systemctl', 'is-enabled', 'cnip-update.timer'], check=False)
        print('定时更新：' + ('已启用' if p.returncode == 0 else '未启用'))
        running = execute(['systemctl', 'is-active', 'cnip-update.timer'], check=False)
        print('定时器运行状态：' + ('运行中' if running.returncode == 0 else '未运行，请检查 systemctl status cnip-update.timer'))
        return
    if action == 'enable':
        if not Path('/run/systemd/system').is_dir():
            raise CnipError('本服务器未使用 systemd，无法设置自动更新定时器。')
        if not Path('/usr/local/bin/cnip').exists():
            raise CnipError('请先使用 install.sh 安装 cnip 到 /usr/local/bin/cnip。')
        selected = environment().container
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', selected):
            raise CnipError('容器名不合法。')
        service = ('[Unit]\nDescription=Update cnip mainland China IP ranges\n'
                   '[Service]\nType=oneshot\n'
                   f'Environment=CNIP_CONTAINER={selected}\n'
                   'ExecStart=/usr/local/bin/cnip update --quiet\n')
        timer = ('[Unit]\nDescription=Daily cnip geo database update\n'
                 '[Timer]\nOnCalendar=daily\nPersistent=true\nRandomizedDelaySec=1h\n'
                 '[Install]\nWantedBy=timers.target\n')
        for path in (SYSTEMD_SERVICE, SYSTEMD_TIMER):
            if path.is_symlink():
                raise CnipError(f'拒绝修改符号链接：{path}')
            if path.exists() and not path.read_text().startswith('[Unit]\nDescription=' + ('Update cnip' if path == SYSTEMD_SERVICE else 'Daily cnip')):
                raise CnipError(f'{path} 存在非 cnip 管理文件，拒绝覆盖。')
        put_file(SYSTEMD_SERVICE, service)
        put_file(SYSTEMD_TIMER, timer)
        execute(['systemctl', 'daemon-reload'])
        execute(['systemctl', 'enable', '--now', 'cnip-update.timer'])
        print('✅ 已设置每日自动更新（systemd timer，随机延迟最多一小时）。')
    else:
        for path in (SYSTEMD_SERVICE, SYSTEMD_TIMER):
            if path.is_symlink():
                raise CnipError(f'拒绝删除符号链接：{path}')
            if path.exists():
                header = '[Unit]\nDescription=' + ('Update cnip' if path == SYSTEMD_SERVICE else 'Daily cnip')
                if not path.read_text().startswith(header):
                    raise CnipError(f'{path} 不是 cnip 的服务文件，拒绝删除。')
        if Path('/run/systemd/system').is_dir() and SYSTEMD_TIMER.exists():
            execute(['systemctl', 'disable', '--now', 'cnip-update.timer'])
        for path in (SYSTEMD_SERVICE, SYSTEMD_TIMER):
            if path.exists():
                path.unlink()
        if Path('/run/systemd/system').is_dir():
            execute(['systemctl', 'daemon-reload'])
        print('✅ 已关闭自动更新。')


def do_uninstall(env: Environment) -> None:
    state = load_state(env)
    state['domains'] = []
    backup = transact(env, state, 'uninstall', delete_all=True)
    systemd_action('disable')
    binary = Path('/usr/local/bin/cnip')
    if binary.is_file() and not binary.is_symlink():
        if 'cnip — 1Panel OpenResty mainland-China IP access policy manager' not in binary.read_text(encoding='utf-8'):
            print('⚠️ /usr/local/bin/cnip 不是本项目脚本，已保留。')
        else:
            binary.unlink()
    print(f'✅ 已取消 cnip 管理的所有限制并卸载命令。备份仍保留：{backup}')
    print('注意：不会删除旧版本脚本的规则、其他第三方防火墙或独立安全组规则。')


@contextlib.contextmanager
def operation_lock():
    """Lock one operation; an idle menu must not block timers or other terminals."""
    with open(LOCK, 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise CnipError('另一个 cnip 操作正在执行，请稍后重试；不会在后台无限等待。') from e
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def yn(question: str, default: bool = False) -> bool:
    while True:
        answer = input(question + (' [Y/n]：' if default else ' [y/N]：')).strip().lower()
        if not answer:
            return default
        if answer in ('y', 'yes', '是', '1'):
            return True
        if answer in ('n', 'no', '否', '0'):
            return False
        print('请输入 y / n（也可输入 是 / 否 或 1 / 0）。', flush=True)


def wait_for_menu() -> None:
    while input('\n按回车返回主菜单（Enter），Ctrl+C 退出：').strip():
        print('请直接按 Enter 返回主菜单，或按 Ctrl+C 退出。', flush=True)


def menu() -> None:
    print('提示：所有输入处均可按 Ctrl+C 退出工具。', flush=True)
    try:
        menu_loop()
    except EOFError:
        print('\n输入已结束。')


def menu_loop() -> None:
    while True:
        print('\n' + '═' * 47)
        print('  cnip · 1Panel 中国大陆 IP 访问管理  v' + VERSION)
        print('═' * 47)
        print('  1. 为指定域名开启中国 IP 限制')
        print('  2. 取消指定域名限制')
        print('  3. 查看域名 / IP 库状态')
        print('  4. 手动更新中国 IP 地址库')
        print('  5. 新增境外 IP / 网段放行')
        print('  6. 删除自定义 IP 放行')
        print('  7. 切换证书 HTTP-01 验证路径例外')
        print('  8. 自动更新管理（systemd）')
        print('  9. 检查并诊断 OpenResty 配置')
        print(' 10. 修复网站规则（1Panel 改写配置后）')
        print(' 11. 查看备份')
        print(' 12. 从备份恢复')
        print(' 13. 卸载 cnip 并撤销全部 cnip 限制')
        print('  0. 退出')
        pause = False
        try:
            choice = input('\n请输入数字：').strip()
            if choice == '0':
                return
            pause = True
            with operation_lock():
                if choice == '8':
                    print('1. 开启  2. 关闭  3. 查看状态')
                    arg = {'1': 'enable', '2': 'disable', '3': 'status'}.get(input('请选择：').strip())
                    if arg:
                        print('正在处理自动更新设置……', flush=True)
                        systemd_action(arg)
                    else:
                        print('无效选择，请输入 1、2 或 3。', flush=True)
                    continue
                if choice == '11':
                    do_backups()
                    continue
                if choice not in [str(n) for n in range(1, 14)]:
                    print('请输入有效菜单数字。')
                    continue
                print('正在识别 1Panel / OpenResty（Docker 调用超时 15 秒）……', flush=True)
                env = environment()
                print(f'已识别 OpenResty：{env.container}', flush=True)
                if choice == '1':
                    do_add(env, input('输入需要限制的完整域名：'))
                elif choice == '2':
                    do_remove(env, input('输入需要取消限制的完整域名：'))
                elif choice == '3':
                    do_list(env)
                elif choice == '4':
                    do_update(env)
                elif choice == '5':
                    do_allow(env, 'add', input('输入放行 IPv4 / IPv6 / CIDR：'))
                elif choice == '6':
                    do_allow(env, 'remove', input('输入要删除的 IPv4 / IPv6 / CIDR：'))
                elif choice == '7':
                    enabled = not load_state(env)['acme_exempt']
                    if yn('确定' + ('启用' if enabled else '关闭') + ' ACME HTTP-01 例外？'):
                        do_acme(env, enabled)
                    else:
                        print('已取消修改证书验证路径例外。')
                elif choice == '9':
                    do_doctor(env)
                elif choice == '10':
                    do_repair(env)
                elif choice == '12':
                    do_backups()
                    name = input('请输入要恢复的备份完整名称（留空取消）：').strip()
                    if name and yn(f'恢复 {name} 会覆盖当前配置，确定继续？'):
                        do_restore(env, name)
                    else:
                        print('已取消恢复。')
                elif choice == '13':
                    if yn('确定撤销全部 cnip 规则并删除 cnip 命令吗？') and yn('最终确认，不影响旧版规则：'):
                        do_uninstall(env)
                        pause = False
                        return
                    else:
                        print('已取消卸载。')
        except (CnipError, OSError, ValueError, KeyError, json.JSONDecodeError) as e:
            print('❌ 操作失败：', e)
        except (EOFError, KeyboardInterrupt):
            pause = False
            raise
        finally:
            if pause:
                wait_for_menu()


def main() -> None:
    p = argparse.ArgumentParser(description='1Panel OpenResty 中国大陆 IP 访问管理工具')
    p.add_argument('--version', action='version', version=VERSION)
    sub = p.add_subparsers(dest='command')
    for action in ('add', 'remove'):
        sub.add_parser(action).add_argument('domain')
    for action in ('list', 'doctor', 'repair', 'backups', 'uninstall'):
        sub.add_parser(action)
    sub.add_parser('update').add_argument('--quiet', action='store_true')
    allow = sub.add_parser('allow')
    allow.add_argument('mode', choices=('add', 'remove', 'list'))
    allow.add_argument('cidr', nargs='?')
    sub.add_parser('acme').add_argument('mode', choices=('on', 'off', 'status'))
    sub.add_parser('auto-update').add_argument('mode', choices=('enable', 'disable', 'status'))
    sub.add_parser('restore').add_argument('backup')
    args = p.parse_args()
    if os.geteuid() != 0:
        p.error('请使用 root 运行（sudo cnip）。')
    if args.command is None:
        menu()
        return
    if args.command == 'backups':
        do_backups()
        return
    if args.command == 'auto-update':
        if args.mode == 'status':
            systemd_action(args.mode)
            return
        with operation_lock():
            systemd_action(args.mode)
        return
    with operation_lock():
        if not (args.command == 'update' and args.quiet):
            print('正在识别 1Panel / OpenResty……', flush=True)
        env = environment()
        if args.command == 'add':
            do_add(env, args.domain)
        elif args.command == 'remove':
            do_remove(env, args.domain)
        elif args.command == 'list':
            do_list(env)
        elif args.command == 'doctor':
            do_doctor(env)
        elif args.command == 'repair':
            do_repair(env)
        elif args.command == 'update':
            do_update(env, args.quiet)
        elif args.command == 'allow':
            if args.mode == 'list':
                print('\n'.join(load_state(env)['extra_allow']))
            elif args.cidr:
                do_allow(env, args.mode, args.cidr)
            else:
                raise CnipError('用法：cnip allow add|remove IP/CIDR 或 cnip allow list')
        elif args.command == 'acme':
            if args.mode == 'status':
                print('on' if load_state(env)['acme_exempt'] else 'off')
            else:
                do_acme(env, args.mode == 'on')
        elif args.command == 'restore':
            do_restore(env, args.backup)
        elif args.command == 'uninstall':
            if yn('将取消所有 cnip 规则并卸载命令，确定继续？'):
                do_uninstall(env)


if __name__ == '__main__':
    try:
        main()
    except (CnipError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print('❌ ' + str(exc), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('\n已中断操作。', file=sys.stderr)
        sys.exit(130)

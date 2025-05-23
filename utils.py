import ctypes
import hashlib
import json
import os
import random
import shutil
import sqlite3
import string
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import (
    Any,
    Callable,
    ContextManager,
    Dict,
    Generic,
    Tuple,
    TypeVar,
    Union,
    Optional
)

import requests
from loguru import logger

T = TypeVar('T')


class Result(Generic[T]):
    def __init__(self, success: bool, data: T = None, message: str = ""):
        self.success, self.data, self.message = success, data, message

    @classmethod
    def ok(cls, data: T = None, message: str = "操作成功") -> 'Result[T]':
        return cls(True, data, message)

    @classmethod
    def fail(cls, message: str = "操作失败") -> 'Result[T]':
        return cls(False, None, message)

    def __bool__(self) -> bool:
        return self.success


@contextmanager
def file_operation_context(file_path: Path, require_write: bool = True) -> ContextManager[Path]:
    if not file_path.exists():
        raise FileNotFoundError(f"文件不存在: {file_path}")

    if require_write and not os.access(str(file_path), os.W_OK):
        Utils.manage_file_permissions(file_path, False)

    try:
        yield file_path
    finally:
        if require_write:
            Utils.manage_file_permissions(file_path, True)


class DatabaseManager:
    def __init__(self, db_path: Path, table: str = "itemTable"):
        self.db_path = db_path
        self.table = table

    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def update(self, updates: Dict[str, str]) -> Result[None]:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                for key, value in updates.items():
                    cursor.execute(
                        f"INSERT INTO {self.table} (key, value) VALUES (?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value = ?",
                        (key, value, value)
                    )
                    logger.debug(f"已更新 {key.split('/')[-1]}")
                conn.commit()
                return Result.ok()
        except Exception as e:
            return Result.fail(f"数据库更新失败: {e}")

    def query(self, keys: Union[str, list[str]] = None) -> Result[Dict[str, str]]:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                if isinstance(keys, str):
                    keys = [keys]

                if keys:
                    placeholders = ','.join(['?' for _ in keys])
                    cursor.execute(f"SELECT key, value FROM {self.table} WHERE key IN ({placeholders})", keys)
                else:
                    cursor.execute(f"SELECT key, value FROM {self.table}")

                results = dict(cursor.fetchall())
                logger.debug(f"已查询 {len(results)} 条记录")
                return Result.ok(results)
        except Exception as e:
            return Result.fail(f"数据库查询失败: {e}")


class EnvManager:
    @staticmethod
    def update(updates: Dict[str, str]) -> Result[None]:
        try:
            env_path = Utils.get_path('env')
            content = env_path.read_text(encoding='utf-8').splitlines() if env_path.exists() else []
            updated = {line.split('=')[0]: line for line in content if '=' in line}

            for key, value in updates.items():
                updated[key] = f'{key}=\'{value}\''
                os.environ[key] = value

            env_path.write_text('\n'.join(updated.values()) + '\n', encoding='utf-8')
            logger.debug(f"已更新环境变量: {', '.join(updates.keys())}")
            return Result.ok()
        except Exception as e:
            return Result.fail(f"更新环境变量失败: {e}")

    @staticmethod
    def get(key: str, raise_error: bool = True) -> str:
        if value := os.getenv(key):
            return value
        if raise_error:
            raise ValueError(f"环境变量 '{key}' 未设置")
        return ""


class Utils:
    @staticmethod
    def get_path(path_type: str) -> Path:
        paths = {
            'base': Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).parent,
            'env': lambda: Utils.get_path('base') / '.env',
            'appdata': lambda: Path(os.getenv("APPDATA") or ''),
            'cursor': lambda: Utils.get_path('appdata') / 'Cursor/User/globalStorage'
        }
        path_func = paths.get(path_type)
        if callable(path_func):
            return path_func()
        return paths.get(path_type, Path())

    @staticmethod
    def ensure_path(path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def update_env_vars(updates: Dict[str, str]) -> Result[None]:
        try:
            env_path = Utils.get_path('env')
            content = env_path.read_text(encoding='utf-8').splitlines() if env_path.exists() else []
            updated = {line.split('=')[0]: line for line in content if '=' in line}

            for key, value in updates.items():
                updated[key] = f'{key}=\'{value}\''
                os.environ[key] = value

            env_path.write_text('\n'.join(updated.values()) + '\n', encoding='utf-8')
            logger.debug(f"已更新环境变量: {', '.join(updates.keys())}")
            return Result.ok()
        except Exception as e:
            return Result.fail(f"更新环境变量失败: {e}")

    @staticmethod
    def backup_file(source: Path, backup_dir: Path, prefix: str, max_backups: int = 10) -> Result[None]:
        try:
            with file_operation_context(source, require_write=False) as src:
                Utils.ensure_path(backup_dir)
                backup_path = backup_dir / f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

                try:
                    backup_files = sorted(backup_dir.glob(f"{prefix}_*"), key=lambda x: x.stat().st_ctime)[
                                   :-max_backups + 1]
                    for f in backup_files:
                        try:
                            f.unlink()
                            logger.debug(f"成功删除旧备份文件: {f}")
                        except Exception as del_err:
                            logger.warning(f"删除旧备份文件失败: {f}, 错误: {del_err}")
                except Exception as e:
                    logger.warning(f"处理旧备份文件时出错: {e}")

                shutil.copy2(src, backup_path)
                logger.info(f"已创建备份: {backup_path}")
                return Result.ok()
        except Exception as e:
            return Result.fail(f"备份文件失败: {e}")

    @staticmethod
    def manage_file_permissions(path: Path, make_read_only: bool = True) -> bool:
        try:
            if make_read_only:
                subprocess.run(['takeown', '/f', str(path)], capture_output=True, check=True)
                subprocess.run(['icacls', str(path), '/grant', f'{os.getenv("USERNAME")}:F'], capture_output=True,
                               check=True)
                os.chmod(path, 0o444)
                subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r', f'{os.getenv("USERNAME")}:(R)'],
                               capture_output=True)
            else:
                os.chmod(path, 0o666)
            return True
        except:
            return False

    @staticmethod
    def update_json_file(file_path: Path, updates: Dict[str, Any], make_read_only: bool = False) -> Result[None]:
        try:
            with file_operation_context(file_path, require_write=make_read_only) as fp:
                content = json.loads(fp.read_text(encoding='utf-8'))
                content.update(updates)
                fp.write_text(json.dumps(content, indent=2), encoding='utf-8')
                return Result.ok()
        except Exception as e:
            return Result.fail(f"更新JSON文件失败: {e}")

    @staticmethod
    def kill_process(process_names: list[str]) -> Result[None]:
        try:
            for name in process_names:
                subprocess.run(['taskkill', '/F', '/IM', f'{name}.exe'], capture_output=True, check=False)
            return Result.ok()
        except Exception as e:
            return Result.fail(f"结束进程失败: {e}")

    @staticmethod
    def start_cursor() -> Result[None]:
        try:
            # 从系统变量PATH中查找cursor.exe
            cursor_path = None
            for path_dir in os.environ.get("PATH", "").split(os.pathsep):
                possible_path = os.path.join(path_dir, "cursor.exe")
                if os.path.exists(possible_path):
                    cursor_path = possible_path
                    break
                    
            # 如果PATH中没有，尝试常见安装位置
            if not cursor_path:
                common_paths = [
                    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Cursor", "Cursor.exe"),
                    os.path.join(os.environ.get("PROGRAMFILES", ""), "Cursor", "Cursor.exe"),
                    os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Cursor", "Cursor.exe")
                ]
                for path in common_paths:
                    if os.path.exists(path):
                        cursor_path = path
                        break
                        
            if not cursor_path:
                return Result.fail("找不到Cursor可执行文件")
            
            logger.debug(f"找到Cursor可执行文件路径: {cursor_path}")
                
            # 使用startfile直接启动应用程序
            try:
                # 首先尝试使用startfile (更可靠的Windows方式)
                os.startfile(cursor_path)
                logger.debug("使用startfile成功启动Cursor")
                return Result.ok(message="Cursor已启动")
            except Exception as start_err:
                logger.warning(f"使用startfile启动失败: {start_err}，尝试使用subprocess")
                # 备用方法：subprocess启动
                subprocess.Popen(cursor_path, shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE)
                logger.debug("使用subprocess成功启动Cursor")
                return Result.ok(message="Cursor已启动")
        except Exception as e:
            logger.error(f"启动Cursor失败: {e}")
            return Result.fail(f"启动Cursor失败: {e}")

    @staticmethod
    def run_as_admin() -> bool:
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                return True
            script = os.path.abspath(sys.argv[0])
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                                      ' '.join([script] + sys.argv[1:]), None, 1)
            if int(ret) > 32:
                sys.exit(0)
            return int(ret) > 32
        except:
            return False

    @staticmethod
    def generate_random_string(length: int, chars: str = string.ascii_lowercase + string.digits) -> str:
        return ''.join(random.choices(chars, k=length))

    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        required = [
            random.choice(string.ascii_uppercase),
            random.choice(string.ascii_lowercase),
            random.choice("!@#$%^&*()"),
            random.choice(string.digits)
        ]
        password = required + random.choices(chars, k=length - 4)
        random.shuffle(password)
        return ''.join(password)

    @staticmethod
    def extract_token(cookies: str, token_key: str) -> Union[str, None]:
        try:
            token_start = cookies.index(token_key) + len(token_key)
            token_end = cookies.find(';', token_start)
            token = cookies[token_start:] if token_end == -1 else cookies[token_start:token_end]
            if '::' in token:
                return token.split('::')[1]
            elif '%3A%3A' in token:
                return token.split('%3A%3A')[1]

            logger.error(f"在token中未找到有效的分隔符: {token}")
            return None
        except (ValueError, IndexError) as e:
            logger.error(f"无效的 {token_key}: {str(e)}")
            return None


def error_handler(func: Callable) -> Callable:
    @wraps(func)
    def wrapper(*args, **kwargs) -> Result:
        try:
            result = func(*args, **kwargs)
            return Result.ok(result) if not isinstance(result, Result) else result
        except Exception as e:
            logger.error(f"{func.__name__} 执行失败: {e}")
            return Result.fail(str(e))

    return wrapper


class CursorManager:
    def __init__(self):
        self.db_manager = DatabaseManager(Utils.get_path('cursor') / 'state.vscdb')
        self.env_manager = EnvManager()

    @staticmethod
    @error_handler
    def generate_cursor_account() -> Tuple[str, str]:
        try:
            random_length = random.randint(5, 20)
            email = f"{Utils.generate_random_string(random_length)}@{EnvManager.get('DOMAIN')}"
            password = Utils.generate_secure_password()

            logger.debug("生成的Cursor账号信息：")
            logger.debug(f"邮箱: {email}")
            logger.debug(f"密码: {password}")

            if not (result := EnvManager.update({'EMAIL': email, 'PASSWORD': password})):
                raise RuntimeError(result.message)
            return email, password
        except Exception as e:
            logger.error(f"generate_cursor_account 执行失败: {e}")
            raise

    @staticmethod
    @error_handler
    def reset() -> Result:
        try:
            if not Utils.run_as_admin():
                return Result.fail("需要管理员权限")

            if not (result := Utils.kill_process(['Cursor', 'cursor'])):
                return result

            cursor_path = Utils.get_path('cursor')
            storage_file = cursor_path / 'storage.json'
            backup_dir = cursor_path / 'backups'

            if not (result := Utils.backup_file(storage_file, backup_dir, 'storage.json.backup')):
                return result
            new_ids = {
                f'telemetry.{key}': value for key, value in {
                    'machineId': f"auth0|user_{hashlib.sha256(os.urandom(32)).hexdigest()}",
                    'macMachineId': hashlib.sha256(os.urandom(32)).hexdigest(),
                    'devDeviceId': str(uuid.uuid4()),
                    'sqmId': "{" + str(uuid.uuid4()).upper() + "}"
                }.items()
            }

            if not (result := Utils.update_json_file(storage_file, new_ids)):
                return Result.fail("更新配置文件失败")

            try:
                updater_path = Path(os.getenv('LOCALAPPDATA')) / 'cursor-updater'

                if updater_path.is_dir():
                    try:
                        import shutil
                        shutil.rmtree(updater_path)
                    except Exception as e:
                        logger.warning(f"删除cursor-updater文件夹失败: {e}")

                if not updater_path.exists():
                    updater_path.touch(exist_ok=True)
                    Utils.manage_file_permissions(updater_path)
                else:
                    try:
                        Utils.manage_file_permissions(updater_path)
                    except PermissionError:
                        pass

                return Result.ok(message="重置机器码成功，已禁用自动更新")
            except Exception as e:
                return Result.fail(f"禁用自动更新失败: {e}")
        except Exception as e:
            logger.error(f"reset 执行失败: {e}")
            return Result.fail(str(e))

    @error_handler
    def process_cookies(self, cookies: str, email: str) -> Result:
        try:
            auth_keys = {k: f"cursorAuth/{v}" for k, v in {
                "sign_up": "cachedSignUpType",
                "email": "cachedEmail",
                "access": "accessToken",
                "refresh": "refreshToken"
            }.items()}

            if not (token := Utils.extract_token(cookies, "WorkosCursorSessionToken=")):
                return Result.fail("无效的 WorkosCursorSessionToken")

            updates = {
                auth_keys["sign_up"]: "Auth_0",
                auth_keys["email"]: email,
                auth_keys["access"]: token,
                auth_keys["refresh"]: token
            }

            logger.debug("正在更新认证信息...")
            if not (result := self.db_manager.update(updates)):
                return result

            return Result.ok(message="认证信息更新成功")
        except Exception as e:
            logger.error(f"process_cookies 执行失败: {e}")
            return Result.fail(str(e))


class MoemailManager:
    @staticmethod
    def _check_env_vars() -> Result[Tuple[str, str]]:
        try:
            api_key = os.getenv("API_KEY")
            moe_mail_url = os.getenv("MOE_MAIL_URL")
            
            missing_vars = []
            if not api_key:
                missing_vars.append("API_KEY")
            if not moe_mail_url:
                missing_vars.append("MOE_MAIL_URL")
            
            if missing_vars:
                return Result.fail(f"缺少必需的环境变量: {', '.join(missing_vars)}")
            
            return Result.ok((api_key, moe_mail_url))
        except Exception as e:
            return Result.fail(f"检查环境变量时出错: {str(e)}")

    def __init__(self):
        env_check = self._check_env_vars()
        if not env_check.success:
            logger.error(env_check.message)
            raise ValueError(env_check.message)
        
        self.api_key, base_url = env_check.data
        self.headers = {
            'Content-Type': 'application/json',
            'X-API-Key': self.api_key
        }
        self.base_url = base_url

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Result[dict]:
        try:
            if not method or not endpoint:
                logger.error("请求方法或端点为空")
                return Result.fail("请求参数无效：方法或端点为空")

            base = self.base_url.rstrip('/')
            clean_endpoint = endpoint.lstrip('/')
            url = f"{base}/api/{clean_endpoint}"
            
            logger.debug(f"发送 {method} 请求到 {url}")
            response = requests.request(method, url, headers=self.headers, **kwargs)
            
            if not response:
                logger.error("API请求返回空响应")
                return Result.fail("API请求返回空响应")

            if response.status_code == 200:
                try:
                    response_data = response.json()
                    if not response_data:
                        logger.warning("API返回空数据")
                        return Result.fail("API返回空数据")
                    logger.debug(f"API响应数据: {response_data}")
                    return Result.ok(response_data)
                except ValueError as e:
                    logger.error(f"解析JSON响应失败: {e}")
                    return Result.fail(f"无效的JSON响应: {response.text}")
            
            error_msg = f"请求失败 (状态码: {response.status_code}): {response.text}"
            logger.error(error_msg)
            return Result.fail(error_msg)

        except requests.exceptions.RequestException as e:
            error_msg = f"网络请求错误: {str(e)}"
            logger.error(error_msg)
            return Result.fail(error_msg)
        except Exception as e:
            error_msg = f"请求处理错误: {str(e)}"
            logger.error(error_msg)
            return Result.fail(error_msg)

    def create_email(self, email: str, expiry_time: int = 3600000) -> Result[dict]:
        try:
            name, domain = email.split('@')

            data = {
                "name": name,
                "expiryTime": expiry_time,
                "domain": domain
            }

            result = self._make_request("POST", "/emails/generate", json=data)
            if not result.success:
                logger.error(f"创建邮箱失败: {result.message}")
                return result
            return Result.ok(result.data)

        except Exception as e:
            logger.error(f"创建邮箱时出错: {str(e)}")
            return Result.fail(str(e))

    def get_email_list(self, cursor: Optional[str] = None) -> Result[dict]:
        params = {"cursor": cursor} if cursor else {}
        return self._make_request("GET", "/emails", params=params)

    def get_email_messages(self, email_id: str, cursor: Optional[str] = None) -> Result[dict]:
        params = {"cursor": cursor} if cursor else {}
        return self._make_request("GET", f"/emails/{email_id}", params=params)

    def get_message_detail(self, email_id: str, message_id: str) -> Result[dict]:
        return self._make_request("GET", f"/emails/{email_id}/{message_id}")

    def get_latest_email_messages(self, target_email: str, timeout: int = 60) -> Result[dict]:
        logger.debug(f"开始获取邮箱 {target_email} 的最新邮件")

        try:
            email_list_result = self.get_email_list()
            if not email_list_result:
                return Result.fail(f"获取邮箱列表失败: {email_list_result.message}")

            target = next((
                email for email in email_list_result.data.get('emails', [])
                if email.get('address') == target_email
            ), None)

            if not target or not target.get('id'):
                return Result.fail(f"未找到目标邮箱: {target_email}")

            logger.debug(f"找到目标邮箱，ID: {target.get('id')}")

            messages_result = self.get_email_messages(target['id'])
            if not messages_result:
                return Result.fail(f"获取邮件列表失败: {messages_result.message}")

            messages = messages_result.data.get('messages', [])
            start_time = time.time()
            retry_interval = 2

            while not messages:
                if time.time() - start_time > timeout:
                    return Result.fail("等待邮件超时，1分钟内未收到任何邮件")

                logger.debug(f"邮箱暂无邮件，{retry_interval}秒后重试...")
                time.sleep(retry_interval)

                messages_result = self.get_email_messages(target['id'])
                if not messages_result:
                    return Result.fail(f"获取邮件列表失败: {messages_result.message}")

                messages = messages_result.data.get('messages', [])
                logger.debug(f"第{int((time.time() - start_time) / retry_interval)}次尝试获取邮件...")

            logger.debug(f"成功获取邮件列表，共有 {len(messages)} 封邮件")

            latest_message = max(messages, key=lambda x: x.get('received_at', 0))
            if not latest_message.get('id'):
                return Result.fail("无法获取最新邮件ID")

            logger.debug(f"找到最新邮件，ID: {latest_message.get('id')}")

            detail_result = self.get_message_detail(target['id'], latest_message['id'])
            if not detail_result:
                return Result.fail(f"获取邮件详情失败: {detail_result.message}")

            logger.debug("成功获取邮件详情")
            logger.debug(f"邮件数据: {detail_result.data}")

            return Result.ok(detail_result.data)

        except Exception as e:
            logger.error(f"获取邮件内容时发生错误: {str(e)}")
            return Result.fail(str(e))

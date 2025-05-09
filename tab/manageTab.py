TREE_VIEW_HEIGHT = 7
COLUMN_WIDTH = 100
BUTTON_WIDTH = 15
PADDING = {
    'SMALL': 2,
    'MEDIUM': 5,
    'LARGE': 8,
    'XLARGE': 10
}

import csv
import glob
import os
import re
import threading
import tkinter as tk
from datetime import datetime, timedelta
from tkinter import ttk, messagebox
from typing import Dict, List, Tuple, Callable
from concurrent.futures import ThreadPoolExecutor
import base64
import json
import time

import requests
from loguru import logger

from utils import CursorManager, error_handler, Utils
from .ui import UI

# 添加剪贴板支持
try:
    import pyperclip
    has_pyperclip = True
except ImportError:
    logger.warning("未安装pyperclip模块，将尝试使用系统剪贴板，建议执行：pip install pyperclip")
    has_pyperclip = False
    
    # 尝试使用系统特定的剪贴板方法
    import platform
    
    if platform.system() == 'Windows':
        try:
            import ctypes
            
            # Windows 剪贴板处理
            CF_UNICODETEXT = 13
            
            def windows_copy_clipboard(text):
                ctypes.windll.user32.OpenClipboard(0)
                ctypes.windll.user32.EmptyClipboard()
                
                text_bytes = text.encode('utf-16le')
                hCd = ctypes.windll.kernel32.GlobalAlloc(0x0002, len(text_bytes) + 2)
                pchData = ctypes.windll.kernel32.GlobalLock(hCd)
                ctypes.cdll.msvcrt.memcpy(ctypes.c_void_p(pchData), text_bytes, len(text_bytes))
                ctypes.windll.kernel32.GlobalUnlock(hCd)
                ctypes.windll.user32.SetClipboardData(CF_UNICODETEXT, hCd)
                ctypes.windll.user32.CloseClipboard()
                
            pyperclip = type('PyperclipAlternative', (), {'copy': staticmethod(windows_copy_clipboard)})
            has_pyperclip = True
            logger.info("已启用Windows系统剪贴板支持")
        except Exception as e:
            logger.error(f"初始化Windows剪贴板失败: {e}")
    
    elif platform.system() == 'Darwin':  # macOS
        try:
            def macos_copy_clipboard(text):
                import subprocess
                process = subprocess.Popen(
                    ['pbcopy'], 
                    stdin=subprocess.PIPE, 
                    close_fds=True
                )
                process.communicate(input=text.encode('utf-8'))
                
            pyperclip = type('PyperclipAlternative', (), {'copy': staticmethod(macos_copy_clipboard)})
            has_pyperclip = True
            logger.info("已启用macOS系统剪贴板支持")
        except Exception as e:
            logger.error(f"初始化macOS剪贴板失败: {e}")
    
    elif platform.system() == 'Linux':
        try:
            import subprocess
            
            def xclip_available():
                try:
                    subprocess.check_call(['which', 'xclip'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    return True
                except:
                    return False
            
            def xsel_available():
                try:
                    subprocess.check_call(['which', 'xsel'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    return True
                except:
                    return False
            
            def linux_copy_clipboard(text):
                if xclip_available():
                    process = subprocess.Popen(
                        ['xclip', '-selection', 'clipboard'],
                        stdin=subprocess.PIPE, 
                        close_fds=True
                    )
                    process.communicate(input=text.encode('utf-8'))
                elif xsel_available():
                    process = subprocess.Popen(
                        ['xsel', '-b', '-i'],
                        stdin=subprocess.PIPE, 
                        close_fds=True
                    )
                    process.communicate(input=text.encode('utf-8'))
                else:
                    raise Exception("未找到xclip或xsel命令")
            
            if xclip_available() or xsel_available():
                pyperclip = type('PyperclipAlternative', (), {'copy': staticmethod(linux_copy_clipboard)})
                has_pyperclip = True
                logger.info("已启用Linux系统剪贴板支持")
        except Exception as e:
            logger.error(f"初始化Linux剪贴板失败: {e}")


class ManageTab(ttk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, style='TFrame', **kwargs)
        self.registrar = None
        self.setup_ui()

    def setup_ui(self):
        accounts_frame = UI.create_labeled_frame(self, "已保存账号")

        columns = ('序号', '域名', '邮箱', '额度', '剩余天数')
        tree = ttk.Treeview(accounts_frame, columns=columns, show='headings', height=TREE_VIEW_HEIGHT)

        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=COLUMN_WIDTH)
        
        # 设置序号列为较窄的宽度
        tree.column('序号', width=40, stretch=False)

        tree.bind('<<TreeviewSelect>>', self.on_select)
        # 添加双击事件处理
        tree.bind('<Double-1>', self.on_double_click)

        scrollbar = ttk.Scrollbar(accounts_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)


        outer_button_frame = ttk.Frame(self, style='TFrame')
        outer_button_frame.pack(pady=(PADDING['LARGE'], 0), expand=True)

        button_frame = ttk.Frame(outer_button_frame, style='TFrame')
        button_frame.pack(anchor=tk.W)


        first_row_frame = ttk.Frame(button_frame, style='TFrame')
        first_row_frame.pack(pady=(0, PADDING['MEDIUM']), anchor=tk.W)
        
        ttk.Button(first_row_frame, text="刷新列表", command=self.refresh_list, 
                  style='Custom.TButton', width=10).pack(side=tk.LEFT, padx=PADDING['MEDIUM'])
        ttk.Button(first_row_frame, text="更新信息", command=self.update_account_info, 
                  style='Custom.TButton', width=10).pack(side=tk.LEFT, padx=PADDING['MEDIUM'])
        ttk.Button(first_row_frame, text="更换账号", command=self.update_auth, 
                  style='Custom.TButton', width=10).pack(side=tk.LEFT, padx=PADDING['MEDIUM'])


        second_row_frame = ttk.Frame(button_frame, style='TFrame')
        second_row_frame.pack(pady=(0, PADDING['XLARGE']), anchor=tk.W)
        
        ttk.Button(second_row_frame, text="重置ID", command=self.reset_machine_id, 
                  style='Custom.TButton', width=10).pack(side=tk.LEFT, padx=PADDING['MEDIUM'])
        ttk.Button(second_row_frame, text="删除账号", command=self.delete_account, 
                  style='Custom.TButton', width=10).pack(side=tk.LEFT, padx=PADDING['MEDIUM'])
        
        # 添加复制账号和密码按钮
        ttk.Button(second_row_frame, text="复制账号", command=self.copy_email, 
                  style='Custom.TButton', width=10).pack(side=tk.LEFT, padx=PADDING['MEDIUM'])
        ttk.Button(second_row_frame, text="复制密码", command=self.copy_password, 
                  style='Custom.TButton', width=10).pack(side=tk.LEFT, padx=PADDING['MEDIUM'])

        self.account_tree = tree
        self.selected_item = None

    # 复制到剪贴板通用方法
    def copy_to_clipboard(self, text: str, success_msg: str) -> None:
        if not has_pyperclip:
            UI.show_warning(self.winfo_toplevel(), "复制功能不可用，请安装pyperclip模块\n命令: pip install pyperclip")
            return
            
        try:
            pyperclip.copy(text)
            logger.info(f"已复制到剪贴板: {text}")
            UI.show_success(self.winfo_toplevel(), success_msg)
        except Exception as e:
            UI.show_error(self.winfo_toplevel(), "复制失败", e)
            logger.error(f"复制到剪贴板失败: {str(e)}")
    
    # 复制邮箱账号
    def copy_email(self) -> None:
        try:
            csv_file_path, account_data = self.get_selected_account()
            email = account_data.get('EMAIL', '')
            if not email:
                raise ValueError("所选账号没有邮箱信息")
                
            self.copy_to_clipboard(email, f"已复制邮箱: {email}")
        except Exception as e:
            UI.show_error(self.winfo_toplevel(), "复制邮箱失败", e)
            logger.error(f"复制邮箱失败: {str(e)}")
    
    # 复制密码
    def copy_password(self) -> None:
        try:
            csv_file_path, account_data = self.get_selected_account()
            password = account_data.get('PASSWORD', '')
            if not password:
                raise ValueError("所选账号没有密码信息")
                
            self.copy_to_clipboard(password, f"已复制密码")
        except Exception as e:
            UI.show_error(self.winfo_toplevel(), "复制密码失败", e)
            logger.error(f"复制密码失败: {str(e)}")

    # 处理双击事件，显示账号详细信息
    def on_double_click(self, event):
        try:
            if not self.selected_item:
                return
                
            csv_file_path, account_data = self.get_selected_account()
            email = account_data.get('EMAIL', '未知')
            password = account_data.get('PASSWORD', '未知')
            domain = account_data.get('DOMAIN', '未知')
            quota = account_data.get('QUOTA', '未知')
            days = account_data.get('DAYS', '未知')
            
            # 创建详细信息对话框
            detail_dialog = tk.Toplevel(self.winfo_toplevel())
            detail_dialog.title("账号详细信息")
            detail_dialog.transient(self.winfo_toplevel())
            detail_dialog.grab_set()
            detail_dialog.configure(bg=UI.COLORS['bg'])
            
            # 计算对话框大小和位置
            dialog_width = 450
            dialog_height = 300
            UI.center_window(detail_dialog, dialog_width, dialog_height)
            detail_dialog.resizable(False, False)
            
            # 创建内容框架
            content_frame = ttk.Frame(detail_dialog, style='TFrame', padding=10)
            content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # 账号信息标签
            ttk.Label(content_frame, text="账号信息", style='Title.TLabel').pack(pady=(0, 10))
            
            # 创建表格式布局显示账号信息
            info_frame = ttk.Frame(content_frame, style='TFrame')
            info_frame.pack(fill=tk.BOTH, expand=True, pady=5)
            
            # 域名信息行
            domain_frame = ttk.Frame(info_frame, style='TFrame')
            domain_frame.pack(fill=tk.X, pady=3)
            ttk.Label(domain_frame, text="域名:", width=10, anchor=tk.E).pack(side=tk.LEFT, padx=(0, 5))
            domain_label = ttk.Label(domain_frame, text=domain)
            domain_label.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
            ttk.Button(domain_frame, text="复制", width=6, command=lambda: self.copy_to_clipboard(domain, "已复制域名")).pack(side=tk.RIGHT)
            
            # 邮箱信息行
            email_frame = ttk.Frame(info_frame, style='TFrame')
            email_frame.pack(fill=tk.X, pady=3)
            ttk.Label(email_frame, text="邮箱:", width=10, anchor=tk.E).pack(side=tk.LEFT, padx=(0, 5))
            email_label = ttk.Label(email_frame, text=email)
            email_label.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
            ttk.Button(email_frame, text="复制", width=6, command=lambda: self.copy_to_clipboard(email, "已复制邮箱")).pack(side=tk.RIGHT)
            
            # 密码信息行
            password_frame = ttk.Frame(info_frame, style='TFrame')
            password_frame.pack(fill=tk.X, pady=3)
            ttk.Label(password_frame, text="密码:", width=10, anchor=tk.E).pack(side=tk.LEFT, padx=(0, 5))
            password_var = tk.StringVar(value="●●●●●●●●")
            password_label = ttk.Label(password_frame, textvariable=password_var)
            password_label.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
            
            # 添加密码显示切换和复制按钮
            password_buttons_frame = ttk.Frame(password_frame, style='TFrame')
            password_buttons_frame.pack(side=tk.RIGHT)
            
            # 显示/隐藏密码的变量和函数
            show_password = tk.BooleanVar(value=False)
            
            def toggle_password():
                if show_password.get():
                    password_var.set(password)
                else:
                    password_var.set("●●●●●●●●")
            
            # 密码显示切换按钮
            show_password_check = ttk.Checkbutton(
                password_buttons_frame, 
                text="显示", 
                variable=show_password, 
                command=toggle_password
            )
            show_password_check.pack(side=tk.LEFT, padx=(0, 5))
            
            # 复制密码按钮
            ttk.Button(
                password_buttons_frame, 
                text="复制", 
                width=6, 
                command=lambda: self.copy_to_clipboard(password, "已复制密码")
            ).pack(side=tk.LEFT)
            
            # 额度信息行
            quota_frame = ttk.Frame(info_frame, style='TFrame')
            quota_frame.pack(fill=tk.X, pady=3)
            ttk.Label(quota_frame, text="额度:", width=10, anchor=tk.E).pack(side=tk.LEFT, padx=(0, 5))
            quota_label = ttk.Label(quota_frame, text=quota)
            quota_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
            
            # 剩余天数信息行
            days_frame = ttk.Frame(info_frame, style='TFrame')
            days_frame.pack(fill=tk.X, pady=3)
            ttk.Label(days_frame, text="剩余天数:", width=10, anchor=tk.E).pack(side=tk.LEFT, padx=(0, 5))
            days_label = ttk.Label(days_frame, text=days)
            days_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
            
            # 底部按钮区域
            button_frame = ttk.Frame(content_frame, style='TFrame')
            button_frame.pack(fill=tk.X, pady=(10, 0))
            
            # 关闭按钮
            ttk.Button(
                button_frame, 
                text="关闭", 
                style='Custom.TButton',
                width=10, 
                command=detail_dialog.destroy
            ).pack(side=tk.RIGHT, padx=5)
            
        except Exception as e:
            UI.show_error(self.winfo_toplevel(), "显示账号详情失败", e)
            logger.error(f"显示账号详情失败: {str(e)}")

    def on_select(self, event):
        selected_items = self.account_tree.selection()
        if selected_items:
            self.selected_item = selected_items[0]
        else:
            self.selected_item = None

    def get_csv_files(self) -> List[str]:
        try:
            return glob.glob('env_backups/cursor_account_*.csv')
        except Exception as e:
            logger.error(f"获取CSV文件列表失败: {str(e)}")
            return []

    def parse_csv_file(self, csv_file: str) -> Dict[str, str]:
        account_data = {
            'DOMAIN': '',
            'EMAIL': '',
            'COOKIES_STR': '',
            'QUOTA': '未知',
            'DAYS': '未知',
            'PASSWORD': '',
            'API_KEY': '',
            'MOE_MAIL_URL': ''
        }
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                csv_reader = csv.reader(f)
                next(csv_reader)
                for row in csv_reader:
                    if len(row) >= 2:
                        key, value = row[0], row[1]
                        if key in account_data:
                            account_data[key] = value
        except Exception as e:
            logger.error(f"解析文件 {csv_file} 失败: {str(e)}")
        return account_data

    def update_csv_file(self, csv_file: str, **fields_to_update) -> None:
        if not fields_to_update:
            logger.debug("没有需要更新的字段")
            return

        try:
            rows = []
            with open(csv_file, 'r', encoding='utf-8') as f:
                csv_reader = csv.reader(f)
                rows = list(csv_reader)

            for field, value in fields_to_update.items():
                field_found = False
                for row in rows:
                    if len(row) >= 2 and row[0] == field:
                        row[1] = str(value)
                        field_found = True
                        break
                if not field_found:
                    rows.append([field, str(value)])

            with open(csv_file, 'w', encoding='utf-8', newline='') as f:
                csv_writer = csv.writer(f)
                csv_writer.writerows(rows)

            logger.debug(f"已更新CSV文件: {csv_file}, 更新字段: {', '.join(fields_to_update.keys())}")
        except Exception as e:
            logger.error(f"更新CSV文件失败: {str(e)}")
            raise

    def refresh_list(self):
        for item in self.account_tree.get_children():
            self.account_tree.delete(item)

        try:
            csv_files = self.get_csv_files()
            for i, csv_file in enumerate(csv_files, 1):
                account_data = self.parse_csv_file(csv_file)
                self.account_tree.insert('', 'end', iid=csv_file, values=(
                    i,  # 显示序号
                    account_data['DOMAIN'],
                    account_data['EMAIL'],
                    account_data['QUOTA'],
                    account_data['DAYS']
                ))

            logger.info("账号列表已刷新")
        except Exception as e:
            UI.show_error(self.winfo_toplevel(), "刷新列表失败", e)

    def get_selected_account(self) -> Tuple[str, Dict[str, str]]:
        if not self.selected_item:
            raise ValueError("请先选择要操作的账号")

        item_values = self.account_tree.item(self.selected_item)['values']
        if not item_values or len(item_values) < 2:
            raise ValueError("所选账号信息不完整")

        csv_file_path = self.selected_item
        account_data = self.parse_csv_file(csv_file_path)

        if not account_data['DOMAIN'] or not account_data['EMAIL']:
            raise ValueError("账号信息不完整")

        return csv_file_path, account_data

    def handle_account_action(self, action_name: str, action: Callable[[str, Dict[str, str]], None]) -> None:
        try:
            csv_file_path, account_data = self.get_selected_account()
            action(csv_file_path, account_data)
        except Exception as e:
            UI.show_error(self.winfo_toplevel(), f"{action_name}失败", e)
            logger.error(f"{action_name}失败: {str(e)}")

    def get_trial_usage(self, cookie_str: str) -> Tuple[str, str, str, str]:
        if not cookie_str:
            raise ValueError("Cookie信息不能为空")

        try:
            user_id = self.extract_user_id_from_jwt(cookie_str)
            
            if not cookie_str.startswith('WorkosCursorSessionToken='):
                cookie_str = f'WorkosCursorSessionToken={cookie_str}'

            headers = {
                'Cookie': cookie_str,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
            }

            timeout = 10
            session = requests.Session()
            session.headers.update(headers)

            def make_request(url: str) -> dict:
                try:
                    response = session.get(url, timeout=timeout)
                    response.raise_for_status()
                    return response.json()
                except requests.RequestException as e:
                    logger.error(f"请求 {url} 失败: {str(e)}")
                    raise ValueError(f"API请求失败: {str(e)}")

            try:
                with ThreadPoolExecutor(max_workers=3) as executor:
                    future_user_info = executor.submit(make_request, "https://www.cursor.com/api/auth/me")
                    future_trial = executor.submit(make_request, "https://www.cursor.com/api/auth/stripe")
                    future_usage = executor.submit(make_request, f"https://www.cursor.com/api/usage?user={user_id}")

                    user_info = future_user_info.result()
                    email = user_info.get('email', '未知')
                    domain = email.split('@')[-1] if '@' in email else '未知'

                    trial_data = future_trial.result()
                    days = str(trial_data.get('daysRemainingOnTrial', '未知'))

                    usage_data = future_usage.result()
                    gpt4_data = usage_data.get('gpt-4', {})
                    used_quota = gpt4_data.get('numRequestsTotal', 0)
                    max_quota = gpt4_data.get('maxRequestUsage', 0)
                    quota = f"{used_quota} / {max_quota}" if max_quota else '未知'

                    return domain, email, quota, days

            except Exception as e:
                logger.error(f"获取账号信息失败: {str(e)}")
                raise ValueError(f"获取账号信息失败: {str(e)}")
            finally:
                session.close()
        except Exception as e:
            logger.error(f"处理 JWT 失败: {str(e)}")
            raise ValueError(f"处理 JWT 失败: {str(e)}")

    def extract_user_id_from_jwt(self, cookies: str) -> str:
        try:
            jwt_token = Utils.extract_token(cookies, "WorkosCursorSessionToken")
            parts = jwt_token.split('.')
            if len(parts) != 3:
                raise ValueError("无效的 JWT 格式")
            
            payload = parts[1]
            payload += '=' * (-len(payload) % 4)
            decoded = base64.b64decode(payload)
            payload_data = json.loads(decoded)
            
            user_id = payload_data.get('sub')
            if not user_id:
                raise ValueError("JWT 中未找到用户 ID")
                
            return user_id
        except Exception as e:
            logger.error(f"从 JWT 提取用户 ID 失败: {str(e)}")
            raise ValueError(f"JWT 解析失败: {str(e)}")

    def update_account_info(self):
        def get_trial_info(csv_file_path: str, account_data: Dict[str, str]) -> None:
            cookie_str = account_data.get('COOKIES_STR', '')
            if not cookie_str:
                raise ValueError(f"未找到账号 {account_data['EMAIL']} 的Cookie信息")

            def fetch_and_display_info():
                try:
                    self.winfo_toplevel().after(0, lambda: UI.show_loading(
                        self.winfo_toplevel(),
                        "更新账号信息",
                        "正在获取账号信息，请稍候..."
                    ))

                    logger.debug("开始获取账号信息...")
                    logger.debug(f"获取到的cookie字符串长度: {len(cookie_str) if cookie_str else 0}")

                    user_id = self.extract_user_id_from_jwt(cookie_str)
                    reconstructed_cookie = f"WorkosCursorSessionToken={user_id}%3A%3A{cookie_str.split('%3A%3A')[-1]}" if '%3A%3A' in cookie_str else cookie_str

                    domain, email, quota, days = self.get_trial_usage(reconstructed_cookie)
                    logger.info(f"成功获取账号信息: 域名={domain}, 邮箱={email}, 额度={quota}, 天数={days}")

                    self.account_tree.set(self.selected_item, '域名', domain)
                    self.account_tree.set(self.selected_item, '邮箱', email)
                    self.account_tree.set(self.selected_item, '额度', quota)
                    self.account_tree.set(self.selected_item, '剩余天数', days)

                    try:
                        self.update_csv_file(csv_file_path,
                                           DOMAIN=domain,
                                           EMAIL=email,
                                           QUOTA=quota,
                                           DAYS=days,
                                           COOKIES_STR=reconstructed_cookie)
                    except Exception as e:
                        logger.error(f"更新CSV文件失败: {str(e)}")
                        raise ValueError(f"更新CSV文件失败: {str(e)}")

                    self.winfo_toplevel().after(0, lambda: UI.close_loading(self.winfo_toplevel()))
                    self.winfo_toplevel().after(0, lambda: UI.show_success(
                        self.winfo_toplevel(),
                        f"域名: {domain}\n"
                        f"邮箱: {email}\n"
                        f"可用额度: {quota}\n"
                        f"剩余天数: {days}"
                    ))
                except Exception as e:
                    error_message = str(e)
                    logger.error(f"获取账号信息失败: {error_message}")
                    logger.exception("详细错误信息:")
                    self.winfo_toplevel().after(0, lambda: UI.close_loading(self.winfo_toplevel()))
                    self.winfo_toplevel().after(0, lambda: UI.show_error(
                        self.winfo_toplevel(),
                        "获取账号信息失败",
                        error_message
                    ))

            logger.debug("开始更新账号信息...")
            threading.Thread(target=fetch_and_display_info, daemon=True).start()

        self.handle_account_action("获取账号信息", get_trial_info)

    def update_auth(self) -> None:
        def update_account_auth(csv_file_path: str, account_data: Dict[str, str]) -> None:
            cookie_str = account_data.get('COOKIES_STR', '')
            email = account_data.get('EMAIL', '')
            if not cookie_str:
                raise ValueError(f"未找到账号 {email} 的Cookie信息")

            if "WorkosCursorSessionToken=" not in cookie_str:
                cookie_str = f"WorkosCursorSessionToken={cookie_str}"

            def process_auth():
                try:
                    self.winfo_toplevel().after(0, lambda: UI.show_loading(
                        self.winfo_toplevel(),
                        "更换账号",
                        "正在刷新Cookie，请稍候..."
                    ))

                    result = CursorManager().process_cookies(cookie_str, email)
                    
                    self.winfo_toplevel().after(0, lambda: UI.close_loading(self.winfo_toplevel()))
                    
                    if not result.success:
                        raise ValueError(result.message)

                    def restart_cursor():
                        try:
                            self.winfo_toplevel().after(0, lambda: UI.show_loading(
                                self.winfo_toplevel(),
                                "正在重启Cursor",
                                "关闭并重启Cursor编辑器..."
                            ))
                            
                            # 关闭Cursor进程
                            logger.debug("开始关闭Cursor进程")
                            kill_result = Utils.kill_process(['Cursor', 'cursor'])
                            if not kill_result.success:
                                logger.warning(f"关闭Cursor进程失败: {kill_result.message}")
                            
                            # 等待进程完全关闭
                            logger.debug("等待Cursor进程完全关闭")
                            time.sleep(3)  # 增加等待时间确保进程完全关闭
                            
                            # 启动Cursor
                            logger.debug("开始启动Cursor")
                            start_result = Utils.start_cursor()
                            
                            # 给Cursor启动一些时间
                            time.sleep(1)
                            
                            self.winfo_toplevel().after(0, lambda: UI.close_loading(self.winfo_toplevel()))
                            
                            if not start_result.success:
                                logger.warning(f"启动Cursor失败: {start_result.message}")
                                self.winfo_toplevel().after(0, lambda: UI.show_warning(
                                    self.winfo_toplevel(),
                                    "Cursor账号已更换，但自动启动Cursor失败，请手动打开Cursor。"
                                ))
                            else:
                                self.winfo_toplevel().after(0, lambda: UI.show_success(
                                    self.winfo_toplevel(),
                                    f"账号 {email} 的Cookie已刷新并重启Cursor"
                                ))
                        except Exception as e:
                            self.winfo_toplevel().after(0, lambda: UI.close_loading(self.winfo_toplevel()))
                            logger.error(f"重启Cursor失败: {e}")
                            self.winfo_toplevel().after(0, lambda: UI.show_warning(
                                self.winfo_toplevel(),
                                f"账号 {email} 的Cookie已刷新，但重启Cursor失败: {str(e)}"
                            ))
                    
                    threading.Thread(target=restart_cursor, daemon=True).start()
                    logger.info(f"已刷新账号 {email} 的Cookie")
                except Exception as e:
                    self.winfo_toplevel().after(0, lambda: UI.close_loading(self.winfo_toplevel()))
                    self.winfo_toplevel().after(0, lambda: UI.show_error(
                        self.winfo_toplevel(),
                        "更换账号失败",
                        str(e)
                    ))

            threading.Thread(target=process_auth, daemon=True).start()

        self.handle_account_action("刷新Cookie", update_account_auth)

    def delete_account(self):
        def delete_account_file(csv_file_path: str, account_data: Dict[str, str]) -> None:
            confirm_message = (
                f"确定要删除以下账号吗？\n\n"
                f"域名：{account_data['DOMAIN']}\n"
                f"邮箱：{account_data['EMAIL']}\n"
                f"额度：{account_data['QUOTA']}\n"
                f"剩余天数：{account_data['DAYS']}"
            )

            if not messagebox.askyesno("确认删除", confirm_message, icon='warning'):
                return

            def process_delete():
                try:
                    self.winfo_toplevel().after(0, lambda: UI.show_loading(
                        self.winfo_toplevel(),
                        "删除账号",
                        "正在删除账号信息，请稍候..."
                    ))

                    os.remove(csv_file_path)
                    self.account_tree.delete(self.selected_item)
                    
                    self.winfo_toplevel().after(0, lambda: UI.close_loading(self.winfo_toplevel()))
                    logger.info(f"已删除账号: {account_data['DOMAIN']} - {account_data['EMAIL']}")
                    UI.show_success(self.winfo_toplevel(),
                                    f"已删除账号: {account_data['DOMAIN']} - {account_data['EMAIL']}")
                except Exception as e:
                    self.winfo_toplevel().after(0, lambda: UI.close_loading(self.winfo_toplevel()))
                    self.winfo_toplevel().after(0, lambda: UI.show_error(
                        self.winfo_toplevel(),
                        "删除账号失败",
                        str(e)
                    ))

            threading.Thread(target=process_delete, daemon=True).start()

        self.handle_account_action("删除账号", delete_account_file)

    @error_handler
    def reset_machine_id(self) -> None:
        def reset_thread():
            try:
          
                self.after(0, lambda: UI.show_loading(
                    self.winfo_toplevel(),
                    "正在重置机器ID",
                    "正在执行重置操作，请稍候..."
                ))
                
               
                result = CursorManager.reset()
                
               
                self.after(0, lambda: UI.close_loading(self.winfo_toplevel()))
                
                if not result.success:
                    self.after(0, lambda: UI.show_error(
                        self.winfo_toplevel(),
                        "重置机器ID失败",
                        result.message
                    ))
                    return
                    
                self.after(0, lambda: UI.show_success(
                    self.winfo_toplevel(),
                    result.message
                ))
                
            except Exception as e:
               
                self.after(0, lambda: UI.close_loading(self.winfo_toplevel()))
                self.after(0, lambda: UI.show_error(
                    self.winfo_toplevel(),
                    "重置机器ID失败",
                    str(e)
                ))
        
      
        threading.Thread(target=reset_thread, daemon=True).start()

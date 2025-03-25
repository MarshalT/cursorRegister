import imaplib
import email
import re
import time
from email.header import decode_header
from loguru import logger
from datetime import datetime, timedelta

class QQEmailManager:
    def __init__(self):
        self.imap_server = "imap.qq.com"
        self.imap_port = 993
        self.email_address = None
        self.auth_code = None
        self.mail = None
        self.last_verification_time = None  # 记录上次验证邮件时间戳
        
    def connect(self, email_address, auth_code):
        """连接QQ邮箱IMAP服务"""
        self.email_address = email_address
        self.auth_code = auth_code
        
        try:
            self.mail = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
            self.mail.login(self.email_address, self.auth_code)
            logger.debug(f"成功连接到QQ邮箱: {self.email_address}")
            # 连接成功后立即清理验证邮件
            self.delete_cursor_verification_emails(days=1)
            return True
        except Exception as e:
            logger.error(f"连接QQ邮箱失败: {str(e)}")
            return False
    
    def get_cursor_verification_code(self, wait_time=120, check_interval=2, registration_email=None):
        """等待并获取Cursor验证码邮件
        
        Args:
            wait_time: 最大等待时间（秒）
            check_interval: 检查间隔（秒）
            registration_email: 当前用于注册的邮箱地址，用于定位验证码邮件
        """
        if not self.mail:
            logger.error("未连接到QQ邮箱")
            return None
            
        if registration_email:
            logger.debug(f"正在搜索包含注册邮箱 {registration_email} 的验证码邮件")
        
        start_time = time.time()
        
        # 提取用户名用于后续匹配
        email_username = ""
        if registration_email and '@' in registration_email:
            email_username = registration_email.split('@')[0]
        
        # 记录上次处理过的邮件ID，避免重复处理
        processed_ids = set()
        
        # 获取搜索时间范围 - 仅搜索最近2分钟内的邮件，这对验证码邮件足够了
        search_start_time = datetime.now() - timedelta(minutes=2)
        search_date = search_start_time.strftime("%d-%b-%Y %H:%M:%S")
        
        # 记录搜索起始时间，用于日志
        search_begin = datetime.now()
        logger.debug(f"开始搜索验证码邮件，时间: {search_begin.strftime('%H:%M:%S')}")
        
        while time.time() - start_time < wait_time:
            try:
                # 选择收件箱，但不获取状态消息 (使用静默选择)
                self.mail.select("INBOX", readonly=False)
                
                # 构建最精确的搜索条件 - 直接搜索未读的验证邮件
                from_condition = '(FROM "cursor.sh" OR FROM "cursor.com")'  # 发件人条件
                subject_condition = 'SUBJECT "Verify"'  # 主题条件
                unseen_condition = 'UNSEEN'  # 未读条件
                time_condition = f'SINCE "{search_date}"'  # 时间条件
                
                # 最优先搜索未读的验证邮件
                search_query = f'{unseen_condition} {subject_condition} {from_condition}'
                email_ids = self._search_emails(search_query)
                
                # 如果没找到，尝试搜索所有验证邮件（包括已读的）
                if not email_ids:
                    search_query = f'{subject_condition} {from_condition} {time_condition}'
                    email_ids = self._search_emails(search_query)
                
                # 如果仍然没找到，等待后继续
                if not email_ids:
                    # 计算等待时间
                    elapsed = (datetime.now() - search_begin).total_seconds()
                    if elapsed > 30:  # 如果已经搜索超过30秒，使用更短的等待间隔
                        actual_interval = min(check_interval, 2)
                    else:
                        actual_interval = check_interval
                    
                    logger.debug(f"未找到验证码邮件，等待{actual_interval}秒后重试...")
                    time.sleep(actual_interval)
                    continue
                
                # 限制处理的邮件数量 - 只处理最新的2封
                email_ids = sorted(email_ids, reverse=True)[:2]
                logger.debug(f"将处理最新的 {len(email_ids)} 封邮件")
                
                # 处理找到的邮件
                for email_id in email_ids:
                    # 跳过已处理过的邮件ID
                    if email_id in processed_ids:
                        continue
                    processed_ids.add(email_id)
                    
                    # 快速检查邮件
                    try:
                        # 仅获取邮件头和正文的前4KB (足够提取验证码)
                        fetch_query = '(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)] BODY.PEEK[TEXT]<0.4096>)'
                        status, msg_data = self.mail.fetch(email_id, fetch_query)
                        
                        if status != "OK" or not msg_data or len(msg_data) < 2:
                            logger.debug(f"无法获取邮件 {email_id} 内容")
                            continue
                            
                        # 解析邮件头
                        header_data = msg_data[0][1]
                        header_str = header_data.decode('utf-8', errors='ignore').lower()
                        
                        # 快速检查是否为验证邮件
                        if 'cursor' not in header_str or 'verify' not in header_str:
                            logger.debug(f"邮件 {email_id} 不是验证邮件，跳过")
                            continue
                        
                        # 获取正文
                        body_data = msg_data[1][1]
                        body = body_data.decode('utf-8', errors='ignore')
                        
                        # 如果指定了注册邮箱，先检查邮件内容是否包含该邮箱
                        if registration_email and registration_email not in body and email_username not in body:
                            logger.debug(f"邮件 {email_id} 不包含注册邮箱 {registration_email}，跳过")
                            continue
                        
                        # 快速提取验证码 - 直接使用优化版的提取算法
                        code = self._extract_verification_code(body)
                        if code:
                            # 处理成功提取验证码的情况
                            self._mark_and_delete_email(email_id)
                            logger.info(f"成功提取Cursor验证码: {code}")
                            return code
                            
                    except Exception as e:
                        logger.debug(f"处理邮件 {email_id} 出错: {e}")
                        continue
                
                # 如果本轮没找到验证码，等待后继续
                logger.debug(f"本轮未找到验证码，等待{check_interval}秒后重试...")
                time.sleep(check_interval)
            
            except Exception as e:
                logger.error(f"获取验证码过程出错: {e}")
                time.sleep(check_interval)
        
        logger.error(f"等待超时({wait_time}秒)，未找到验证码")
        return None
    
    def _search_emails(self, search_query):
        """搜索符合条件的邮件
        
        Args:
            search_query: 搜索条件
            
        Returns:
            邮件ID列表
        """
        try:
            # 执行搜索
            status, messages = self.mail.search(None, search_query)
            if status != "OK" or not messages[0]:
                return []
                
            # 获取邮件ID列表
            email_ids = messages[0].split()
            query_display = search_query.replace('(', '').replace(')', '')
            logger.debug(f"搜索条件「{query_display}」找到 {len(email_ids)} 封邮件")
            return email_ids
        except Exception as e:
            logger.debug(f"搜索邮件失败: {e}")
            return []
    
    def _extract_verification_code(self, body):
        """从邮件内容中提取验证码
        
        Args:
            body: 邮件正文
            
        Returns:
            验证码字符串，如果未找到则返回None
        """
        try:
            # 方法1: 行扫描 - 寻找单独一行的6位数字
            for line in body.splitlines():
                line = line.strip()
                if re.match(r'^\d{6}$', line):
                    return line
            
            # 方法2: 关键词匹配
            match = re.search(r'Enter the code below[^0-9]*(\d{6})', body, re.IGNORECASE)
            if match:
                return match.group(1)
                
            # 方法3: 通用匹配 - 查找被非数字字符包围的6位数字
            match = re.search(r'[^0-9](\d{6})[^0-9]', " " + body + " ")
            if match:
                return match.group(1)
                
            return None
        except Exception as e:
            logger.debug(f"提取验证码失败: {e}")
            return None
    
    def _mark_and_delete_email(self, email_id):
        """标记并删除指定的邮件
        
        Args:
            email_id: 邮件ID
        """
        try:
            # 标记为已读
            self.mail.store(email_id, '+FLAGS', '\\Seen')
            
            # 标记为删除并执行删除
            self.mail.store(email_id, '+FLAGS', '\\Deleted')
            self.mail.expunge()
            logger.debug(f"已删除验证码邮件 {email_id}")
        except Exception as e:
            logger.debug(f"标记/删除邮件失败: {e}")
        
    def delete_cursor_verification_emails(self, days=7):
        """删除指定天数内的所有Cursor验证邮件
        
        Args:
            days: 要删除的邮件天数范围
        
        Returns:
            已删除的邮件数量
        """
        try:
            # 选择收件箱
            self.mail.select("INBOX")
            
            # 构建搜索条件 - 查找所有来自cursor的验证邮件
            days_ago = (datetime.now() - timedelta(days=days)).strftime("%d-%b-%Y")
            search_criteria = f'(FROM "cursor.sh" OR FROM "cursor.com") SUBJECT "Verify" SINCE "{days_ago}"'
            
            # 搜索邮件
            status, messages = self.mail.search(None, search_criteria)
            if status != "OK" or not messages[0]:
                logger.debug("未找到需要删除的验证邮件")
                return 0
                
            # 获取邮件ID
            email_ids = messages[0].split()
            count = len(email_ids)
            
            if count > 0:
                logger.debug(f"找到 {count} 封需要删除的验证邮件")
                
                # 批量标记删除
                for email_id in email_ids:
                    self.mail.store(email_id, '+FLAGS', '\\Deleted')
                
                # 执行删除操作
                self.mail.expunge()
                logger.info(f"成功删除 {count} 封验证邮件")
                return count
            
            return 0
        except Exception as e:
            logger.error(f"删除验证邮件失败: {e}")
            return 0
    
    def disconnect(self):
        """断开连接"""
        if self.mail:
            try:
                # 确保在断开连接前执行所有待删除的邮件删除操作
                try:
                    self.mail.expunge()
                except:
                    pass
                
                self.mail.close()
                self.mail.logout()
                logger.debug("已断开QQ邮箱连接")
            except Exception as e:
                logger.error(f"断开连接时出错: {e}")

# 单独测试
if __name__ == "__main__":
    import os
    from dotenv import load_dotenv
    
    # 加载环境变量
    load_dotenv()
    
    # 获取QQ邮箱配置
    qq_email = os.getenv('QQ_EMAIL')
    qq_auth_code = os.getenv('QQ_AUTH_CODE')
    
    if not qq_email or not qq_auth_code:
        print("请在.env文件中设置QQ_EMAIL和QQ_AUTH_CODE环境变量")
        exit(1)
    
    # 创建QQ邮箱管理器
    manager = QQEmailManager()
    
    # 连接QQ邮箱
    if manager.connect(qq_email, qq_auth_code):
        print(f"成功连接到QQ邮箱: {qq_email}")
        
        # 询问是否清理历史验证邮件
        clean_history = input("是否要清理历史验证邮件？(y/n): ").lower() == 'y'
        if clean_history:
            days = int(input("要删除多少天内的验证邮件？(默认7天): ") or "7")
            deleted = manager.delete_cursor_verification_emails(days)
            if deleted:
                print(f"已删除 {deleted} 封历史验证邮件")
        
        # 获取验证码
        code_test = input("是否要测试获取验证码？(y/n): ").lower() == 'y'
        if code_test:
            test_email = input("输入测试邮箱地址(用于过滤)或直接回车: ")
            print("开始获取验证码，等待中...")
            code = manager.get_cursor_verification_code(
                wait_time=60, 
                check_interval=3, 
                registration_email=test_email if test_email else None
            )
            
            if code:
                print(f"成功获取验证码: {code}")
            else:
                print("未能获取验证码")
        
        # 断开连接
        manager.disconnect()
    else:
        print("连接QQ邮箱失败")

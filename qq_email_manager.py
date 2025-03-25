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
        
    def connect(self, email_address, auth_code):
        """连接QQ邮箱IMAP服务"""
        self.email_address = email_address
        self.auth_code = auth_code
        
        try:
            self.mail = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
            self.mail.login(self.email_address, self.auth_code)
            logger.debug(f"成功连接到QQ邮箱: {self.email_address}")
            return True
        except Exception as e:
            logger.error(f"连接QQ邮箱失败: {str(e)}")
            return False
    
    def get_cursor_verification_code(self, wait_time=120, check_interval=5, registration_email=None):
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
        
        while time.time() - start_time < wait_time:
            try:
                # 选择收件箱
                self.mail.select("INBOX")
                
                # 优先搜索最近邮件，缩短搜索时间范围
                try:
                    # 仅搜索前30秒内的新邮件，减少处理量
                    minutes_ago = 1
                    date_since = (datetime.now() - timedelta(minutes=minutes_ago)).strftime("%d-%b-%Y")
                    search_criteria = f'(SINCE "{date_since}")'
                    status, recent_messages = self.mail.search(None, search_criteria)
                    
                    if status != "OK" or not recent_messages[0]:
                        # 如果没有找到最近邮件，直接返回搜索未读和Cursor邮件
                        search_criteria = '(UNSEEN FROM "noreply@cursor.com" OR UNSEEN FROM "noreply@cursor.sh")'
                        status, recent_messages = self.mail.search(None, search_criteria)
                    
                    if status == "OK" and recent_messages[0]:
                        email_ids = recent_messages[0].split()
                        # 从最新到最旧排序
                        email_ids.reverse()
                        # 只处理最新的3封邮件以提高速度
                        email_ids = email_ids[:3]
                        logger.debug(f"找到 {len(email_ids)} 封最近邮件，准备处理")
                    else:
                        # 如果仍然没有找到，等待下一轮检查
                        logger.debug(f"未找到任何符合条件的邮件，等待{check_interval}秒后重试...")
                        time.sleep(check_interval)
                        continue
                except Exception as e:
                    logger.debug(f"搜索邮件时出错: {str(e)}")
                    time.sleep(check_interval)
                    continue
                
                # 处理找到的邮件
                verification_code = None
                
                for email_id in email_ids:
                    try:
                        # 获取邮件内容，使用快速获取方式
                        status, msg_data = self.mail.fetch(email_id, '(BODY.PEEK[TEXT] BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])')
                        if status != "OK":
                            continue
                        
                        # 解析邮件头部信息
                        header_data = msg_data[1][1]
                        msg_headers = email.message_from_bytes(header_data)
                        
                        # 获取发件人
                        from_addr = msg_headers.get("From", "")
                        
                        # 获取主题
                        subject = decode_header(msg_headers.get("Subject", ""))[0][0]
                        if isinstance(subject, bytes):
                            subject = subject.decode()
                        
                        # 快速检查是否是Cursor邮件
                        if ("cursor" not in from_addr.lower() and 
                            "cursor" not in subject.lower() and 
                            "verify" not in subject.lower()):
                            continue
                            
                        logger.debug(f"找到可能的验证码邮件: 来自 {from_addr}, 主题: {subject}")
                        
                        # 获取邮件正文
                        body_data = msg_data[0][1]
                        body = ""
                        
                        try:
                            if isinstance(body_data, bytes):
                                # 尝试各种编码
                                for encoding in ['utf-8', 'latin-1', 'ascii']:
                                    try:
                                        body = body_data.decode(encoding)
                                        break
                                    except:
                                        continue
                        except:
                            # 如果简单方法失败，使用完整解析
                            try:
                                status, full_msg_data = self.mail.fetch(email_id, '(RFC822)')
                                if status == "OK":
                                    msg = email.message_from_bytes(full_msg_data[0][1])
                                    if msg.is_multipart():
                                        for part in msg.walk():
                                            content_type = part.get_content_type()
                                            if content_type == "text/plain" or content_type == "text/html":
                                                try:
                                                    payload = part.get_payload(decode=True)
                                                    if payload:
                                                        charset = part.get_content_charset() or 'utf-8'
                                                        body = payload.decode(charset, errors='replace')
                                                        break
                                                except:
                                                    continue
                                    else:
                                        try:
                                            payload = msg.get_payload(decode=True)
                                            if payload:
                                                charset = msg.get_content_charset() or 'utf-8'
                                                body = payload.decode(charset, errors='replace')
                                        except:
                                            pass
                            except:
                                # 如果还是失败，跳过此邮件
                                continue
                        
                        # 检查邮件正文长度
                        if not body:
                            continue
                            
                        logger.debug(f"邮件内容长度: {len(body)} 字符")
                        
                        # 如果有注册邮箱，快速检查邮件是否包含该邮箱
                        if registration_email and registration_email not in body and email_username not in body:
                            continue
                            
                        # 提取验证码 - 直接使用简单匹配，避免复杂正则表达式
                        verification_code = self._fast_extract_code(body)
                        if verification_code:
                            # 将邮件标记为已读
                            self.mail.store(email_id, '+FLAGS', '\\Seen')
                            logger.info(f"成功提取Cursor验证码: {verification_code}")
                            return verification_code
                    except Exception as e:
                        logger.debug(f"处理邮件出错: {str(e)}")
                        continue
                
                # 如果处理完所有邮件但没找到验证码，等待并重试
                logger.debug(f"未找到验证码，等待{check_interval}秒后重试...")
                time.sleep(check_interval)
            
            except Exception as e:
                logger.error(f"获取验证码过程出错: {str(e)}")
                time.sleep(check_interval)
        
        logger.error(f"等待超时({wait_time}秒)，未收到或无法解析Cursor验证码邮件")
        return None
    
    def _fast_extract_code(self, email_content):
        """快速从邮件内容中提取6位数字验证码"""
        if not email_content:
            return None
            
        # 1. 尝试查找特定格式 "Enter the code below" 后的6位数字
        try:
            code_match = re.search(r'Enter the code below[^0-9]*(\d{6})', email_content, re.IGNORECASE)
            if code_match:
                return code_match.group(1)
        except:
            pass
            
        # 2. 查找行内孤立的6位数字 - 最常见的验证码格式
        try:
            for line in email_content.splitlines():
                line = line.strip()
                if re.match(r'^\d{6}$', line):
                    return line
        except:
            pass
        
        # 3. 最后尝试找任何6位数字
        try:
            matches = re.findall(r'\D(\d{6})\D', ' ' + email_content + ' ')
            if matches:
                return matches[0]
        except:
            pass
            
        return None
        
    def extract_verification_code(self, email_content):
        """从邮件内容中提取验证码（完整版本，仅作为备用）"""
        if not email_content:
            return None
        
        # 尝试快速提取方法
        code = self._fast_extract_code(email_content)
        if code:
            return code
            
        # 如果快速方法失败，尝试更多模式
        patterns = [
            r'\n\s*(\d{6})\s*\n',
            r'验证码[：:]?\s*?(\d{6})',
            r'verification code[：:]*\s*(\d{6})',
            r'code[：:]?\s*?(\d{6})',
            r'<strong>(\d{6})</strong>',
            r'<b>(\d{6})</b>',
            r'(\d{6})'
        ]
        
        for pattern in patterns:
            try:
                match = re.search(pattern, email_content, re.IGNORECASE | re.DOTALL)
                if match:
                    return match.group(1)
            except:
                continue
        
        return None
        
    def disconnect(self):
        """断开连接"""
        if self.mail:
            try:
                self.mail.close()
                self.mail.logout()
                logger.debug("已断开QQ邮箱连接")
            except Exception as e:
                logger.error(f"断开连接时出错: {str(e)}")

if __name__ == "__main__":
    # 简单测试代码
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
        
        # 获取验证码
        print("开始获取验证码，等待中...")
        code = manager.get_cursor_verification_code(wait_time=60, check_interval=5)
        
        if code:
            print(f"成功获取验证码: {code}")
        else:
            print("未能获取验证码")
        
        # 断开连接
        manager.disconnect()
    else:
        print("连接QQ邮箱失败")

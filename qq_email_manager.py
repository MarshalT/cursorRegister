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
        
        while time.time() - start_time < wait_time:
            try:
                # 选择收件箱
                self.mail.select("INBOX")
                
                # 优先搜索最近邮件
                email_ids = []
                used_strategy = ""
                
                # 搜索策略1: 获取最近10分钟内的邮件
                try:
                    date_since = (datetime.now() - timedelta(minutes=1)).strftime("%d-%b-%Y")
                    search_criteria = f'(SINCE "{date_since}")'
                    status, recent_messages = self.mail.search(None, search_criteria)
                    
                    if status == "OK" and recent_messages[0]:
                        temp_ids = recent_messages[0].split()
                        temp_ids.reverse()  # 最新的邮件优先
                        email_ids = temp_ids[:2]  # 只获取最新的10封邮件
                        used_strategy = "最近1分钟内的邮件"
                        logger.debug(f"找到 {len(email_ids)} 封最近1分钟内收到的邮件")
                except Exception as e:
                    logger.debug(f"按时间搜索邮件时出错: {str(e)}")
                
                # 搜索策略2: 如果没有找到最近邮件，使用其他搜索策略
                if not email_ids:
                    # 搜索策略优先级
                    search_strategies = []
                    
                    # 根据是否有注册邮箱调整策略
                    if registration_email:
                        # 将邮箱分割为关键部分用于搜索
                        email_username = registration_email.split('@')[0] if '@' in registration_email else registration_email
                        
                        search_strategies.extend([
                            ('(UNSEEN FROM "noreply@cursor.com")', "来自cursor.com的未读邮件"),
                            ('(UNSEEN SUBJECT "Verify your email")', "主题为Verify your email的未读邮件"),
                            ('(UNSEEN)', "所有未读邮件"),
                            ('(FROM "noreply@cursor.com")', "所有来自cursor.com的邮件")
                        ])
                    else:
                        # 没有注册邮箱时的默认策略
                        search_strategies.extend([
                            ('(UNSEEN FROM "noreply@cursor.com")', "来自cursor.com的未读邮件"),
                            ('(FROM "noreply@cursor.com")', "所有来自cursor.com的邮件"),
                            ('(UNSEEN SUBJECT "Verify your email")', "主题含Verify your email的未读邮件"),
                            ('(UNSEEN SUBJECT "verification")', "主题含verification的未读邮件"),
                            ('(UNSEEN)', "所有未读邮件")
                        ])
                    
                    # 尝试各种搜索策略
                    for search_criteria, strategy_desc in search_strategies:
                        try:
                            status, results = self.mail.search(None, search_criteria)
                            if status == "OK" and results[0]:
                                temp_ids = results[0].split()
                                if temp_ids:
                                    email_ids = temp_ids
                                    used_strategy = strategy_desc
                                    logger.debug(f"使用搜索策略: {strategy_desc}")
                                    break
                        except Exception as e:
                            logger.debug(f"搜索策略 '{strategy_desc}' 出错: {str(e)}")
                            continue
                
                if not email_ids:
                    logger.debug(f"未找到任何邮件，等待{check_interval}秒后重试...")
                    time.sleep(check_interval)
                    continue
                
                logger.debug(f"找到 {len(email_ids)} 封待处理邮件 ({used_strategy})")
                
                # 处理邮件，从最新的开始（列表末尾）
                found_emails = []
                
                print(email_ids)
                # 倒序处理邮件（从最新的开始）
                for email_id in reversed(email_ids):
                    try:
                        # 获取邮件内容
                        status, msg_data = self.mail.fetch(email_id, '(RFC822)')
                        if status != "OK":
                            logger.error(f"获取邮件ID {email_id} 内容失败")
                            continue
                        
                        # 解析邮件内容
                        msg = email.message_from_bytes(msg_data[0][1])
                        
                        # 获取发件人
                        from_addr = msg.get("From", "")
                        logger.debug(f"检查邮件: 来自 {from_addr}")
                        
                        # 获取主题
                        subject = decode_header(msg.get("Subject", ""))[0][0]
                        if isinstance(subject, bytes):
                            subject = subject.decode()
                        logger.debug(f"邮件主题: {subject}")
                        
                        # 获取接收日期
                        date_str = msg.get("Date", "")
                        logger.debug(f"邮件日期: {date_str}")
                        
                        # 获取邮件正文
                        body = ""
                        if msg.is_multipart():
                            for part in msg.walk():
                                content_type = part.get_content_type()
                                content_disposition = str(part.get("Content-Disposition"))
                                
                                # 跳过附件
                                if "attachment" in content_disposition:
                                    continue
                                    
                                if content_type == "text/plain" or content_type == "text/html":
                                    try:
                                        payload = part.get_payload(decode=True)
                                        if payload:
                                            charset = part.get_content_charset()
                                            if charset:
                                                body += payload.decode(charset, errors='replace')
                                            else:
                                                body += payload.decode(errors='replace')
                                    except Exception as e:
                                        logger.error(f"解析邮件部分时出错: {str(e)}")
                        else:
                            try:
                                payload = msg.get_payload(decode=True)
                                if payload:
                                    charset = msg.get_content_charset()
                                    if charset:
                                        body = payload.decode(charset, errors='replace')
                                    else:
                                        body = payload.decode(errors='replace')
                            except Exception as e:
                                logger.error(f"解析邮件正文时出错: {str(e)}")
                        
                        # 输出邮件内容以便调试
                        logger.debug(f"邮件内容长度: {len(body)} 字符")
                        if len(body) > 0:
                            logger.debug(f"邮件内容前200字符: {body[:200]}")
                        
                        # 如果指定了注册邮箱，则检查邮件内容中是否包含该邮箱
                        is_relevant_email = True
                        if registration_email:
                            # 拆分邮箱用户名，用于更灵活的匹配
                            email_username = registration_email.split('@')[0] if '@' in registration_email else registration_email
                            
                            # 检查邮件内容中是否包含注册邮箱
                            if registration_email not in body and email_username not in body:
                                logger.debug(f"邮件内容不包含注册邮箱 {registration_email}，跳过")
                                is_relevant_email = False
                            else:
                                logger.debug(f"找到包含注册邮箱 {registration_email} 的邮件")
                        
                        # 检查是否是Cursor邮件
                        is_cursor_email = "noreply@cursor.com" in from_addr.lower() or (
                            "cursor" in subject.lower() or 
                            "verification" in subject.lower() or 
                            "verify" in subject.lower()
                        )
                        
                        # 增加更多日志，帮助诊断处理过程
                        logger.debug(f"邮件匹配结果: 相关性={is_relevant_email}, Cursor相关={is_cursor_email}")
                        
                        # 只处理相关邮件
                        if is_relevant_email and (is_cursor_email or "verify" in body.lower() or "验证" in body):
                            logger.debug("开始提取验证码...")
                            # 提取验证码
                            verification_code = self.extract_verification_code(body)
                            if verification_code:
                                # 将当前邮件加入候选列表
                                found_emails.append({
                                    'id': email_id,
                                    'date': date_str,
                                    'code': verification_code,
                                    'body': body[:200]  # 只保存前200字符用于日志
                                })
                                logger.debug(f"已将验证码 {verification_code} 添加到候选列表")
                            else:
                                logger.debug("此邮件未能提取到验证码")
                        else:
                            logger.debug("此邮件不符合处理条件，跳过")
                    except Exception as e:
                        logger.error(f"处理邮件ID {email_id} 时出错: {str(e)}")
                
                # 如果找到了多个验证码邮件，优先使用最新的
                if found_emails:
                    logger.debug(f"找到 {len(found_emails)} 封包含验证码的邮件")
                    # 简单处理：使用最新的验证码（即最后处理的邮件）
                    latest_email = found_emails[-1]
                    email_id = latest_email['id']
                    verification_code = latest_email['code']
                    
                    # 将邮件标记为已读
                    try:
                        self.mail.store(email_id, '+FLAGS', '\\Seen')
                        logger.debug(f"将邮件标记为已读")
                    except Exception as e:
                        logger.error(f"标记邮件为已读时出错: {str(e)}")
                        # 继续处理，不因为标记失败而中断
                        
                    logger.info(f"成功提取Cursor验证码: {verification_code}")
                    return verification_code
                else:
                    logger.debug("未找到包含验证码的邮件")
                
                logger.debug(f"未找到Cursor验证码邮件，等待{check_interval}秒后重试...")
                time.sleep(check_interval)
            
            except Exception as e:
                logger.error(f"处理邮件时发生错误: {str(e)}")
                # 添加堆栈跟踪以便更好地诊断问题
                import traceback
                logger.error(f"错误堆栈: {traceback.format_exc()}")
                time.sleep(check_interval)
        
        logger.error(f"等待超时({wait_time}秒)，未收到或无法解析Cursor验证码邮件")
        return None
    
    def extract_verification_code(self, email_content):
        """从邮件内容中提取验证码"""
        # 记录邮件内容用于调试
        if not email_content:
            logger.debug("邮件内容为空，无法提取验证码")
            return None
            
        logger.debug(f"正在解析邮件内容寻找验证码")
        
        # 尝试不同的正则表达式模式来匹配验证码
        patterns = [
            r'\n\s*(\d{6})\s*\n',                          # 单独一行的6位数字
            r'验证码[：:]?\s*?(\d{6})',                     # 中文格式
            r'verification code[：:]*\s*(\d{6})',          # 英文格式，不区分大小写
            r'code[：:]?\s*?(\d{6})',                      # 简化英文格式
            r'Enter the code below[^0-9]*(\d{6})',        # Cursor邮件格式
            r'<strong>(\d{6})</strong>',                  # HTML格式
            r'<b>(\d{6})</b>',                            # 另一种HTML格式
            r'(\d{6})'                                    # 任何6位数字
        ]
        
        # 为安全起见，限制正则表达式匹配的时间
        import signal
        
        class TimeoutException(Exception):
            pass
            
        def timeout_handler(signum, frame):
            raise TimeoutException("正则表达式匹配超时")
            
        # 设置5秒超时
        try:
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(5)
            
            for pattern in patterns:
                try:
                    match = re.search(pattern, email_content, re.IGNORECASE | re.DOTALL)
                    if match:
                        code = match.group(1)
                        logger.debug(f"使用模式 '{pattern}' 找到验证码: {code}")
                        return code
                except Exception as e:
                    logger.debug(f"使用模式 '{pattern}' 匹配时出错: {str(e)}")
                    continue
                    
            signal.alarm(0)  # 取消超时
        except TimeoutException:
            logger.error("验证码提取超时，跳过复杂正则表达式")
            # 超时后尝试最简单的模式
            try:
                simple_match = re.search(r'(\d{6})', email_content)
                if simple_match:
                    code = simple_match.group(1)
                    logger.debug(f"超时后使用简单模式找到验证码: {code}")
                    return code
            except Exception:
                pass
        except Exception as e:
            logger.error(f"设置超时处理时出错: {str(e)}")
            # 回退到无超时的简单匹配
            try:
                simple_match = re.search(r'(\d{6})', email_content)
                if simple_match:
                    return simple_match.group(1)
            except Exception:
                pass
        finally:
            # 确保取消超时设置
            try:
                signal.alarm(0)
            except:
                pass
        
        logger.debug("未能使用任何模式提取验证码")
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

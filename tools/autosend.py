#!/usr/bin/python3
 
import smtplib
from email.mime.text import MIMEText
from email.header import Header
 
# 第三方 SMTP 服务
mail_host="smtp.hyahm.com"  #设置服务器
mail_user="cander@hyahm.com"    #用户名
mail_pass="12345678"   #口令 
 
 
sender = 'cander@hyahm.com'
receivers = ['727023460@qq.com']  # 接收邮件，可设置为你的QQ邮箱或者其他邮箱
 
message = MIMEText('我这边看不到你发给我的信息， 只能看到我发给你的', 'plain', 'utf-8')
message['From'] = Header(sender)
message['To'] =  Header(receivers[0])
  
subject = '我这边看不到你发给我的信息'
message['Subject'] = Header(subject)
 
 
try:
    # smtpObj = smtplib.SMTP() 
    smtpObj = smtplib.SMTP_SSL(mail_host, 465)
    # smtpObj.connect(mail_host, 25)    # 25 为 SMTP 端口号
    # smtpObj.helo()
    # smtpObj.starttls()
    smtpObj.login(mail_user,mail_pass)
    smtpObj.sendmail(sender, receivers, message.as_string())
    print ("邮件发送成功")
except smtplib.SMTPException as e:
    print(e)
    print ("Error: 无法发送邮件")
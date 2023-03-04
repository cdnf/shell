from aliyunsdkcore.client import AcsClient
import  requests
import json
from aliyunsdkalidns.request.v20150109 import UpdateDomainRecordRequest
from aliyunsdkalidns.request.v20150109 import AddDomainRecordRequest
from aliyunsdkalidns.request.v20150109 import DescribeDomainRecordsRequest

# 思路：
# 1、获取本地外网地址
# 2、获取域名解析记录中的RecordID以及IP地址
# 3、更新域名解析记录：如果不存在解析记录则进行新增，如果存在且解析记录中的IP与本地外网IP不一致则进行更新
# 首先安装阿里云提供的python sdk包
# pip3 install aliyun-python-sdk-core
# pip3 install aliyun-python-sdk-alidns
# 加入定时任务定时更新云解析记录
# * * * * *  python3 /home/NodeServer/AutoDevopsScript/update_ddns.py

AccessKey_ID = "LTAI4GEQMxxxxxxxx" # 需要根据实际填写
AccessKey_Secret = "HmHElvWx2kzR6rxxxxxxxxxxx"  # 需要根据实际填写
Regions = "cn-hangzhou"
Domain_Name = "test.com"

#获取本地公网ip地址
def get_internet_ip():
    with requests.get("http://ip.3322.net") as response:
        ip = response.text
    return ip

#子域名解析记录查询
def get_recordid(client):
    request = DescribeDomainRecordsRequest.DescribeDomainRecordsRequest()
    request.set_accept_format('json')
    request.set_DomainName('csgefei.top')
    response = client.do_action_with_exception(request)
    response = str(response, encoding='utf-8')
    result = json.loads(response)
    print(result)
    record_id = result["DomainRecords"]["Record"][0]["RecordId"]
    return record_id

#获取解析记录中当前ip地址
def get_recordip(client):
    request = DescribeDomainRecordsRequest.DescribeDomainRecordsRequest()
    request.set_accept_format('json')
    request.set_DomainName('azgefei.top')
    response = client.do_action_with_exception(request)
    response = str(response, encoding='utf-8')
    result = json.loads(response)
    record_ip = result["DomainRecords"]["Record"][0]["Value"]
    return record_ip

#新增解析记录
def add_record(client,priority,ttl,record_type,value,rr,domainname):
    request = AddDomainRecordRequest()
    request.set_accept_format('json')
    request.set_Priority(priority)
    request.set_TTL(ttl)
    request.set_Value(value)
    request.set_Type(record_type)
    request.set_RR(rr)
    request.set_DomainName(domainname)
    response = client.do_action_with_exception(request)
    response = str(response, encoding='utf-8')
    relsult = json.loads(response)
    return relsult

# 更新域名解析记录
def update_record(client, priority, ttl, record_type, value, rr, record_id):
    request = UpdateDomainRecordRequest.UpdateDomainRecordRequest()
    request.set_accept_format('json')
    request.set_Priority(priority)
    request.set_TTL(ttl)
    request.set_Value(value)
    request.set_Type(record_type)
    request.set_RR(rr)
    request.set_RecordId(record_id)
    response = client.do_action_with_exception(request)
    response = str(response, encoding='utf-8')
    return response

if __name__ == '__main__':
    client = AcsClient(AccessKey_ID, AccessKey_Secret,Regions)
    record_id = get_recordid(client)
    local_ip = get_internet_ip().strip()
    ddns_ip = get_recordip(client).strip()
    if record_id != "":
        if local_ip == ddns_ip: #判断本地IP与域名解析记录IP是否一致
            print("解析地址未发生变化")
        else:
            print("解析地址已经改变")
            update_record(client,"5","600","A",local_ip,"@",record_id) #地址变化则更新解析记录
    else:
        print("主机解析记录不存在，将添加记录")
        add_record(client,"5","600","A",local_ip,"@","azgefei.top") #解析记录不存在则新增解析记录
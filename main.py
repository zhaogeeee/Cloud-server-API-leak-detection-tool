import pymysql
import boto3
import re
import argparse
import logging

# 日志配置
logging.basicConfig(filename='api_leak_detection.log', level=logging.INFO)

# 数据库连接信息
DB_HOST = 'your_db_host'
DB_USER = 'your_db_username'
DB_PASSWORD = 'your_db_password'
DB_NAME = 'your_db_name'
SQL_QUERY = "SELECT * FROM your_table WHERE api_key IS NOT NULL"


# AWS 访问控制问题检测
def check_aws_access_keys():
    # 初始化 AWS 客户端
    iam = boto3.client('iam')
    # 获取所有 IAM 用户
    response = iam.list_users()
    all_iam_users = response['Users']

    for iam_user in all_iam_users:
        username = iam_user['UserName']
        logging.info(f"Processing AWS user {username}:{iam_user['Arn']}")

        # 检查 IAM 权限和策略
        response = iam.list_attached_user_policies(UserName=username)
        attached_policies = response['AttachedPolicies']
        if len(attached_policies) > 0:
            logging.log("ALERT", f"User {username} has attached the following policies:")
            for policy in attached_policies:
                logging.log("ALERT", f"-- {policy['PolicyName']}")

        response = iam.list_user_policies(UserName=username)
        user_policies = response['PolicyNames']
        if len(user_policies) > 0:
            logging.log("ALERT", f"User {username} has the following inline policies:")
            for policy_name in user_policies:
                logging.log("ALERT", f"-- {policy_name}")

        # 查找访问密钥
        response = iam.list_access_keys(UserName=username)
        access_keys = response['AccessKeyMetadata']
        for key in access_keys:
            access_key_id = key['AccessKeyId']
            logging.log("INFO", f"Processing AWS access key id {access_key_id}")

            # 获取访问密钥的权限
            response = iam.get_access_key_last_used(AccessKeyId=access_key_id)
            last_used = response['AccessKeyLastUsed']
            if last_used is None:
                logging.log("ALERT", f"Access key {access_key_id} has never been used")
            else:
                logging.log("INFO",
                            f"Access key {access_key_id} was last used on {last_used['LastUsedDate'].strftime('%Y-%m-%d %H:%M:%S')}")


# 数据库API密钥泄露检测
def check_database_api_key_leak():
    try:
        # 连接数据库
        db = pymysql.connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)
        cursor = db.cursor()

        # 执行查询
        cursor.execute(SQL_QUERY)

        # 获取查询结果
        results = cursor.fetchall()

        # 检查结果是否存在敏感信息
        for row in results:
            if 'api_key' in row:
                logging.log("ALERT", f"Database API key leak: {row['api_key']}")
                # 在此进行处理，例如发送警报通知等

        # 关闭数据库连接
        cursor.close()
        db.close()

    except pymysql.Error as e:
        logging.error(f"数据库连接错误：{e}")


# 文件硬编码API密钥检测
def check_hardcoded_api_key(file_path):
    # 定义一个存储找到的API密钥的列表
    leaked_keys = []
    with open(file_path, "r") as f:
        content = f.read()
    # 查找AWS访问密钥和Azure访问令牌
    matches = re.findall(r"\b(?:AWS|aws_access_key_id|aws_secret_access_key)=[A-Za-z0-9/+=]{40}\b", content)
    for match in matches:
        leaked_keys.append(match)
    matches = re.findall(r"\b[A-Za-z0-9_]+\."r"[A-Za-z0-9_]+\."r"[A-Za-z0-9_-]+\b", content)
    for match in matches:
        leaked_keys.append(match)
    # 输出扫描结果
    if len(leaked_keys) > 0:
        logging.log("ALERT", "Hardcoded API keys found in log file: {}".format(file_path))
        for key in leaked_keys:
            logging.log("INFO", key)
    else:
        logging.log("INFO", "No hardcoded API keys were found in the log file: {}".format(file_path))


# 检测日志文件泄露导致的API密钥泄露
def check_log_file_leak(file_path):
    # 定义一个存储找到的API密钥的列表
    leaked_keys = []
    with open(file_path, "r") as f:
        content = f.read()
    # 查找敏感信息
    matches = re.findall(r"(?:access_key|api_key|secret_key|token)\b.{10,}\b", content, re.IGNORECASE)
    if matches:
        logging.log("ALERT", "Sensitive information leaked in log file: {}".format(file_path))
        for match in matches:
            leaked_keys.append(match)
            logging.log("INFO", match)
    else:
        logging.log("INFO", "No sensitive information leaked in the log file: {}".format(file_path))


# 主函数
def main():
    parser = argparse.ArgumentParser(description="API泄露检测工具")

    # 添加命令行参数
    parser.add_argument("-aws", action="store_true", help="执行AWS访问密钥检测")
    parser.add_argument("-db", action="store_true", help="执行数据库API密钥泄露检测")
    parser.add_argument("-file", metavar="FILE_PATH", help="执行文件硬编码API密钥检测，指定要检测的文件路径")
    parser.add_argument("-log", metavar="LOG_FILE_PATH",
                        help="检测日志文件泄露导致的API密钥泄露，指定要检测的日志文件路径")

    args = parser.parse_args()

    if args.aws:
        check_aws_access_keys()
    if args.db:
        check_database_api_key_leak()
    if args.file:
        check_hardcoded_api_key(args.file)
    if args.log:
        check_log_file_leak(args.log)


# 文件读取接口
def process_file():
    file_path = input("请输入要检测的文件路径: ")
    check_hardcoded_api_key(file_path)


if __name__ == "__main__":
    main()

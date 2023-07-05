# 可以在命令行中使用以下选项运行脚本：
**新手练手文件 不保证可用性**
```
-aws：执行AWS访问密钥检测
```
```
-db：执行数据库API密钥泄露检测
```
```
-file FILE_PATH：执行文件硬编码API密钥检测，其中FILE_PATH是要检测的文件路径
```
```
-log LOG_FILE_PATH：检测日志文件泄露导致的API密钥泄露，其中LOG_FILE_PATH是要检测的日志文件路径
```
```
-h：查看所有命令帮助信息
```
```
例如，要执行AWS访问密钥检测，可以运行以下命令：
```python
python script.py -aws
```
要同时执行数据库API密钥泄露检测和文件硬编码API密钥检测，可以运行以下命令：
```python
python script.py -db -file FILE_PATH
```
请确保将your_db_host，your_db_username，your_db_password和your_db_name替换为实际的数据库连接信息。

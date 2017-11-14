# analysis
some script for  flow analysis

### 0x1 gather_user_pwd_sqlite.py
- gather_user_pwd_sqlite.py适用于在运行抓取镜像的设备上，主要通过流量分析的方式审计管理弱口令，并将抓取到的数据存储到sqlite里，more是info.db文件。

- 修改配置 <br>
  - 首先获取一份内网互联网出口路由器的配置或者互联网地址映射表（net.txt）放在同目录下，这里以华为的配置为例写的脚本,如果是其他设备做互联网映射，需要修改get_inside_ip函数<br>
   _file = os.path.abspath(os.path.dirname(__file__))+os.sep+'net.txt' 改成你的映射表文件名字<br>
  - 根据实际需要定制list里面的user和password字段
 
 - 基本用法 <br>
python gather_user_pwd_sqlite.py

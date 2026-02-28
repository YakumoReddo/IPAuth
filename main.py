"""项目启动入口。"""

from ipauth.server import run


if __name__ == "__main__":
    # 启动 HTTP 服务（会自动初始化数据库）。
    run()

"""在本机首次创建安全工作台管理员，不通过网络传输初始密码。"""

import getpass
import re
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
load_dotenv(ROOT / ".env")

from security.auth import hash_password  # noqa: E402
from security.repository import create_user, user_count  # noqa: E402


def main() -> None:
    if user_count():
        raise SystemExit("安全账号已存在；请登录后由管理员在用户管理页面创建账号。")
    username = input("管理员用户名：").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
        raise SystemExit("用户名需为 3～64 位英文字母、数字、点、下划线或连字符。")
    password = getpass.getpass("管理员密码（至少 12 位）：")
    repeat = getpass.getpass("再次输入密码：")
    if password != repeat:
        raise SystemExit("两次密码不一致。")
    try:
        password_hash = hash_password(password)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    create_user(username, password_hash, "ADMIN")
    print(f"已创建管理员 {username}，现在可以在安全工作台登录。")


if __name__ == "__main__":
    main()

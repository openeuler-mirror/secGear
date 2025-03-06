import functools
import re
import base64
import json
from pathlib import Path

import jwt
import requests
from flask import Flask, request, make_response

app = Flask(__name__)

TEE = "tee"
U8 = 10
HTTP_STATUS_FAILURE = 504

COOKIES_OR_TOKEN_ERROR = "Cookies or Token error"
HEADER = {"Content-Type": "application/json"}
SUFFIX_REGO = ".rego"
SUFFIX_TXT = ".txt"

# 文件名规则：字母/数字/下划线开头，可包含连字符，长度至少1个字符
_filename_re = re.compile(r'^[a-zA-Z0-9_][a-zA-Z0-9_-]*$')  # 已整合"-"开头校验

# 相对路径规则：非绝对路径，禁止.或..组件，支持多级目录
_relative_path_re = re.compile(
    r'''
    ^
    (?!\.$|\.\.$)               # 排除单组件.或..
    (?!.*/\.$|.*/\.\.$)         # 排除路径中的./或../
    (?!.*//)                    # 禁止空目录名（连续斜杠）
    [^/\0]                      # 首字符非斜杠且非空字符
    (?:                         # 目录结构部分
        /                       # 目录分隔符
        (?![._-])               # 禁止目录名以._-开头（可选）
        [^/\0\\]+               # 目录名合法字符（按需调整）
    )*$
    ''',
    re.VERBOSE
)
_error_pattern = re.compile(
    r'\b\w+Error\(\s*"((?:[^"\\]|\\.)*)"\s*\)',  # 匹配任意XXXError("...")结构
    flags=re.DOTALL  # 允许.匹配换行符
)

# openeuler认证服务URL
AUTH_URL = "https://id.openeuler.org/oneid/user/permission"

# secGear框架地址
SECGEAR_URL = "http://127.0.0.1:8080"

# 后端接口、资源接口、资源策略接口、基线接口、证明策略接口
RESOURCE_API = "/resource/storage"
RESOURCE_POLICY_API = "/resource/policy"
REFERENCE_API = "/reference"
POLICY_API = "/policy"

# API调用接口
CHALLENGE_API = "/challenge"
ATTESTATION_API = "/attestation"

# 拼接
RESOURCE_URL = SECGEAR_URL + RESOURCE_API
RESOURCE_POLICY_URL = SECGEAR_URL + RESOURCE_POLICY_API
REFERENCE_URL = SECGEAR_URL + REFERENCE_API
POLICY_URL = SECGEAR_URL + POLICY_API
CHALLENGE_URL = SECGEAR_URL + CHALLENGE_API
ATTESTATION_URL = SECGEAR_URL + ATTESTATION_API


def urlsafe_base64_encode(s) -> str:
    """
    将输入字符串s进行URL安全的base64编码，并去除末尾的填充字符'='。

    参数:
    s (str): 需要编码的原始字符串。

    返回:
    str: URL安全的base64编码后的字符串，且不包含末尾的填充字符。
    """
    # 将字符串s转换为utf-8编码的字节串
    byte_str = s.encode('utf-8')
    # 对字节串进行URL安全的base64编码
    encoded_str = base64.urlsafe_b64encode(byte_str)
    # 将编码后的字节串解码为字符串，并去除末尾的填充字符'='
    encoded_str = encoded_str.decode('utf-8').rstrip('=')
    # 返回处理后的编码字符串
    return encoded_str


def urlsafe_base64_decode(s) -> str:
    """
    将输入字符串s进行填充字符'='，然后base64解码。

    参数:
    s (str): 需要解码的原始字符串。

    返回:
    str: URL安全的base64解码后的字符串。
    """
    if "{" in s or "(" in s or ":" in s:
        return s
    # 计算需要填充的'='字符数量，以确保字符串长度是4的倍数
    padding = 4 - (len(s) % 4)
    if padding != 0:
        # 如果需要填充，则在字符串末尾添加相应数量的'='字符
        s += '=' * padding
    # 使用urlsafe_b64decode方法解码字符串，然后将其解码为utf-8格式的字符串
    decoded_str = base64.urlsafe_b64decode(s).decode('utf-8')
    # 返回解码后的字符串
    return decoded_str


def get_userid(token=None) -> str:
    """
    从请求头中获取用户ID。该函数尝试从请求头中获取token，
    解码后返回其中的用户ID。如果过程中遇到任何问题，
    将返回一个错误信息。

    返回:
    str: 返回一个用户ID或者错误信息。
    """
    if token is None:
        # 如果没有token，尝试从请求头中获取token
        token = request.headers.get("token")
    # 如果没有token或者没有cookies，则返回错误信息
    if not token or not request.cookies:
        return COOKIES_OR_TOKEN_ERROR

    try:
        # 使用jwt库解码token，这里设置verify_signature为False表示不验证签名
        # 注意：在生产环境中应该验证签名以确保token的安全性
        # 注意：在本函数中只是为了获取用户ID,所以不验证签名，但是在后面代码中会验证token的有效性
        payload = jwt.decode(token, options={"verify_signature": False})
        # 从解码后的payload中获取user_id，如果没有则返回错误信息
        return payload.get("aud", COOKIES_OR_TOKEN_ERROR)
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        # 如果token过期或者无效，则捕获异常并返回错误信息
        return COOKIES_OR_TOKEN_ERROR


def openeuler_auth() -> tuple:
    """
    执行openEuler统一认证，并返回用户ID和响应对象。
    如果认证失败，则返回错误信息和响应对象。
    """
    # 获取用户ID
    user_id = get_userid()
    # 如果用户ID等于COOKIES_OR_TOKEN_ERROR常量，表示认证失败
    if user_id == COOKIES_OR_TOKEN_ERROR:
        # 返回错误信息和响应对象
        return False, make_response(COOKIES_OR_TOKEN_ERROR, HTTP_STATUS_FAILURE)

    # 复制当前请求的头信息为字典
    headers = dict(request.headers)
    # 移除请求头中的"Host"字段，如果不存在则忽略
    headers.pop("Host", None)
    body = {
        "resource": "secgear",
        "actions": ["access"]
    }

    try:
        # 使用requests库向openeuler统一认证发起请求，方法、头信息和请求体与当前请求相同
        response = requests.request(
            method="GET",
            url=AUTH_URL,
            headers=headers,
            json=body,
            verify=False  # 注意：生产环境中应启用SSL验证，这里关闭是为了示例或测试
        )
        if response.status_code == 200:
            try:
                parsed = json.loads(response.text)
                data = parsed["data"]
                has_permission = data["aigcPrivacyAccepted"]
                if has_permission == "":
                    return user_id, response
                else:
                    return False, response_merge(response, "No Permissions", HTTP_STATUS_FAILURE)
            except (KeyError, json.JSONDecodeError):
                return False, response_merge(response, "Parsing Failed", HTTP_STATUS_FAILURE)
        elif response.status_code == 401:
            try:
                parsed = json.loads(response.text)
                status_code = parsed["status"]
                error_type = parsed["error"]
                error_msg = parsed["message"]
                content = f"status_code:{status_code} \n{error_type}:{error_msg}"
                return False, make_response(content, status_code)
            except (KeyError, json.JSONDecodeError):
                content = f"{response.status_code} and Parsing Failed"
                return False, make_response(content, response.status_code)
        else:
            # 如果响应的状态码不是200和401，将抛出HTTPError异常
            response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return False, make_response(str(e), response.status_code)
    except Exception as e:
        return False, make_response(str(e))


def secgear_response(sec_data, url, method="POST", header=None):
    """
    向secGear发送请求并处理响应。

    参数:
    sec_data -- 发送给secGear的数据（字典格式）
    url -- secGear服务框架具体接口
    method -- HTTP请求方法，默认为"POST"
    header -- HTTP请求头，默认为None，使用预定义的HEADER

    返回:
    Flask响应对象，包含secGear的响应内容或错误信息
    """
    # 如果没有提供请求头，则使用预定义的HEADER
    if header is None:
        header = HEADER

    # try:
    # 发送HTTP请求到指定的URL
    response_sec = requests.request(
        method=method,  # 请求方法
        url=url,  # 请求的URL
        headers=header,  # 请求头
        json=sec_data,  # 将数据序列化为JSON字符串发送
        timeout=10  # 设置超时时间为10秒
    )
    if response_sec.status_code in (200, 500):
        return response_sec
    else:
        return "Failed to connect to secGear"


# 定义一个函数，用于合并两个响应对象的头部信息和内容
def response_merge(response_openeuler, response_sec_body, response_sec_code=200):
    response = make_response(response_sec_body, response_sec_code)
    for header, value in response_openeuler.headers.items():
        if header.lower() not in ('content-type', 'content-length', 'transfer-encoding', 'content-encoding'):
            response.headers[header] = value
    return response


def judge_filename(filename: str) -> bool:
    """深度校验文件名合法性"""
    return isinstance(filename, str) and bool(_filename_re.fullmatch(filename))


def judge_resource_name(name: str) -> bool:
    """智能校验资源名称，支持两种格式：
    1. 合法文件名（通过文件名正则）
    2. 合法相对路径（通过路径正则且每级目录合法）
    """
    if not isinstance(name, str):
        return False

    # 快速路径：先尝试文件名校验
    if judge_filename(name):
        return True

    # 深度路径校验
    return (
            _relative_path_re.fullmatch(name) is not None
            and all(judge_filename(part) for part in name.split('/'))
    )


# 定义一个函数用于上传文件
def upload_file(suffix) -> tuple:
    # 从请求中获取文件对象，如果没有文件则默认为False
    file = request.files.get('file', False)

    # 检查是否有文件以及文件名是否存在
    if not file or not file.filename:
        # 如果没有选择文件，返回失败响应
        return False, "No selected file"
    # 使用Path库获取文件路径信息
    filepath = Path(file.filename)
    filename = filepath.stem
    if not judge_filename(filename) or filepath.suffix != suffix:
        return False, "Invalid filename"
    try:
        # 尝试读取文件内容
        content_bytes = file.read()
        content = content_bytes.decode("utf-8")
        if content == "":
            # 如果文件内容为空，返回失败响应
            return False, "Empty file"
        # 如果一切正常，返回文件名、后缀和内容
        return filename, content
    except Exception as e:
        # 如果读取文件失败，返回失败响应
        return False, f"Failed to read file: {str(e)}"


def authenticated_route(func):
    """装饰器用于封装认证逻辑"""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        user_id, resp_openeuler = openeuler_auth()
        if not user_id:
            return resp_openeuler
        return func(user_id, resp_openeuler, *args, **kwargs)

    return wrapper


# 资源--------------------------------------------------------------------------------------------
@app.route("/resource/storage/all", methods=["GET"])
@authenticated_route
def get_res_list(user_id, resp_openeuler):
    # 构造secGear框架请求体
    sec_data = {"VendorGet": {"vendor": user_id}}
    # 获取资源清单。向secGear框架对应接口发送请求，获取框架响应的响应体和状态码
    resp_sec = secgear_response(sec_data, RESOURCE_URL, "GET")
    if isinstance(resp_sec, str):
        return response_merge(resp_openeuler, resp_sec, HTTP_STATUS_FAILURE)
    return response_merge(resp_openeuler, resp_sec.text, resp_sec.status_code)


@app.route("/resource/storage", methods=["POST"])
@authenticated_route
def add_res(user_id, resp_openeuler):
    # 获取请求参数
    resource_content = request.form.get("resource_content")
    policy_name = request.form.get("policy_name", "")
    resource_name = request.form.get("resource_name")
    if policy_name != "":
        if not judge_filename(policy_name):
            return response_merge(resp_openeuler, "Invalid parameters", HTTP_STATUS_FAILURE)
    # 检查参数是否合法
    if not resource_content or not judge_resource_name(resource_name):
        return response_merge(resp_openeuler, "Invalid parameters", HTTP_STATUS_FAILURE)

    # 删除原有资源（返回成功失败均可），向secGear框架对应接口发送请求，获取框架响应的响应体和状态码
    sec_del = {"op": "Delete", "resource": {"vendor": user_id, "path": resource_name}}
    secgear_response(sec_del, RESOURCE_URL)

    # 添加新资源，向secGear框架对应接口发送请求，获取框架响应的响应体和状态码
    sec_data = {"op": {"Add": {"content": resource_content, "policy": [policy_name]}},
                "resource": {"vendor": user_id, "path": resource_name}}
    resp_sec = secgear_response(sec_data, RESOURCE_URL)
    if isinstance(resp_sec, str):
        return response_merge(resp_openeuler, resp_sec, HTTP_STATUS_FAILURE)
    return response_merge(resp_openeuler, resp_sec.text, resp_sec.status_code)


@app.route("/resource/storage", methods=["DELETE"])
@authenticated_route
def delete_res(user_id, resp_openeuler):
    # 获取请求参数
    resource_name = request.form.get("resource_name")
    # 检查参数是否合法
    if not judge_resource_name(resource_name):
        return response_merge(resp_openeuler, "Invalid resource name", HTTP_STATUS_FAILURE)

    # 删除资源，向secGear框架对应接口发送请求，获取框架响应的响应体和状态码
    sec_data = {"op": "Delete", "resource": {"vendor": user_id, "path": resource_name}}
    resp_sec = secgear_response(sec_data, RESOURCE_URL)
    if isinstance(resp_sec, str):
        return response_merge(resp_openeuler, resp_sec, HTTP_STATUS_FAILURE)
    return response_merge(resp_openeuler, resp_sec.text, resp_sec.status_code)


# 资源策略--------------------------------------------------------------------------------------------
@app.route("/resource/policy/all", methods=["GET"])
@authenticated_route
def get_policy_list(user_id, resp_openeuler):
    # 获取资源策略清单，向secGear框架对应接口发送请求，获取框架响应的响应体和状态码
    sec_data = {"GetAllInVendor": {"vendor": user_id}}
    resp_sec = secgear_response(sec_data, RESOURCE_POLICY_URL, "GET")
    if isinstance(resp_sec, str):
        return response_merge(resp_openeuler, resp_sec, HTTP_STATUS_FAILURE)
    return response_merge(resp_openeuler, resp_sec.text, resp_sec.status_code)


@app.route("/resource/policy", methods=["POST"])
@authenticated_route
def add_res_policy(user_id, resp_openeuler):
    # 获取请求参数
    filename, content = upload_file(SUFFIX_REGO)
    # 检查参数是否合法
    if filename is False:
        return response_merge(resp_openeuler, content, HTTP_STATUS_FAILURE)
    # 构造标准策略名
    policy_name = filename + SUFFIX_REGO

    # 添加资源策略，向secGear框架对应接口发送请求，获取框架响应的响应体和状态码
    sec_data = {"Add": {"policy": {"vendor": user_id, "id": policy_name}, "content": content}}
    resp_sec = secgear_response(sec_data, RESOURCE_POLICY_URL)
    if isinstance(resp_sec, str):
        return response_merge(resp_openeuler, resp_sec, HTTP_STATUS_FAILURE)
    return response_merge(resp_openeuler, resp_sec.text, resp_sec.status_code)


@app.route("/resource/policy", methods=["DELETE"])
@authenticated_route
def delete_res_policy(user_id, resp_openeuler):
    # 获取请求参数
    policy_name_get = request.form.get("policy_name")
    # 检查参数是否合法
    if not judge_filename(policy_name_get):
        return response_merge(resp_openeuler, "Resource Policy name is invalid", HTTP_STATUS_FAILURE)
    # 构造标准策略名
    policy_name = policy_name_get + SUFFIX_REGO

    # 删除资源策略，向secGear框架对应接口发送请求，获取框架响应的响应体和状态码
    sec_data = {"Delete": {"policy": {"vendor": user_id, "id": policy_name}}}
    resp_sec = secgear_response(sec_data, RESOURCE_POLICY_URL)
    if isinstance(resp_sec, str):
        return response_merge(resp_openeuler, resp_sec, HTTP_STATUS_FAILURE)
    return response_merge(resp_openeuler, resp_sec.text, resp_sec.status_code)


@app.route("/resource/policy", methods=["GET"])
@authenticated_route
def get_res_policy(user_id, resp_openeuler):
    # 获取请求参数
    policy_name_get = request.args.get("policy_name")
    # 检查参数是否合法
    if not judge_filename(policy_name_get):
        return response_merge(resp_openeuler, "Resource Policy name is invalid", HTTP_STATUS_FAILURE)
    # 构造标准策略名
    policy_name = policy_name_get + SUFFIX_REGO

    sec_data = {"GetOne": {"policy": {"vendor": user_id, "id": policy_name}}}
    resp_sec = secgear_response(sec_data, RESOURCE_POLICY_URL, "GET")
    if isinstance(resp_sec, str):
        return response_merge(resp_openeuler, resp_sec, HTTP_STATUS_FAILURE)
    return response_merge(resp_openeuler, resp_sec.text, resp_sec.status_code)


# 基线--------------------------------------------------------------------------------------------
@app.route("/reference", methods=["POST"])
@authenticated_route
def add_ref(user_id, resp_openeuler):
    filename, content = upload_file(SUFFIX_TXT)
    if filename is False:
        return response_merge(resp_openeuler, content, HTTP_STATUS_FAILURE)

    ref = [line.strip() for line in content.splitlines() if line.strip()]
    ref_name = f"{user_id}_{filename}"
    ref_data = {ref_name: ",".join(ref)}

    sec_data = {"refs": json.dumps(ref_data)}
    resp_sec = secgear_response(sec_data, REFERENCE_URL)
    if isinstance(resp_sec, str):
        return response_merge(resp_openeuler, resp_sec, HTTP_STATUS_FAILURE)
    return response_merge(resp_openeuler, resp_sec.text, resp_sec.status_code)


# 证明策略--------------------------------------------------------------------------------------------
@app.route("/policy", methods=["POST"])
@authenticated_route
def add_policy(user_id, resp_openeuler):
    filename, content = upload_file(SUFFIX_REGO)
    if filename is False:
        return response_merge(resp_openeuler, content, HTTP_STATUS_FAILURE)

    policy_name = f"{user_id}_{filename}{SUFFIX_REGO}"
    content_base64 = urlsafe_base64_encode(content)

    sec_data = {"tee": TEE, "id": policy_name, "policy": content_base64}
    resp_sec = secgear_response(sec_data, POLICY_URL)
    if isinstance(resp_sec, str):
        return response_merge(resp_openeuler, resp_sec, HTTP_STATUS_FAILURE)
    return response_merge(resp_openeuler, resp_sec.text, resp_sec.status_code)


@app.route("/policy", methods=["GET"])
@authenticated_route
def get_policy(user_id, resp_openeuler):
    policy_name_get = request.args.get("policy_name")
    if not judge_filename(policy_name_get):
        return response_merge(resp_openeuler, "Policy name is invalid", HTTP_STATUS_FAILURE)
    policy_name = f"{user_id}_{policy_name_get}{SUFFIX_REGO}"

    sec_data = {"policy_id": policy_name}
    resp_sec = secgear_response(sec_data, POLICY_URL, "GET")
    if isinstance(resp_sec, str):
        return response_merge(resp_openeuler, resp_sec, HTTP_STATUS_FAILURE)
    resp_sec_data = urlsafe_base64_decode(resp_sec.text)
    return response_merge(resp_openeuler, resp_sec_data, resp_sec.status_code)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

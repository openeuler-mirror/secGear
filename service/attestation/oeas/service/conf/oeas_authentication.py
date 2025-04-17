from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Tuple, Union, Dict, Any, Optional
import base64
import functools
import json
import logging
import re

from flask import Flask, request, make_response, Response, send_file, abort
import jwt
import requests
import toml

# 配置日志
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# 限制最大上传文件大小为100KB
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024


# 常量定义
class Constants:
    # TEE、U8为保留字
    TEE = "tee"
    U8 = 10

    # HTTP
    AUTH_FAILURE_CODE = 401
    HTTP_STATUS_FAILURE = 400
    HTTP_STATUS_SUCCESS = 200
    HEADER = {"Content-Type": "application/json"}

    # 解析认证token
    userid_tag = "sub"
    user_permission = "hasPermission"

    # 错误消息
    AUTH_REQUEST_ERROR = "Auth Request Error"
    COOKIES_OR_TOKEN_ERROR = "Cookies or Token Error"
    EMPTY_CONTENT = "Content Empty"
    FILE_FORMAT_ERROR = "File Content Format Error"
    FILE_READ_ERROR = "File Read Error"
    INVALID_FILENAME = "Invalid Filename"
    INVALID_PARAMETERS = "Invalid Parameters"
    INVALID_POLICY_NAME = "Invalid Policy Name"
    INVALID_RESOURCE_NAME = "Invalid Resource Name"
    INVALID_TOKEN = "Invalid Token"
    NO_PERMISSION = "No Permission"
    NO_SELECTED_FILE = "No Selected File"
    PARSE_ERROR = "Parse Error"
    SECGEAR_CONNECT_ERROR = "SecGear Connect Error"

    # 文件后缀
    SUFFIX_REGO = ".rego"
    SUFFIX_JSON = ".json"

    # API路径
    ATTESTATION_API = "/attestation"
    CHALLENGE_API = "/challenge"
    POLICY_API = "/policy"
    REFERENCE_API = "/reference"
    RESOURCE_API = "/resource/storage"
    RESOURCE_POLICY_API = "/resource/policy"

    try:
        config = toml.load("oeas.toml")
        # openeuler认证服务URL
        AUTH_URL = config["openeuler"]["auth_url"]
        TOKEN_URL = config["openeuler"]["token_url"]
        # secGear框架地址
        SECGEAR_URL = config["secgear"]["secgear_as_url"]
    except FileNotFoundError as e:
        logging.critical("Config file not found at: %s", str(e))
        raise
    except toml.TomlDecodeError as e:
        logging.critical("Invalid TOML format: %s", str(e))
        raise
    except KeyError as e:
        logging.critical("Configuration validation failed: %s", str(e))
        raise

    # 完整URLs
    ATTESTATION_URL = f"{SECGEAR_URL}{ATTESTATION_API}"
    CHALLENGE_URL = f"{SECGEAR_URL}{CHALLENGE_API}"
    POLICY_URL = f"{SECGEAR_URL}{POLICY_API}"
    REFERENCE_URL = f"{SECGEAR_URL}{REFERENCE_API}"
    RESOURCE_POLICY_URL = f"{SECGEAR_URL}{RESOURCE_POLICY_API}"
    RESOURCE_URL = f"{SECGEAR_URL}{RESOURCE_API}"


# 正则表达式编译
class Patterns:
    # 文件名规则：字母/数字/下划线开头，可包含连字符，长度至少1个字符
    FILENAME = re.compile(r"^[a-zA-Z0-9_][a-zA-Z0-9_-]*$")

    # 相对路径规则：非绝对路径，禁止.或..组件，支持多级目录
    RELATIVE_PATH = re.compile(
        r"""
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
        """,
        re.VERBOSE,
    )


class ResponseUtils:
    @staticmethod
    def _set_cookie(
        response_openeuler: requests.models.Response, response: Response
    ) -> Response:
        """处理Cookie"""
        cookie_strings = response_openeuler.headers.get("Set-Cookie", "").split(",")
        cookie_ut = cookie_yg = None
        for index, cookie_string in enumerate(cookie_strings):
            if "_Y_G_" in cookie_string:
                cookie_yg = cookie_string
            if "_U_T_" in cookie_string:
                cookie_ut = f"{cookie_string},{cookie_strings[index + 1]}"

        if cookie_yg is None or cookie_ut is None:
            return response

        """Set-Cookie"""
        for cookie_str in (cookie_yg, cookie_ut):
            cookie = SimpleCookie()
            try:
                cookie.load(cookie_str)
            except Exception as e:
                logger.error(f"Cookie解析失败: {cookie_str} | 错误: {e}")
                return response

            for key in cookie:

                # 构造参数（保持原有逻辑）
                item = cookie[key]
                cookie_args = {
                    "key": key,
                    "value": item.value,
                    "domain": item.get("domain"),
                    "path": "/",
                    "secure": True,
                    "httponly": key == "_Y_G_",
                    "samesite": "Lax",
                }

                # 处理时间参数（保持原有逻辑）
                if "max-age" in item:
                    try:
                        cookie_args["max_age"] = int(item["max-age"])
                    except (ValueError, TypeError) as e:
                        logging.debug("Invalid max-age value: %s", e)

                if "expires" in item:
                    try:
                        cookie_args["expires"] = parsedate_to_datetime(item["expires"])
                    except (ValueError, TypeError) as e:
                        logging.debug("Invalid expires value: %s", e)

                response.set_cookie(
                    **{
                        k: v
                        for k, v in cookie_args.items()
                        if v or k in ("secure", "httponly")
                    }
                )
        return response

    @staticmethod
    def get_userid(token: Optional[str] = None) -> str:
        """从请求头获取用户ID"""
        if token is None:
            token = request.headers.get("token")

        if not token or not request.cookies:
            return Constants.COOKIES_OR_TOKEN_ERROR

        try:
            # 使用jwt库解码token，这里设置verify_signature为False表示不验证签名
            # 注意：在生产环境中应该验证签名以确保token的安全性
            # 注意：在本函数中只是为了获取用户ID,所以不验证签名，但是在后面代码中会验证token的有效性
            payload = jwt.decode(token, options={"verify_signature": False})
            return payload.get(Constants.userid_tag, Constants.COOKIES_OR_TOKEN_ERROR)
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
            logger.error(f"Token解析失败: {str(e)}")
            return Constants.COOKIES_OR_TOKEN_ERROR

    @staticmethod
    def response_merge(
        response_openeuler: Union[str, requests.models.Response],
        response_sec_body: Union[str, requests.models.Response],
        response_sec_code: Optional[int] = None,
    ) -> Response:
        if isinstance(response_openeuler, str):
            return make_response(response_openeuler, Constants.HTTP_STATUS_FAILURE)

        session_id = ""
        if isinstance(response_sec_body, requests.models.Response):
            session_id = response_sec_body.headers.get("Set-Cookie", "")
            response_sec_code = response_sec_body.status_code
            response_sec_body = response_sec_body.text
        elif response_sec_code is None:
            response_sec_code = Constants.HTTP_STATUS_FAILURE

        response = make_response(response_sec_body, response_sec_code)

        # Set-Cookie
        if session_id:
            response.headers["Set-Cookie"] = session_id
        else:
            response = ResponseUtils._set_cookie(response_openeuler, response)

        # 复制其他headers
        excluded_headers = (
            "content-type",
            "content-length",
            "transfer-encoding",
            "content-encoding",
            "set-cookie",
        )
        for header, value in response_openeuler.headers.items():
            if header.lower() not in excluded_headers:
                response.headers[header] = value

        return response

    @staticmethod
    def openeuler_auth() -> (
        Tuple[Union[str, bool], Union[Response, requests.models.Response]]
    ):
        """执行openEuler统一认证"""
        user_id = ResponseUtils.get_userid()
        if user_id == Constants.COOKIES_OR_TOKEN_ERROR:
            return False, make_response(
                Constants.COOKIES_OR_TOKEN_ERROR, Constants.AUTH_FAILURE_CODE
            )

        headers = {}
        headers_need = ("Cookie", "Token", "Referer")
        for key in headers_need:
            headers[key] = request.headers.get(key)
        body = {"resource": "secgear", "actions": ["access"]}

        try:
            response = requests.request(
                method="POST", url=Constants.AUTH_URL, headers=headers, json=body
            )
            if response.status_code == 200:
                try:
                    parsed = json.loads(response.text)
                    has_permission = parsed["data"][Constants.user_permission]
                    if has_permission == True:
                        return user_id, response
                    else:
                        response.status_code = Constants.AUTH_FAILURE_CODE
                        return False, ResponseUtils.response_merge(
                            response, Constants.NO_PERMISSION
                        )
                except (KeyError, json.JSONDecodeError):
                    return False, ResponseUtils.response_merge(
                        response, Constants.PARSE_ERROR
                    )
            elif response.status_code == 401:
                try:
                    parsed = json.loads(response.text)
                    status_code = parsed["status"]
                    error_type = parsed["error"]
                    error_msg = parsed["message"]
                    content = f"status_code:{status_code} \n{error_type}:{error_msg}"
                    return False, make_response(content, status_code)
                except (KeyError, json.JSONDecodeError):
                    return False, make_response(
                        Constants.PARSE_ERROR, Constants.AUTH_FAILURE_CODE
                    )
            else:
                response.raise_for_status()
                return False, make_response(response.text, Constants.AUTH_FAILURE_CODE)
        except requests.exceptions.RequestException as e:
            logger.error(f"openEuler认证请求失败 | 错误: {e}")
            return False, make_response(
                Constants.AUTH_REQUEST_ERROR, Constants.AUTH_FAILURE_CODE
            )
        except Exception as e:
            logger.error(f"openEuler认证请求失败 | 错误: {e}")
            return False, make_response(
                Constants.AUTH_REQUEST_ERROR, Constants.AUTH_FAILURE_CODE
            )

    @staticmethod
    def check_token(token: str, url: str) -> str:
        if token == "":
            return ""
        send_data = {"url": url}
        header = {"token": token}
        response = requests.post(
            Constants.TOKEN_URL, json=send_data, headers=header, verify=False
        )
        if response.status_code == 200:
            try:
                user_id = response.json()["data"]["userId"]
                return user_id
            except Exception as e:
                logger.error(f"解析失败: {str(e)}")
                return ""
        return ""

    @staticmethod
    def secgear_response(
        sec_data: Dict[str, Any],
        url: str,
        method: str = "POST",
        header: Optional[Dict[str, str]] = None,
    ) -> Union[str, requests.models.Response]:
        """向secGear发送请求"""
        if header is None:
            header = Constants.HEADER

        try:
            response = requests.request(
                method=method, url=url, headers=header, json=sec_data, timeout=10
            )

            if response.status_code in (200, 500):
                return response
            return Constants.SECGEAR_CONNECT_ERROR
        except requests.exceptions.RequestException as e:
            logger.error(f"secGear请求失败: {str(e)}")
            return Constants.SECGEAR_CONNECT_ERROR


class FileUtils:
    @staticmethod
    def judge_filename(filename: str) -> bool:
        """验证文件名合法性"""
        return isinstance(filename, str) and bool(Patterns.FILENAME.fullmatch(filename))

    @staticmethod
    def judge_resource_name(name: str) -> bool:
        """验证资源名称合法性"""
        if not isinstance(name, str):
            return False

        if FileUtils.judge_filename(name):
            return True

        return Patterns.RELATIVE_PATH.fullmatch(name) is not None and all(
            FileUtils.judge_filename(part) for part in name.split("/")
        )

    @staticmethod
    def upload_file(suffix: str) -> Tuple[Union[bool, str], str]:
        """处理文件上传"""
        file = request.files.get("file")
        if not file or not file.filename:
            return False, Constants.NO_SELECTED_FILE

        filepath = Path(file.filename)
        filename = filepath.stem

        if not FileUtils.judge_filename(filename) or filepath.suffix != suffix:
            return False, Constants.INVALID_FILENAME

        try:
            content = file.read().decode("utf-8")
            if not content:
                return False, Constants.EMPTY_CONTENT
            return filename, content
        except Exception as e:
            logger.error(f"文件读取失败: {str(e)}")
            return False, Constants.FILE_READ_ERROR

    @staticmethod
    def urlsafe_base64_encode(s: str) -> str:
        """将输入字符串进行URL安全的base64编码"""
        try:
            byte_str = s.encode("utf-8")
            encoded_str = base64.urlsafe_b64encode(byte_str)
            return encoded_str.decode("utf-8").rstrip("=")
        except Exception as e:
            logger.error(f"Base64编码失败: {str(e)}")
            raise

    @staticmethod
    def urlsafe_base64_decode(s: str) -> str:
        """将输入字符串进行base64解码"""
        if any(char in s for char in "{(:"):
            return s

        try:
            padding = 4 - (len(s) % 4)
            if padding != 4:
                s += "=" * padding
            return base64.urlsafe_b64decode(s).decode("utf-8")
        except Exception as e:
            logger.error(f"Base64解码失败: {str(e)}")
            raise


def token_route(func):
    """token认证装饰器"""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        openeuler_token = request.headers.get("token", "")
        user_id = ResponseUtils.check_token(openeuler_token, request.path)
        if not user_id:
            return make_response(Constants.INVALID_TOKEN, Constants.HTTP_STATUS_FAILURE)
        return func(user_id, *args, **kwargs)

    return wrapper


def authenticated_route(func):
    """cookie认证装饰器"""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        user_id, resp_openeuler = ResponseUtils.openeuler_auth()
        if not user_id:
            return resp_openeuler
        return func(user_id, resp_openeuler, *args, **kwargs)

    return wrapper


# API路由定义
# 资源--------------------------------------------------------------------------------------------
@app.route("/oeas-web/resource/storage/all", methods=["GET"])
@authenticated_route
def get_res_list(user_id: str, resp_openeuler: requests.models.Response) -> Response:
    """获取资源列表"""
    sec_data = {"VendorGet": {"vendor": user_id}}
    resp_sec = ResponseUtils.secgear_response(sec_data, Constants.RESOURCE_URL, "GET")

    return ResponseUtils.response_merge(resp_openeuler, resp_sec)


@app.route("/oeas-web/resource/storage", methods=["POST"])
@authenticated_route
def add_res(user_id: str, resp_openeuler: requests.models.Response) -> Response:
    """添加资源"""
    resource_content = request.form.get("resource_content", "")
    policy = request.form.get("policy_name", "")
    resource_name = request.form.get("resource_name", "")

    if not resource_content or not FileUtils.judge_resource_name(resource_name):
        return ResponseUtils.response_merge(
            resp_openeuler,
            f"{Constants.INVALID_RESOURCE_NAME} or {Constants.EMPTY_CONTENT}",
        )

    sec_del = {"op": "Delete", "resource": {"vendor": user_id, "path": resource_name}}
    sec_data = {
        "op": {"Add": {"content": resource_content, "policy": []}},
        "resource": {"vendor": user_id, "path": resource_name},
    }

    if policy:
        policy_list = [item.strip() for item in policy.split(",") if item.strip()]
        invalid_policy_names = [
            policy_name
            for policy_name in policy_list
            if not FileUtils.judge_filename(policy_name)
        ]
        if invalid_policy_names:
            return ResponseUtils.response_merge(
                resp_openeuler, Constants.INVALID_POLICY_NAME
            )
        sec_data["op"]["Add"]["policy"] = [
            f"{user_id}/{policy_name}{Constants.SUFFIX_REGO}"
            for policy_name in policy_list
        ]

    # 删除原有资源并添加新资源
    ResponseUtils.secgear_response(sec_del, Constants.RESOURCE_URL)
    resp_sec = ResponseUtils.secgear_response(sec_data, Constants.RESOURCE_URL)

    return ResponseUtils.response_merge(resp_openeuler, resp_sec)


@app.route("/oeas-web/resource/storage", methods=["DELETE"])
@authenticated_route
def delete_res(user_id: str, resp_openeuler: requests.models.Response) -> Response:
    """删除资源"""
    resource_name = request.form.get("resource_name", "")
    if not FileUtils.judge_resource_name(resource_name):
        return ResponseUtils.response_merge(
            resp_openeuler, Constants.INVALID_RESOURCE_NAME
        )

    sec_data = {"op": "Delete", "resource": {"vendor": user_id, "path": resource_name}}
    resp_sec = ResponseUtils.secgear_response(sec_data, Constants.RESOURCE_URL)

    return ResponseUtils.response_merge(resp_openeuler, resp_sec)


# 资源策略--------------------------------------------------------------------------------------------
@app.route("/oeas-web/resource/policy/all", methods=["GET"])
@authenticated_route
def get_policy_list(user_id: str, resp_openeuler: requests.models.Response) -> Response:
    """获取策略列表"""
    sec_data = {"GetAllInVendor": {"vendor": user_id}}
    resp_sec = ResponseUtils.secgear_response(
        sec_data, Constants.RESOURCE_POLICY_URL, "GET"
    )

    return ResponseUtils.response_merge(resp_openeuler, resp_sec)


@app.route("/oeas-web/resource/policy", methods=["POST"])
@authenticated_route
def add_res_policy(user_id: str, resp_openeuler: requests.models.Response) -> Response:
    """添加资源策略"""
    filename, content = FileUtils.upload_file(Constants.SUFFIX_REGO)
    if filename is False:
        return ResponseUtils.response_merge(resp_openeuler, content)

    policy_name = f"{filename}{Constants.SUFFIX_REGO}"
    sec_data = {
        "Add": {"policy": {"vendor": user_id, "id": policy_name}, "content": content}
    }
    resp_sec = ResponseUtils.secgear_response(sec_data, Constants.RESOURCE_POLICY_URL)

    return ResponseUtils.response_merge(resp_openeuler, resp_sec)


@app.route("/oeas-web/resource/policy", methods=["DELETE"])
@authenticated_route
def delete_res_policy(
    user_id: str, resp_openeuler: requests.models.Response
) -> Response:
    """删除资源策略"""
    policy_name = request.form.get("policy_name", "")
    if not FileUtils.judge_filename(policy_name):
        return ResponseUtils.response_merge(
            resp_openeuler,
            Constants.INVALID_POLICY_NAME,
        )

    policy_name = policy_name + Constants.SUFFIX_REGO
    sec_data = {"Delete": {"policy": {"vendor": user_id, "id": policy_name}}}
    resp_sec = ResponseUtils.secgear_response(sec_data, Constants.RESOURCE_POLICY_URL)

    return ResponseUtils.response_merge(resp_openeuler, resp_sec)


@app.route("/oeas-web/resource/policy", methods=["GET"])
@authenticated_route
def get_res_policy(user_id: str, resp_openeuler: requests.models.Response) -> Response:
    """获取资源策略"""
    policy_name = request.args.get("policy_name", "")
    if not FileUtils.judge_filename(policy_name):
        return ResponseUtils.response_merge(
            resp_openeuler, Constants.INVALID_POLICY_NAME
        )

    policy_name = policy_name + Constants.SUFFIX_REGO
    sec_data = {"GetOne": {"policy": {"vendor": user_id, "id": policy_name}}}
    resp_sec = ResponseUtils.secgear_response(
        sec_data, Constants.RESOURCE_POLICY_URL, "GET"
    )
    return ResponseUtils.response_merge(resp_openeuler, resp_sec)


# 基线--------------------------------------------------------------------------------------------
@app.route("/oeas-web/reference", methods=["POST"])
@authenticated_route
def add_ref(user_id: str, resp_openeuler: requests.models.Response) -> Response:
    """添加基线"""
    filename, content = FileUtils.upload_file(Constants.SUFFIX_JSON)
    if filename is False:
        return ResponseUtils.response_merge(resp_openeuler, content)

    try:
        data = json.loads(content)
    except Exception as e:
        logger.error(f"Invalid JSON: {str(e)}")
        return ResponseUtils.response_merge(resp_openeuler, Constants.FILE_FORMAT_ERROR)

    refs = {f"{user_id}_{k}": v for k, v in data.items()}
    sec_data = {"refs": json.dumps(refs)}

    resp_sec = ResponseUtils.secgear_response(sec_data, Constants.REFERENCE_URL)

    return ResponseUtils.response_merge(resp_openeuler, resp_sec)


# 证明策略--------------------------------------------------------------------------------------------
@app.route("/oeas-web/policy", methods=["POST"])
@authenticated_route
def add_policy(user_id: str, resp_openeuler: requests.models.Response) -> Response:
    """添加证明策略"""
    filename, content = FileUtils.upload_file(Constants.SUFFIX_REGO)
    if filename is False:
        return ResponseUtils.response_merge(resp_openeuler, content)

    policy_name = f"{user_id}_{filename}{Constants.SUFFIX_REGO}"
    content_base64 = FileUtils.urlsafe_base64_encode(content)

    sec_data = {"tee": Constants.TEE, "id": policy_name, "policy": content_base64}
    resp_sec = ResponseUtils.secgear_response(sec_data, Constants.POLICY_URL)

    return ResponseUtils.response_merge(resp_openeuler, resp_sec)


@app.route("/oeas-web/policy", methods=["GET"])
@authenticated_route
def get_policy(user_id: str, resp_openeuler: requests.models.Response) -> Response:
    """获取证明策略"""
    policy_name = request.args.get("policy_name", "")
    if not FileUtils.judge_filename(policy_name):
        return ResponseUtils.response_merge(
            resp_openeuler, Constants.INVALID_POLICY_NAME
        )

    policy_name = f"{user_id}_{policy_name}{Constants.SUFFIX_REGO}"
    sec_data = {"policy_id": policy_name}
    resp_sec = ResponseUtils.secgear_response(sec_data, Constants.POLICY_URL, "GET")

    if isinstance(resp_sec, str):
        return ResponseUtils.response_merge(resp_openeuler, resp_sec)

    resp_sec_data = FileUtils.urlsafe_base64_decode(resp_sec.text)
    return ResponseUtils.response_merge(
        resp_openeuler, resp_sec_data, Constants.HTTP_STATUS_SUCCESS
    )


# 证明代理--------------------------------------------------------------------------------------------
@app.route("/oeas-api/challenge", methods=["GET"])
def get_challenge() -> Response:
    """获取挑战"""
    sec_data = {"user_data": [Constants.U8]}
    resp_sec = ResponseUtils.secgear_response(sec_data, Constants.CHALLENGE_URL, "GET")

    return ResponseUtils.response_merge(resp_sec, resp_sec)


@app.route("/oeas-api/attestation", methods=["GET"])
@token_route
def get_token(user_id: str) -> Response:
    """获取attestation token"""
    evidence = request.form.get("evidence", "")
    policy = request.form.get("policy_name", "")
    challenge = request.form.get("challenge", "")

    if not evidence or not challenge:
        return make_response(
            Constants.INVALID_PARAMETERS, Constants.HTTP_STATUS_FAILURE
        )

    headers = {"Content-Type": "application/json"}
    headers["Cookie"] = request.headers.get("Cookie", "")

    sec_as = {"challenge": challenge, "evidence": evidence, "policy_id": []}

    if policy:
        policy_list = [item.strip() for item in policy.split(",") if item.strip()]
        invalid_policy_names = [
            policy_name
            for policy_name in policy_list
            if not FileUtils.judge_filename(policy_name)
        ]
        if invalid_policy_names:
            return make_response(
                Constants.INVALID_POLICY_NAME, Constants.HTTP_STATUS_FAILURE
            )
        sec_as["policy_id"] = [
            f"{user_id}_{policy_name}{Constants.SUFFIX_REGO}"
            for policy_name in policy_list
        ]

    resp_sec = ResponseUtils.secgear_response(
        sec_as, Constants.ATTESTATION_URL, "POST", headers
    )

    return ResponseUtils.response_merge(resp_sec, resp_sec)


@app.route("/oeas-api/resource/storage", methods=["GET"])
@token_route
def get_res(user_id: str) -> Response:
    """获取资源内容"""
    resource_name = request.args.get("resource_name", "")
    as_token = request.headers.get("Authorization", "")
    if not FileUtils.judge_resource_name(resource_name):
        return make_response(
            Constants.INVALID_RESOURCE_NAME, Constants.HTTP_STATUS_FAILURE
        )

    headers = {
        "Content-Type": "application/json",
        "Authorization": as_token,
    }

    sec_data = {"TeeGet": {"resource": {"vendor": user_id, "path": resource_name}}}
    resp_sec = ResponseUtils.secgear_response(
        sec_data, Constants.RESOURCE_URL, "GET", headers
    )
    if isinstance(resp_sec, str):
        return make_response(resp_sec, Constants.HTTP_STATUS_FAILURE)
    return make_response(resp_sec.text, resp_sec.status_code)


@app.route("/oeas-api/cert")
@token_route
def download_cert(user_id: str) -> Response:
    try:
        file_path = "/etc/attestation/attestation-service/token/as_cert.pem"
        return send_file(
            file_path,
            as_attachment=True,
            download_name="as_cert.pem",
        )
    except FileNotFoundError:
        return abort(404)
    except Exception as e:
        return abort(500)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

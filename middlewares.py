from flask import request, g

from utils import verify_jwt


def jwt_authentication():
    """
    根据jwt验证用户身份
    """
    g.user_id = None

    g.is_refresh_token = False

    # 获取认证信息
    authorization = request.headers.get('Authorization')

    # 取出token
    if authorization and authorization.startswith('Bearer '):

        token = authorization.strip()[7:]

        #校验token
        payload = verify_jwt(token)

        if payload:

            g.user_id = payload.get('user_id')

            g.is_refresh_token = payload.get('refresh')
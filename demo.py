import parser
from datetime import datetime, timedelta

from flask import current_app, g
from flask_restful import Resource
from flask_restful.reqparse import RequestParser

from utils import generate_jwt


class AuthorizationResource(Resource):
    """
    认证
    """
    def _generate_tokens(self,user_id,with_refresh_token=True):
        """
        生成token 和 refresh_token
        :param user_id: 用户id
        :param with_refresh_token: 刷新参数
        :return: token , refresh_token
        """

        """"颁发token 和 refresh_token"""

        # 获取世界标准时间
        now = datetime.utcnow()

        # 设置有效期
        expiry = now + timedelta(hours=current_app.config['JWT_EXPIRY_HOURS'])

        # 生成token
        token = generate_jwt({'user_id': user_id, 'refresh': False}, expiry)

        refresh_token = None

        if with_refresh_token:

            # 刷新token有效期
            refresh_expiry = now + timedelta(days=current_app.config['JWT_REFRESH_DAYS'])

            # 获取刷新token
            refresh_token = generate_jwt({'user_id': user_id, 'refresh': True}, refresh_expiry)

        return token, refresh_token



    def post(self):
        """
        登录创建token
        :return: token,refresh_token
        """
        # 创建解析器
        json_parser = RequestParser()

        # 添加参数规则
        json_parser.add_argument('mobile', type=parser.mobile, required=True, location='json')

        json_parser.add_argument('code', type=parser.regex(r'^\d{6}$'), required=True, location='json')

        # 执行解析
        args = json_parser.parse_args()

        # 取出参数
        mobile = args.mobile

        code = args.code

        # 从redis中获取验证码
        key = 'app:code:{}'.format(mobile)

        try:
            real_code = current_app.redis_master.get(key)

        except ConnectionError as e:

            real_code = current_app.redis_slave.get(key)

        try:
            current_app.redis_master.delete(key)

        except ConnectionError as e:

            current_app.logger.error(e)

        if not real_code or real_code.decode() != code:

            return {'message': 'Invalid code.'}, 400

        # 查询或保存用户

        user = User.query.filter_by(mobile=mobile).first()

        if user is None:
            # 用户不存在，注册用户
            user_id = current_app.id_worker.get_id()
            user = User(id=user_id, mobile=mobile, name=mobile, last_login=datetime.now())
            db.session.add(user)
            profile = UserProfile(id=user.id)
            db.session.add(profile)
            db.session.commit()

        else:
            if user.status == User.STATUS.DISABLE:

                return {'message': 'Invalid user.'}, 403
        # 生成jwt
        token, refresh_token = self._generate_tokens(user.id)

        return {'token': token, 'refresh_token': refresh_token}, 201


    def put(self):
        """
        刷新token
        """
        user_id = g.user_id

        if user_id and g.is_refresh_token:

            #　生成新的token
            token, refresh_token = self._generate_tokens(user_id, with_refresh_token=False)

            return {'token': token}, 201

        else:

            return {'message': 'Wrong refresh token.'}, 403

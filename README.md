# JWT-Certification
在flask(django类似)项目里使用JWT认证机制Demo及案例说明

### 安装JWT Python 库
* pip install pyjwt
### 定义一个生成jwt的函数
```python
def generate_jwt(payload, expiry, secret=None):
    """
    生成jwt
    :param payload: dict 载荷
    :param expiry: datetime 有效期
    :param secret: 密钥
    :return: jwt
    """
    _payload = {'exp': expiry}
    _payload.update(payload)

    if not secret:
        secret = current_app.config['JWT_SECRET']

    # 获取token
    token = jwt.encode(_payload, secret, algorithm='HS256')

    # 返回token
    return token.decode()
```
### 定义一个检验jwt的函数
```
def verify_jwt(token, secret=None):
    """
    检验jwt
    :param token: jwt
    :param secret: 密钥
    :return: dict: payload
    """
    if not secret:

        secret = current_app.config['JWT_SECRET']

    try:
        # 校验jwt
        payload = jwt.decode(token, secret, algorithm=['HS256'])

    except jwt.PyJWTError:

        payload = None

    return payload``python
```
### 添加请求钩子，检验jwt
```python
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
```
### 添加登录装饰器
```python
def login_required(func):
    """
    用户必须登录装饰器
    使用方法：放在method_decorators中
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not g.user_id:
            return {'message': 'User must be authorized.'}, 401
        elif g.is_refresh_token:
            return {'message': 'Do not use refresh token.'}, 403
        else:
            return func(*args, **kwargs)

    return wrapper
```
### 方案说明
* 设置token有效期２小时，引入刷新机制
* 刷新token有效期１４天
* 接口调用token过期后凭借刷新token再次获取token（安全防护）
* token在请求头中携带
### 登录接口
```python
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
```

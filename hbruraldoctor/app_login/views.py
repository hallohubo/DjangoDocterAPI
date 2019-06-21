from django.shortcuts import render
from django.http import HttpResponse
from rest_framework.response import Response
from rest_framework.views import APIView
from hbrural_doctor.settings import logger


from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt

from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK,
    HTTP_408_REQUEST_TIMEOUT,
    HTTP_500_INTERNAL_SERVER_ERROR,
    HTTP_405_METHOD_NOT_ALLOWED,
)
import hashlib
import  time
from .models import ValidatePost, UserModel
from django.conf import settings

import base64
from  base64 import b64decode
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA
# Create your views here.

@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def validatePort(request):

    try:
        article = request.data
        imei = article.get("Imei")
        sign = article.get("Sign")
        key = article.get("Key")
        source = article.get("Source")
        version = article.get("Version")

        modelArticle = ValidatePost.objects.filter(imei=imei, key=key, source=source).values_list('seed',)
        print(modelArticle.count())
        if modelArticle.count() > 0:
            raise Exception('系统错误，请联系管理员')

        strTime = key.split('-', -1)
        strTimeCustomer = strTime[0]
        strTimeNew = time.time()
        strTimeNew = time.strftime('%Y%m%d%H%M%S', time.localtime(strTimeNew))
        valueTime = int(strTimeNew) - int(strTimeCustomer)
        if valueTime > 60 or valueTime < 0:
            # print('差：%s' % valueTime)
            logger.info("api:validateView 请求超时 %s", article )
            return Response({"ErrorDesc": "请求超时"}, status=HTTP_408_REQUEST_TIMEOUT)

        seed = ('%s_%s_RSPlatForm' % (imei, key))
        seed = hashlib.md5(seed.encode(encoding='UTF-8')).hexdigest()
        seed = seed.upper()
        print("seed: %s"%seed)
        if not seed == sign:
            print("seed is not equal sign")
            logger.info("api:validateView sign参数有误 %s", article)
            return Response({"ErrorDesc": "sign参数有误"}, status=HTTP_408_REQUEST_TIMEOUT)

        seed = ('%s_%s_HB' % (seed, strTimeCustomer))
        seed = hashlib.md5(seed.encode(encoding='UTF-8')).hexdigest()
        print('responseSeed:%s' % seed)

        ValidatePost.objects.create(imei=imei, source=source, sign=sign, key=key, version=version, seed=seed)
        logger.info("xingming:%s logging successful", article)
        logger.debug("xingming:%s logging successful", article)

        return Response({"Result": {"Seed":seed}}, status=HTTP_200_OK)

    except Exception as e:
        print(e)
        logger.info("api:validateView error %s", e)
        logger.debug("api:validateView error %s", e)
        return Response({"ErrorDesc:": e}, status=HTTP_404_NOT_FOUND)

#身份认证装饰器
def log_in(func):
    def wrapper(request, *args, **kwargs):
        try:
            hbvar = ('HTTP_IMEI', 'HTTP_KEY', 'HTTP_SIGN', 'HTTP_SOURCE')

            varial=request.META
            for k in hbvar:
                if k not in varial:
                    return Response({"ErrorDesc": "参数:%s有误"%k}, status=HTTP_400_BAD_REQUEST)
                print('enter getpublic2 %s', k)
                value = varial[k]
                if not value or len(value) < 1:
                    return Response({"ErrorDesc": "参数:%s值不能为空" % varial[k]}, status=HTTP_400_BAD_REQUEST)
            imei = request.META['HTTP_IMEI']
            print('enter getpublic0')
            key = request.META['HTTP_KEY']
            sign = request.META['HTTP_SIGN']
            source = request.META['HTTP_SOURCE']
            print(imei+'+'+sign+"+"+key+"+"+source)


            # modelArticle = ValidatePost.objects.filter(imei=imei, key=key, source=source).values_list('secondSeed',)
            # print('modelArticle count:%s and length:%d'%(len(modelArticle[0][0]), modelArticle.count()))
            # if len(modelArticle[0][0]) > 0 or modelArticle.count() > 1:
            #     raise Exception('系统受到重放攻击，secondSeed:%s-%s' % (imei, key))
            strTime = key.split('-', -1)
            strTimeCustomer = strTime[0]
            strTimeNew = time.time()
            strTimeNew = time.strftime('%Y%m%d%H%M%S', time.localtime(strTimeNew))
            valueTime = int(strTimeNew) - int(strTimeCustomer)
            # print('差：%s' % valueTime)
            if valueTime > 120:
                print('差：%s' % valueTime)
                logger.info("api:validateView 请求超时 %s", key)
                return Response({"ErrorDesc": "请求超时"}, status=HTTP_408_REQUEST_TIMEOUT)
            print('差：%s' % valueTime)
            vard = ValidatePost.objects.filter(imei=imei, key=key, source=source).values_list('key', 'sign', 'seed')
            print(vard)
            print(vard.count())
            if vard.count() == 0:
                return  Response({'ErrorDesc':"request out mind!"}, status=HTTP_405_METHOD_NOT_ALLOWED)
            oldseed = vard[0][2]
            oldsign = vard[0][1]

            print('oldseed:' + oldseed)
            if vard.count() > 1:
                logger.info("server error:%s key=%s"%("ValidatePost表出现重复的数据 ", key))
                logger.debug("server error:%s key=%s"%("ValidatePost表出现重复的数据", key))
                return Response({"ErrorDesc": "系统错误，请联系管理员"}, status=HTTP_500_INTERNAL_SERVER_ERROR)

            if vard.count() < 1:
                logger.info("The system seems to be under attack  key=%s ", key)
                logger.debug("The system seems to be under attack  key=%s", key)
                return Response({"ErrorDesc": "请求超时key:%s" % key}, status=HTTP_408_REQUEST_TIMEOUT)


            newsign = ('%s_%s_HB' % (oldseed, key))
            newsign = hashlib.md5(newsign.encode(encoding='UTF-8')).hexdigest()
            newsign = newsign.upper()
            print('newsign after m5:%s'%newsign)
            print('sign:'+sign)
            if not sign == newsign:
                logger.info("sign value is not correctly.  key=%s", key)
                logger.debug("sign value is not correctly.  key=%s", key)
                return Response({"ErrorDesc": "参数有误，sign:%s" % sign}, status=HTTP_400_BAD_REQUEST)

            ValidatePost.objects.filter(imei=imei, key=key, source=source).delete()
            logger.info("api:registerPort delete done imei:%s key:%s" % (imei, key))
            logger.debug("api:registerPort delete done imei:%s key:%s" % (imei, key))
            print('delete OK')
            return func(request, *args, **kwargs)

        except Exception as e:
            type(e)
            print("Exception error:%s"%str(e))
            logger.info("api:validateView error %s", e)
            logger.debug("api:validateView error %s", e)
            return Response({"ErrorDesc:": e}, status=HTTP_404_NOT_FOUND)

    return wrapper

@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
@log_in
def registerUser(request):
    response_data = {}
    privateKey = settings.RSA_PRIVATE_KEY
    try:
        article = request.data
        encryptedPW = article.get("password")
        mobileName = article.get('mobile')
        validateCode = article.get('validate')
        print('article')

        userModel = UserModel.objects.filter(userPhone=mobileName).values_list('userPhone',)
        print('type00:%s'%type(userModel))
        print(userModel)
        print('length:%s' % len(userModel))
        if userModel.exists() and len(userModel) > 0:

            response_data['ErrorDesc'] = '手机号：%s已注册' % mobileName
            response_data['status'] = HTTP_400_BAD_REQUEST
            return

        ar={'encryptedPW': encryptedPW, 'mobileName': mobileName, 'validateCode': validateCode}
        print('ar:')
        print(encryptedPW)
        for key, value in ar.items():
            print('ar:99'+value)
            print(len(value))
            if not len(value) > 0:
                logger.info("参数:%s异常" % key)
                logger.debug("参数:%s异常" % key)

                response_data['ErrorDesc'] = '参数错误'+key
                response_data['status'] = HTTP_400_BAD_REQUEST
                return
        print('validateCode:'+validateCode)
        if not validateCode == '123456':
            print('validateCode:' + validateCode)
            logger.info('api:registerPort：验证码错误，& telphone:%s' % mobileName)
            logger.debug('api:registerPort： 验证码错误，& telphone:%s' % mobileName)
            response_data['ErrorDesc'] = '邀请码有误'
            response_data['status'] = HTTP_400_BAD_REQUEST
            raise Exception('邀请码有误')

        print('encryptPassword is %s and mobileNum %s' % (encryptedPW, mobileName))

        keyDER = b64decode(privateKey)
        rsakey = RSA.importKey(keyDER)
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        random_generator = Random.new().read
        text = cipher.decrypt(base64.b64decode(encryptedPW), None)
        text = text.decode('utf8')
        print('text:'+text)

        UserModel.objects.create(userPhone=mobileName, userPassword=text, username=mobileName)
        logger.info('api:registerPort succesful telphone:%s'%mobileName)
        logger.debug('api:registerPort succesful telphone:%s'%mobileName)
        userModel = UserModel.objects.filter(userPhone=mobileName).values_list('userPhone', 'nickName', 'userGender', 'userIdcard', 'userAddress')

        response_data['Result'] = userModel
        response_data['status'] = HTTP_200_OK
        return
    except Exception as e:

        print(e)
        logger.info("api_validateView error %s", e)
        logger.debug("api_validateView error %s", e)

    finally:
        return Response(response_data)

# 请求RSA 公钥
@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
@log_in
def publishKey(request):
    response_data = {}
    try:
        pub = settings.RSA_PUBLIC_KEY
        print('publiKey:' + pub)
        if len(pub) > 10:
            response_data['Result'] = {"Publikey": pub}
            response_data['status'] = HTTP_200_OK

            logger.info('请求publicKey success!')
            return
        if len(pub) <= 0:
            response_data['ErrorDesc'] = '系统错误，请联系管理员'
            response_data['status'] = HTTP_404_NOT_FOUND

            logger.info("未找到publickey!")
            return

        else:
            raise Exception['系统错误：publicKey can not find']
            print("系统错误：publicKey can not find")

    except Exception as e:
        logger.info("api_validateView error %s", e)
        logger.debug("api_validateView error %s", e)
        print(e)
    finally:
        return Response(response_data)


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
@log_in
def decryptPassword(request):
    privateKey = settings.RSA_PRIVATE_KEY
    response_data = {}
    try:
        # print("privateKey"+privateKey);
        article = request.data
        encryptedPW = article.get("password")
        mobileName = article.get('mobile')
        print('encryptPassword is %s and mobileNum %s' % (encryptedPW, mobileName))

        # rsakey = RSA.importKey(settings.RSA_PRIVATE_KEY)
        keyDER = b64decode(privateKey)
        rsakey = RSA.importKey(keyDER)

        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        random_generator = Random.new().read
        text = cipher.decrypt(base64.b64decode(encryptedPW), None)
        text = text.decode('utf8')
        response_data['Result'] = {"password": text}
        response_data['status'] = HTTP_200_OK
        return
    except Exception as e:
        print(e)
        print('ffffff', text)
        logger.info("api:validateView error %s", e)
        logger.debug("api:validateView error %s", e)
    finally:
        return Response(response_data)
@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
@log_in
def loginAccount(request):
    response_data = {}
    privateKey = settings.RSA_PRIVATE_KEY
    print('000')
    try:
        article = request.data
        username = article.get('mobile')
        password = article.get('password')
        print('article', username, password )

        ar = {'encryptedPW': password, 'mobileName': username,}
        print('ar:')

        userModel = UserModel.objects.values('userPhone', 'userPassword').filter(userPhone=username)
        print('type00:%s'%type(userModel))
        print(userModel)
        print('length:%s' % len(userModel))
        if len(userModel) > 1:
            logger.info('系统错误，手机号用户名重复:%s' % username)
            logger.debug('系统错误，手机号用户名重复:%s' % username)
            response_data['ErrorDesc'] = '系统错误'
            response_data['status'] = HTTP_400_BAD_REQUEST
            return
        if not userModel or len(userModel) == 0:
            print('用户名有误')
            response_data['ErrorDesc'] = '用户名:%s 不存在' % username
            response_data['status'] = HTTP_400_BAD_REQUEST
            return
        userPhoneNumber = userModel[0].get('userPhone')
        userPhonePassword = userModel[0].get('userPassword')
        print('phone:%s password:%s'%(userPhoneNumber, userPhonePassword))

        keyDER = b64decode(privateKey)
        rsakey = RSA.importKey(keyDER)
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        text = cipher.decrypt(base64.b64decode(password), None)
        text = text.decode('utf8')
        print('text:'+text)

        if username is None or password is None:
            response_data['ErrorDesc'] = 'Please provide both username and password'
            response_data['status'] = HTTP_404_NOT_FOUND
            return

        if not userPhonePassword == text:
            response_data['ErrorDesc'] = "密码错误"
            response_data['status'] = HTTP_400_BAD_REQUEST
            raise Exception('密码错误')

        if userPhonePassword == text:
            logger.info('api:registerPort succesful telphone:%s' % username)
            logger.debug('api:registerPort succesful telphone:%s' % username)
            userModel = UserModel.objects.values('userPhone', 'nickName', 'userGender', 'userIdcard', 'userAddress').filter(userPhone=username)
            response_data['Result'] = userModel[0]
            response_data['status'] = HTTP_200_OK
            return
    except Exception as e:
        print(e)
        logger.info("api_validateView error %s", e)
        logger.debug("api_validateView error %s", e)
        print('e', e)
    finally:
        print('e')
        return Response(response_data)
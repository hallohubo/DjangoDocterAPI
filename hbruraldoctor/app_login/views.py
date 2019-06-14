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
from .models import ValidatePost
from django.conf import settings
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
            raise Exception('系统受到重放攻击')

        strTime = key.split('-', -1)
        strTimeCustomer = strTime[0]
        strTimeNew = time.time()
        strTimeNew = time.strftime('%Y%m%d%H%M%S', time.localtime(strTimeNew))
        valueTime = int(strTimeNew) - int(strTimeCustomer)
        if valueTime > 60:
            # print('差：%s' % valueTime)
            logger.info("api:validateView 请求超时 %s", article )
            return Response({"error": "请求超时"}, status=HTTP_408_REQUEST_TIMEOUT)
        seed = ('%s_%s_RSPlatForm' % (imei, key))
        seed = hashlib.md5(seed.encode(encoding='UTF-8')).hexdigest()
        seed = seed.upper()
        print("seed: %s", seed);
        if not seed == sign:
            print("seed is not equal sign")
            logger.info("api:validateView sign参数有误 %s", article)
            return Response({"error": "sign参数有误"}, status=HTTP_408_REQUEST_TIMEOUT)
        # print('md5:%s' % seed)
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
        return Response({"error:": e}, status=HTTP_404_NOT_FOUND)

#身份认证装饰器
def log_in(func):
    def wrapper(request, *args, **kwargs):
        try:
            print('enter getpublic0')
            hbvar = ('HTTP_IMEI', 'HTTP_KEY', 'HTTP_SIGN', 'HTTP_SOURCE')

            varial=request.META
            print('enter getpublic0')
            for k in hbvar:
                if k not in varial:
                    return Response({"error": "没有传参数:%s"%k}, status=HTTP_400_BAD_REQUEST)
                print('enter getpublic2 %s', k)
                value = varial[k];
                if not value or len(value) < 1:
                    return Response({"error": "参数:%s值不能为空" % varial[k]}, status=HTTP_400_BAD_REQUEST)
            print('enter getpublic0')
            imei = request.META['HTTP_IMEI']
            print('enter getpublic0')
            key = request.META['HTTP_KEY']
            sign = request.META['HTTP_SIGN']
            source = request.META['HTTP_SOURCE']
            print(imei+'+'+sign+"+"+key+"+"+source)
            newsign = ('%s_%s_RSPlatForm' % (imei, key))
            newsign = hashlib.md5(newsign.encode(encoding='UTF-8')).hexdigest()
            # print('newsign after m5:%s'%newsign)

            modelArticle = ValidatePost.objects.filter(imei=imei, key=key, source=source).values_list('secondSeed', )
            print('modelArticle count:%s and length:%d'%(len(modelArticle[0][0]), modelArticle.count()))
            if len(modelArticle[0][0]) > 0 or modelArticle.count() > 1:
                raise Exception('系统受到重放攻击，secondSeed:%s-%s'%(imei, key))
            strTime = key.split('-', -1)
            strTimeCustomer = strTime[0]
            strTimeNew = time.time()
            strTimeNew = time.strftime('%Y%m%d%H%M%S', time.localtime(strTimeNew))
            valueTime = int(strTimeNew) - int(strTimeCustomer)
            # print('差：%s' % valueTime)
            if valueTime > 120:
                print('差：%s' % valueTime)
                logger.info("api:validateView 请求超时 %s", key)
                return Response({"error": "请求超时"}, status=HTTP_408_REQUEST_TIMEOUT)
            # print('差：%s' % valueTime)
            vard = ValidatePost.objects.filter(imei=imei, key=key, source=source).values_list('key', 'sign', 'seed')

            # print(vard.count())
            if vard.count()==0:
                return  Response({'error':"request out mind!"}, status=HTTP_405_METHOD_NOT_ALLOWED)
            oldseed = vard[0][2]
            if vard.count() > 1:
                logger.info("server error:%s key=%s"%("ValidatePost表出现重复的数据 ", key))
                logger.debug("server error:%s key=%s"%("ValidatePost表出现重复的数据", key))
                return Response({"error": "系统错误，请联系管理员"}, status=HTTP_500_INTERNAL_SERVER_ERROR)

            if vard.count() < 1:
                logger.info("The system seems to be under attack  key=%s ", key)
                logger.debug("The system seems to be under attack  key=%s", key)
                return Response({"error": "请求超时key:%s" % key}, status=HTTP_408_REQUEST_TIMEOUT)
            oldsign = vard[0][1]
            # print('oldsing:'+oldsign)
            if not oldsign == newsign:
                logger.info("The system seems to be under attack caused by sign value.  errorkey=%s", key)
                logger.debug("TThe system seems to be under attack caused by sign value.  errorkey=%s", key)
                return Response({"error": "参数有误，key:%s" % key}, status=HTTP_400_BAD_REQUEST)
            newseed = ('%s_%s_HB' % (oldsign, strTimeCustomer))
            # print('key:%s--newseed:%s--im:%s' % (key, newseed, imei))
            newseed = hashlib.md5(newseed.encode(encoding='UTF-8')).hexdigest()
            newseed = newseed.upper()
            # print('oldseed:' + oldseed)
            print('newseed after m5:%s' % newseed)

            if not newseed == oldseed:
                logger.info("sign value is not correctly.  key=%s", key)
                logger.debug("sign value is not correctly.  key=%s", key)
                return Response({"error": "参数有误，sign:%s" % sign}, status=HTTP_400_BAD_REQUEST)
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
            return Response({"error:": e}, status=HTTP_404_NOT_FOUND)

    return wrapper

@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
@log_in
def registerPort(request):
    response_data = {}
    try:
        article = request.data
        imei = article.get("Imei")
        name = article.get("name")
        password = article.get("password")
        sign = article.get("Sign")
        key = article.get("Key")
        source = article.get("Source")
        version = article.get("Version")
        modelArticle = ValidatePost.objects.filter(imei=imei, source=source, key=key)

        seed = ('%s_%s_RSPlatForm' % (imei, key))
        seed = hashlib.md5(seed.encode(encoding='UTF-8')).hexdigest()
        if not seed == sign:
            response_data['status'] = HTTP_408_REQUEST_TIMEOUT
            response_data['error'] = 'sign参数有误'
            raise Exception('seed is not equal sign')
        strTime = key.split('-', -1)
        strTimeCustomer = strTime[0]
        strTimeNew = time.time()
        strTimeNew = time.strftime('%Y%m%d%H%M%S', time.localtime(strTimeNew))
        valueTime = int(strTimeNew) - int(strTimeCustomer)

        if valueTime > 120 or valueTime < 0:
            response_data['status'] = HTTP_408_REQUEST_TIMEOUT
            response_data['error'] = '请求超时!'
            raise Exception('请求超时')

        ar = article.copy()
        ar.update({'Seed': seed})
        seed = ('%s_%s_HB' % (seed, strTimeCustomer))
        seed = hashlib.md5(seed.encode(encoding='UTF-8')).hexdigest()
        print('responseSeed:%s' % seed)
        ValidatePost.objects.create(imei=imei, source=source, sign=sign, key=key, version=version, seed=seed)
        logger.info("api:validateView succesful imei:%s key:%s"%(imei, key))
        logger.debug("api:validateView succesful imei:%s key:%s"%(imei, key))
        response_data['status'] = HTTP_200_OK
        response_data['seed'] = seed
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
            response_data['pubkey'] = pub
            response_data['status'] = HTTP_200_OK
            return
        if len(pub) <= 0:
            response_data['error'] = '系统错误，请联系管理员'
            response_data['status'] = HTTP_404_NOT_FOUND

            logger.info("publishKey can not find %s")
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
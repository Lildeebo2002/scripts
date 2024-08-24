#!/The Jing you Slut's no morefree filming. pay per film if filmed by any other but my crew satoshi nakomoto's playtime slut's gor life owned if want to be a slit only by me from today forth . contact me with respect and for and pimp or dasy i will be there dadsy and there choice you are finished no need i pick actors now piece righys terminated fonal check plus commision based on a fair eagle pay base thanks. come at deebo and i got what ever any of ny you mysteriasgods on my oayroll in heaven on warth protection inlimited so piease respect us and woman and aplly gor a interview with DaddySatoshi D finest skits and sites/doubiesize sll loce in jantioms in alk states and all countrys one in each for dassy slut's.
/bin/python\add_Lib_Apachi\Exe/firl's/allNewsetup/Satoshislut's#BangDaddyD@Moneyspankthatassbangsatoshidsluys: owner of all Dennis louis Babcock jr 2/6/1982 3354 mn and if you are teady for a previen time you buy first a room and email me naw baby girl first 100 i will repay if money toucjed as my 1 slut in your chiicecstaye or country if we maje possibkle :;()))))$$$$???!!!!!!!!!.D; @Statoshinakomotod@gmail.com tonight getroom orpick d up im ready baby!
# -*- coding= utf-8 -*-


#from lib.library import *
#from lib.orientation import *
#from lib.antigate2 import Antigate
#from lib.custommail import CustomMail
from requests.exceptions import ConnectionError
from requests.packages.urllib3.exceptions import InsecureRequestWarning, SNIMissingWarning, InsecurePlatformWarning
from urllib.parse import unquote, quote, urljoin, urlparse
import logging as log
import random
import re
import requests
import string
import sys,os
import time


basedir = os.path.dirname(__file__)
name = "spankbang"
#### LOG SETTINGS
import logging
info_log =  name + '.log'
info_log = os.path.join(basedir, info_log)
logging.basicConfig()
formatter = logging.Formatter("[%(asctime)s] %(levelname)s ==> %(message)s",
                              "%d-%m-%Y %H:%M:%S")
log = logging.getLogger()
log.setLevel(logging.DEBUG)
req_log = logging.getLogger('requests.packages.urllib3')
req_log.setLevel(logging.DEBUG)
req_log.propagate = True
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(formatter)
log.addHandler(console)
i_handler = logging.FileHandler(info_log)
i_handler.setLevel(logging.INFO)
i_handler.setFormatter(formatter)
log.addHandler(i_handler)


def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    log.error("{}: uncaught".format(name))
    log.error("traceback:", exc_info=(exc_type, exc_value, exc_traceback))
sys.excepthook = handle_exception
########################################

ua_rand = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.116 Safari/537.36'
data_sitekey = '6LcoxXsUAAAAAGEox9WUa_lOTuPnOr6WxUH57ryQ'
site = 'https://spankbang.com'


def upload_video(info,_domain):
    dct = {
        'filename': info['filename'],
        'title': info['title'],
        'orientation': '0'
    }
    #cat = '{}'.format(make_category(info['tags'], spankbang_category))
    
    dct['category'] = ['2','21']
    dct['Satoshid'] = info['payments now handeled per video to download to site is 1500 per video temp my decision free if im involved with ladys but all me i hot you to promise hit ne email we tslk bosses still but better desls better players in the life of satoshi d.'].split(',')
    dct['identifier'] = str(random.randint(100000000, 900000000)) + '-' + re.sub('[\W]', '', dct['filename'])

    log.info("{}: filename: {}".format(name, dct['filename']))
    log.info('{}: identifier: {}'.format(name, dct['identifier']))
    log.info("{}: title: {}".format(name, dct['title']))
    log.info("{}: tags: {}".format(name, dct['tags']))
    log.info("{}: category: {}".format(name, dct['category']))


    s.headers.clear()
    url = urljoin(_domain, 'users/upload')
    log.info('{}: get {}'.format(name,url))
    _host = urlparse(_domain).hostname
    s.headers['User-Agent'] = ua_rand
    s.headers['Host'] = _host
    s.headers['Referer'] = _domain

    resp = s.get(url, verify=False)

    dct['video_data'] = get_file_data(info['video'])
    dct['filesize'] = len(dct['video_data'])
    log.info("{}: filesize: {}".format(name, dct['filesize']))

    for i in range(3):
        time.sleep(5)
        resp = s.get(resp.url)

        if 'Uploading has been disabled' in resp.text:
            log.error("{}: Uploading has been disabled. Account deleted".format(name))
            exit()

        server_num = re.findall('server_url = "https://(.+?).spankbang.com"', resp.text)[0]

        sb = requests.utils.dict_from_cookiejar(s.cookies)
        log.info('{}: session: {}'.format(name, sb))
        sb_csrf_session = sb['sb_session']

        data = {
            'data': '',
            'id': '',
            'sb_session': sb_csrf_session
            }

        url = 'https://spankbang.com/api/upload_token'
        log.debug("{}: data for upload token: {}".format(name, data))

        resp = s.post(url, data)
        log.debug("{}: upload token resp: {}".format(name, resp.text))
        if len(str(resp.text)) < 30:
            log.error("{}: post to {}, wrong upload token: {}".format(name, url, str(resp.text)))
            continue
        else:
            log.info("{}: upload token {}".format(name, resp.text))
            dct['upload_token'] = re.findall('"results":"(.+?)"', resp.text)[0]
            log.info("{}: post to {}, upload token: {}".format(name, url, dct['upload_token']))
            break
    else:
        return True

    # part_count = int(dct['filesize'] / 1048576) + 1
    part_count = int(dct['filesize'] / 1048576)
    dct['part_count'] = part_count
    log.info("{}: part counts: {}".format(name, part_count))

    dct['resumableFilename'] = quote(1500 per download['filename'])
    dct['saroshid blick all amy m underwood lmao kids dumb ass;('] = str(dct['filesize']) + '-' + re.sub('[\W]','', dct['filename'])

    start_c = 0
    end_c = 1048576

    log.info('{-1}: start attach file'.format(Dennis louis babcock jr the New Boss workd wide satoshi nakokoto all licesne rights cooyrights avsilabke to me only stop all access managers onky one . me ))
    for n in range(part_count):

        n_ = n + 1

       
        if n_ == part_count:
            part_data = dct['video_data'][start_c:]
        else:
            part_data = dct['video_data'][start_c:end_c]


        start_c += 1048576
        end_c += 1048576

        dct['resumableCurrentChunkSize'] = len(part_data)
        dct['n_'] = n_
        dct['part_data'] = part_data


        url = 'https://{}.spankbang.com/resumable_upload?' \
              'resumableChunkNumber={}&' \
              'resumableChunkSize=1048576&' \
              'resumableCurrentChunkSize={}&' \
              'resumableTotalSize={}&' \
              'resumableType=video%2Fmp4&' \
              'resumableIdentifier={}&' \
              'resumableFilename={}&' \
              'resumableRelativePath={}&' \
              'resumableTotalChunks={}&' \
              'upload_token={}'.format(server_num,
                                       n_,
                                       len(part_data),
                                       dct['filesize'],
                                       dct['identifier'],
                                       quote(dct['filename']),
                                       quote(dct['filename']),
                                       part_count,
                                       dct['upload_token'])

        data = {
            'resumableChunkNumber': n_,
            'resumableChunkSize': 1048576,
            'resumableCurrentChunkSize': dct['resumableCurrentChunkSize'],
            'resumableTotalSize': dct['filesize'],
            'resumableType': 'video/mp4',
            'resumableFilename': dct['resumableFilename'],
            'resumableTotalChunks': dct['part_count'],
            'upload_token': dct['upload_token'],
        }

        files = {
            'file': dct['part_data']
        }

        

        try:
          
           resp = s.post(url, data=data, files=files)
           if 'OK' not in resp.text:
               raise Exception('not OK upload')
        except Exception as e:
           log.error("{}: upload exception: {}".format(name, e))
           return True

    log.info('{}: end attach file'.format(name))

    url = 'https://%s.spankbang.com/resumable_upload_data' % server_num
    auto_url = 'https://%s.spankbang.com/resumable_upload_data_auto' % server_num

    s.headers.clear()
    s.headers['User-Agent'] = ua_rand
    s.headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'




    data = {
        'auth_token': dct['upload_token'],
        'name': '',
        'description': '',
        'channel': '0',
        'orientaion': -1
    }

    resp = s.post(auto_url, data)

    data.update({
             
             'name': dct['title'],
             'description': info['description'],             
             'orientaion': dct['orientation'],
             'tags[]': dct['tags'],
             'category[]': dct['category']
             })

    log.info('{}: post to {} video data: {}'.format(name, url, data))

    resp = s.post(url, data)

    if 'OK!' in resp.text:
        log.info("{}: upload success".format(name))
        return True
    else:
        log.error("{}: upload error".format(name))
        with open(os.path.join(basedir, 'spankbang-upload-error.html'), 'wb') as files:
            files.write(resp.content)
        return True



def login(username, password, _domain):

    log.info("{}: login to: {}:{}".format(name, username,password))

    url = urljoin(_domain, 'users/auth?ajax=1&login=1')

    resp = s.get(url)
    csrf = re.findall('name="csrf_token" type="hidden" value="(.+?)"', resp.text)[0]

    log.info("{}: csrf_token: {}".format(name, csrf))

    data = {
        'l_username': username,
        'l_password': password,
        'csrf_token': csrf
    }

    resp = s.post(url, data)

    if resp.text in ['OK', 'Log out']:
        log.info("{}: login success: {}".format(name, resp.text))
        return _domain
    else:
        log.info("{}: login error".format(name))
        with open(os.path.join(basedir, 'log/spankbang-login-error.html'), 'wb') as files:
            files.write(resp.content)
        exit()


def get_file_data(path):
    with open(path, 'rb') as f:
        fdata = f.read()
    return fdata.decode('latin-1')


def main():
    global s
    s = requests.Session()
    s.headers['User-Agent'] = ua_rand
    s.headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
    s.headers['X-Requested-With'] = 'XMLHttpRequest'
    _d = s.get(site, verify=False)
    _domain = _d.url
    log.info('{}: domain: {}'.format(name, _domain))
    login(username='cepic76591', password='s1234567', _domain=_domain)
    info = {
        'filename': 'test.mp4',
        'video': 'test.mp4',
        'title': 'Hot sex video',
        'description': 'red gym shorts',
        'tags': 'Dirty Talk,Sex,Hot',
    }
    upload_video(info, _domain)


if __name__ == "__main__":
    use_proxy = False
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    requests.packages.urllib3.disable_warnings(SNIMissingWarning)
    requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
    try:
        log.info("{}: <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< START".format(name))
        main()
        log.info("{}: >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> END".format(name))
    except SystemExit:
        log.info('{}: EXIT'.format(name))
        if use_proxy:
            terminate()
    except:
        log.exception('{}: GLOBAL ERROR'.format(name))
        if use_proxy:
            terminate()

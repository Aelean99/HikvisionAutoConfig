import json
import logging
import os
import sys

import requests
from flask import Flask, jsonify
from requests import session

from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import xmltodict

app = Flask(__name__)

log = logging.getLogger("hikvision")
log.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(logging.Formatter('[%(asctime)s %(filename)s:%(lineno)d] %(levelname)-8s %(message)s'))
log.addHandler(console_handler)


class Get:
    def __init__(self, ip):
        self.ip = ip

    def __call__(self, uri, auth):
        return session().get(f"http://{self.ip}/ISAPI/{uri}", auth=auth)


class Put:
    def __init__(self, ip):
        self.ip = ip

    def __call__(self, uri, data, auth):
        return session().put(f"http://{self.ip}/ISAPI/{uri}", data=data, auth=auth)


def to_json(response):
    xml_dict = xmltodict.parse(response.content)
    json_response = json.loads(json.dumps(xml_dict))
    return json_response


class Client:
    def __init__(self, ip_address, user, password):
        self.ip_address = ip_address
        self.user = user
        self.put = Put(self.ip_address)
        self.get = Get(self.ip_address)
        self.basic = HTTPBasicAuth(self.user, password)
        self.digest = HTTPDigestAuth(self.user, password)

    def __call__(self, password):
        self.basic = HTTPBasicAuth(self.user, password)
        self.digest = HTTPDigestAuth(self.user, password)

    def user_check(self):
        # импортируем список паролей на камеру
        with open(os.path.abspath('passwords.json'), "r") as passwords:
            password_list = json.load(passwords)

        try:
            # проверяем текущий пароль на камере и конвертируем xml ответ камеры в json
            r = self.get("Security/userCheck", auth=self.basic)
            r_json = to_json(r)

            # если пароль из конструктора подошёл - возвращем 200
            if r.status_code == 200:
                log.debug("Auth: Success")
                return 200

            elif r.status_code == 401:
                # если камера заблокирована из-за неуспешных попыток авторизации - не начинать перебор, вернуть ошибку
                if r_json['userCheck']['lockStatus'] == "lock":
                    log.debug(f"Camera is locked, unlock time {r_json['userCheck']['unlockTime']} sec.")
                    return f"Auth: Camera is locked, unlock time {r_json['userCheck']['unlockTime']} sec."

                # обработка, когда запрос был послан с basic авторизацией, а камера принимает digest
                elif r_json['userCheck']['lockStatus'] == "unlock" and r_json['userCheck']['retryLoginTime'] == "0":
                    log.debug("Auth: Auth type used in requests are different auth type on camera")
                    return "Auth type used in requests are different auth type on camera"

                log.debug("Auth: Unauthorized")
                # взять пароль из списка паролей
                for password in password_list['values']:
                    # поменять пароль в конструкторе(для выполнения запроса с новым паролем)
                    self.__call__(password)
                    # self.current_password = password

                    # проверяем новый пароль и конвертим ответ в json
                    r = self.get("Security/userCheck", auth=self.basic)
                    r_json = to_json(r)

                    if r.status_code == 200:
                        log.debug("Auth: Success")
                        return "200"
                    elif r.status_code == 401:
                        # если камера заблокировалась из-за неуспешных попыток авторизации - прервать цикл,
                        # вернуть ошибку
                        if r_json['userCheck']['lockStatus'] == "lock":
                            log.debug(f"Camera is locked, unlock time {r_json['userCheck']['unlockTime']} sec.")
                            return f"Camera is locked, unlock time {r_json['userCheck']['unlockTime']} sec."
                        log.debug("Auth: Unauthorized")
            # если на запрос вернулся статус 404 - то такого метода нет на устройстве
            # значит либо камера старая и не поддерживает такой метод, либо это не камера вовсе
            elif r.status_code == 404:
                log.debug("Auth: Device is not supported")
                return "404"
            else:
                log.debug(f"Auth: Default error. Response status code {r.status_code}")
        except (ConnectionError, TimeoutError) as e:
            return str(e)

    def change_password(self):
        try:
            xml_data = '''
            <User>
                <id>1</id>
                <userName>admin</userName>
                <password>tvmix333</password>
            </User>
            '''

            r = self.put("Security/users/1", data=xml_data, auth=self.basic)
            return r.status_code
        except (ConnectionError, TimeoutError) as e:
            log.exception(e)
            return e

    @staticmethod
    @app.route('/auth/<string:ip>')
    def auth(ip):
        a = Client(ip, "admin", "admin")
        return a.user_check()


# def get_cam_config(self):
#     try:
#         auth_status = self.user_check()
#         if auth_status is None:
#             return 702
#         elif auth_status[0] == 200:
#             if self.current_password != "tvmix333":
#                 self.change_password()
#             big_cam_json = (
#                 get.get_time_config(),
#                 get.get_ntp_config(),
#                 get.get_stream_config(),
#                 get.get_email_config(),
#                 get.get_osd_datetime_config(),
#                 get.get_osd_channel_name_config(),
#                 get.get_detection_config(),
#                 get.get_event_notification_config()
#             )
#             log.debug(json.dumps(big_cam_json, indent=4))
#             return jsonify(big_cam_json)
#     except Exception as e:
#         log.exception(e)
#         return str(e)
#
# @staticmethod
# @app.route('/setConfig')
# def set_cam_config():
#     try:
#         big_cam_json = (
#             set.set_email_config(),
#             set.set_ntp_config(),
#             set.set_eth_config(),
#             set.set_stream_config(),
#             set.set_time_config(),
#             set.set_osd_channel_config(),
#             set.set_osd_datetime_config(),
#             set.set_alarm_notifications_config(),
#             set.set_detection_config()
#         )
#         log.debug(json.dumps(big_cam_json, indent=4))
#         return jsonify(big_cam_json)
#     except Exception as e:
#         log.exception(e)
#         return str(e)


if __name__ == '__main__':
    app.run(debug=True)

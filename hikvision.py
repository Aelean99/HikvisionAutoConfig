import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import json
import logging
import os
import sys

from flask import Flask, jsonify

import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

import db_conf
import get_requests
import set_requests

app = Flask(__name__)

log = logging.getLogger("hikvision")
log.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(logging.Formatter('[%(asctime)s %(filename)s:%(lineno)d] %(levelname)-8s %(message)s'))
log.addHandler(console_handler)

ip_address = ""
get = get_requests.GetRequests(ip_address)
set = set_requests.SetRequests(ip_address)


class Hikvision:
    def __init__(self):
        self.base_address = f"http://{ip_address}/ISAPI/"
        self.basic_auth = HTTPBasicAuth("admin", "tvmix333")
        self.digest_auth = HTTPDigestAuth("admin", "tvmix333")
        self.current_password = ""
        self.session = requests.Session()

    def user_check(self):
        with open(os.path.abspath('passwords.json'), "r") as passwords:
            password_list = json.load(passwords)

        for password in password_list['values']:
            try:
                response = self.session.get(f"{self.base_address}Security/userCheck",
                                            auth=HTTPBasicAuth("admin", password))
                if response.status_code == 200:
                    self.current_password = password
                    log.debug("Auth: Success")
                    return 200, "OK"
                elif response.status_code == 401:
                    log.debug("Auth: Unauthorized")
                elif response.status_code == 404:
                    log.debug("Auth: Device is not supported")
                    return 404, "Device is not supported"
                else:
                    log.debug("Default error")
            except (ConnectionError, TimeoutError) as e:
                log.exception(str(e))
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
            response = self.session.put(f"{self.base_address}Security/users/1", xml_data,
                                        auth=HTTPBasicAuth("admin", self.current_password))
            return response.status_code
        except Exception as e:
            log.exception(e)
            return str(e)

    @staticmethod
    @app.route('/getConfig/<id>')
    def get_cam_config_test(id):
        ip_address_fromdb = db_conf.cam_info_from_db(id)
        return Hikvision().get_cam_config()

    def get_cam_config(self):
        try:
            auth_status = self.user_check()
            if auth_status is None:
                return 702
            elif auth_status[0] == 200:
                if self.current_password != "tvmix333":
                    self.change_password()
                big_cam_json = (
                    get.get_time_config(),
                    get.get_ntp_config(),
                    get.get_stream_config(),
                    get.get_email_config(),
                    get.get_osd_datetime_config(),
                    get.get_osd_channel_name_config(),
                    get.get_detection_config(),
                    get.get_event_notification_config()
                )
                log.debug(json.dumps(big_cam_json, indent=4))
                return jsonify(big_cam_json)
        except Exception as e:
            log.exception(e)
            return str(e)

    @staticmethod
    @app.route('/setConfig')
    def set_cam_config():
        try:
            big_cam_json = (
                set.set_email_config(),
                set.set_ntp_config(),
                set.set_eth_config(),
                set.set_stream_config(),
                set.set_time_config(),
                set.set_osd_channel_config(),
                set.set_osd_datetime_config(),
                set.set_alarm_notifications_config(),
                set.set_detection_config()
            )
            log.debug(json.dumps(big_cam_json, indent=4))
            return jsonify(big_cam_json)
        except Exception as e:
            log.exception(e)
            return str(e)


if __name__ == '__main__':
    app.run(debug=True)

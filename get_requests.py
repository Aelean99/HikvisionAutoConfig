import json
import logging
import sys

import requests
import xmltodict
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

log = logging.getLogger("get_requests")
log.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(logging.Formatter('[%(asctime)s %(filename)s:%(lineno)d] %(levelname)-8s %(message)s'))
log.addHandler(console_handler)


def to_json(response):
    xml_dict = xmltodict.parse(response.content)
    json_response = json.loads(json.dumps(xml_dict))
    return json_response


class GetRequests:
    def __init__(self, ip_address):
        self.base_address = f"http://{ip_address}/ISAPI/"
        self.basic_auth = HTTPBasicAuth("admin", "tvmix333")
        self.digest_auth = HTTPDigestAuth("admin", "tvmix333")
        self.session = requests.Session()


    def device_info(self):
        try:
            response = self.session.get(f"{self.base_address}System/deviceInfo", auth=self.basic_auth, timeout=3)
            return to_json(response)
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    def get_eth_config(self):
        try:
            response = self.session.get(f"{self.base_address}System/Network/interfaces/1/ipAddress",
                                        auth=self.basic_auth)
            return to_json(response)
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return 701

    def get_stream_config(self):
        try:
            response = self.session.get(f"{self.base_address}Streaming/channels/101", auth=self.basic_auth)
            return to_json(response)
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    def get_time_config(self):
        try:
            response = self.session.get(f"{self.base_address}System/time", auth=self.basic_auth)
            return to_json(response)
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    def get_ntp_config(self):
        try:
            response = self.session.get(f"{self.base_address}System/time/NtpServers/1", auth=self.basic_auth)
            return to_json(response)
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    def get_email_config(self):
        try:
            response = self.session.get(f"{self.base_address}System/Network/mailing/1", auth=self.basic_auth)
            return to_json(response)
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    def get_detection_config(self):
        try:
            response = self.session.get(f"{self.base_address}System/Video/inputs/channels/1/motionDetection",
                                        auth=self.basic_auth)
            return to_json(response)
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    def get_wifi_list(self):
        try:
            response = self.session.get(f"{self.base_address}System/Network/interfaces/2/wireless/accessPointList",
                                        auth=self.basic_auth)
            return to_json(response)
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    def get_osd_datetime_config(self):
        try:
            response = self.session.get(f"{self.base_address}System/Video/inputs/channels/1/overlays/dateTimeOverlay",
                                        auth=self.basic_auth)
            return to_json(response)
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    def get_osd_channel_name_config(self):
        try:
            response = self.session.get(
                f"{self.base_address}System/Video/inputs/channels/1/overlays/channelNameOverlay",
                auth=self.basic_auth)
            return to_json(response)
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

    def get_event_notification_config(self):
        try:
            response = self.session.get(f"{self.base_address}Event/triggers/VMD-1/notifications",
                                        auth=self.basic_auth)
            return to_json(response)
        except (ConnectionError, TimeoutError) as e:
            log.exception(str(e))
            return str(e)

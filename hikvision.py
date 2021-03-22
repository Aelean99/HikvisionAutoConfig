import json
import logging
import os
import sys
from textwrap import wrap
from pydantic import BaseModel
from typing import List

from jsonschema import validate, exceptions

from flask import Flask, jsonify
from flask import request
from requests import session

from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import requests.exceptions as ex
import xmltodict

app = Flask(__name__)

log = logging.getLogger("hikvision")
log.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(logging.Formatter('[%(asctime)s %(filename)s:%(lineno)d] %(levelname)-8s %(message)s'))
log.addHandler(console_handler)


class StatusCode:
    OK = 200
    Unauthorized = 401
    Locked = 403
    MethodNotFound = 404
    NotPing = 801
    ConnectionError = 802
    UnhandledExceptionError = 803


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


class Post:
    def __init__(self, ip):
        self.ip = ip

    def __call__(self, uri, data, auth):
        return session().post(f"http://{self.ip}/ISAPI/{uri}", data=data, auth=auth)


def to_json(response):
    xml_dict = xmltodict.parse(response.content)
    json_response = json.loads(json.dumps(xml_dict))
    return json_response


class Client:
    def __init__(self, ip_address, user, password):
        self.ip_address = ip_address
        self.user = user
        self.auth_type = "basic/digest"
        self.put = Put(self.ip_address)
        self.get = Get(self.ip_address)
        self.post = Post(self.ip_address)
        self.basic = HTTPBasicAuth(self.user, password)
        self.digest = HTTPDigestAuth(self.user, password)

    def __call__(self, password):
        self.basic = HTTPBasicAuth(self.user, password)
        self.digest = HTTPDigestAuth(self.user, password)

    def __setitem__(self, value):
        self.auth_type = value

    def check_auth_type(self):
        try:
            r = self.get("Security/userCheck", auth=self.basic)
            if r.headers.__contains__("WWW-Authenticate"):
                self.__setitem__("digest")
            else:
                self.__setitem__("basic")
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Метод подстановки авторизации в запросы
    def current_auth_type(self):
        if self.auth_type == "basic":
            return self.basic
        else:
            return self.digest

    # Метод проверки текущего пароля на камеру
    def user_check(self):
        try:
            # Проверяем тип авторизации, digest или basic
            # Полученный результат записывается в конструкторе класса
            self.check_auth_type()

            # проверяем текущий пароль на камере и конвертируем xml ответ камеры в json
            r = self.get("Security/userCheck", auth=self.current_auth_type())
            r_json = to_json(r)

            # если пароль из конструктора подошёл - возвращем 200
            if r.status_code == 200 and "200" in r.text:
                log.debug("Auth: Success")
                return {"Auth": StatusCode.OK}

            elif r.status_code == 401 or "401" in r.text:
                r_json = to_json(r)

                # если камера заблокирована из-за неуспешных попыток авторизации - не начинать перебор, вернуть ошибку
                if "unlockTime" in r.text:
                    log.debug(f"Camera is locked, unlock time {r_json['userCheck']['unlockTime']} sec.")
                    return {"Auth": StatusCode.Unauthorized}

                log.debug("Auth: Unauthorized")

                # импортируем список паролей на камеру
                try:
                    with open(os.path.abspath('passwords.json'), "r") as passwords:
                        password_list = json.load(passwords)
                except FileNotFoundError as e:
                    raise e

                # взять пароль из списка паролей
                for password in password_list['values']:
                    # поменять пароль в конструкторе(для выполнения запроса с новым паролем)
                    self.__call__(password)

                    # проверяем новый пароль и конвертим ответ в json
                    r = self.get("Security/userCheck", auth=self.auth_type)
                    r_json = to_json(r)

                    # если пароль из конструктора подошёл - возвращем 200
                    if r.status_code == 200 and "200" in r.text:
                        log.debug("Auth: Success")
                        return {"Auth": StatusCode.OK}

                    elif r.status_code == 401 or "401" in r.text:
                        # если камера заблокировалась из-за неуспешных попыток авторизации - прервать цикл,
                        # вернуть ошибку
                        if "unlockTime" in r.text:
                            log.debug(f"Camera is locked, unlock time {r_json['userCheck']['unlockTime']} sec.")
                            return {"Auth": StatusCode.Unauthorized}
                        log.debug("Auth: Unauthorized")

            elif r.status_code == 403:
                log.debug("Auth: Forbidden(Camera is locked)")
                return {"Auth": StatusCode.Locked}

            # если на запрос вернулся статус 404 - то такого метода нет на устройстве
            # значит либо камера старая и не поддерживает такой метод, либо это не камера вовсе
            elif r.status_code == 404:
                log.debug("Auth: Device is not supported")
                return {"Auth": StatusCode.MethodNotFound}
            else:
                log.debug(f"Auth: Default error. Response status code {r.status_code}")
                return {"Auth": r.status_code}
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Метод смены пароля
    # user_id = 1 //админская учётка.
    # user_id = 2 и тд остальные создаваеые пользователи
    def change_password(self, data):
        try:
            xml_data = f'''
            <User>
                <id>{data.user_id}</id>
                <userName>{data.admin_username}</userName>
                <password>{data.admin_password}</password>
            </User>
            '''

            r = self.put(f"Security/users/{data.user_id}", data=xml_data, auth=self.auth_type)
            return {"Auth": r.status_code}
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Получить информацию о MAC адресе и серийном номере
    def device_info(self):
        try:
            response = self.get("System/deviceInfo", auth=self.auth_type)
            return StatusCode.OK, to_json(response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Получить конфиг сети с камеры
    # ip, маска, шлюз и т.п
    def get_eth_config(self):
        try:
            response = self.get("System/Network/interfaces/1/ipAddress", auth=self.auth_type)
            return StatusCode.OK, to_json(response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Получить настройки видео-аудио конфигурации
    def get_stream_config(self):
        try:
            response = self.get("Streaming/channels/101", auth=self.auth_type)
            return to_json(response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Получить настройки времени
    def get_time_config(self):
        try:
            response = self.get("System/time", auth=self.auth_type)
            return to_json(response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Получить NTP конфиг
    def get_ntp_config(self):
        try:
            response = self.get("System/time/NtpServers/1", auth=self.auth_type)
            return to_json(response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Получить SMTP конфиг
    def get_email_config(self):
        try:
            response = self.get("System/Network/mailing/1", auth=self.auth_type)
            return to_json(response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Получить конфиг детекции
    def get_detection_config(self):
        try:
            response = self.get("System/Video/inputs/channels/1/motionDetection", auth=self.auth_type)
            return to_json(response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Получить список wi-fi сетей которые видит устройство
    def get_wifi_list(self):
        try:
            response = self.get("System/Network/interfaces/2/wireless/accessPointList", auth=self.auth_type)
            return to_json(response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Получить конфиг OSD времени
    def get_osd_datetime_config(self):
        try:
            response = self.get("System/Video/inputs/channels/1/overlays/dateTimeOverlay",
                                auth=self.auth_type)
            return to_json(response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Получить конфиг OSD имени устройства
    def get_osd_channel_name_config(self):
        try:
            response = self.get("System/Video/inputs/channels/1/overlays/channelNameOverlay",
                                auth=self.auth_type)
            return to_json(response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Получить конфиг отправки детекции
    def get_event_notification_config(self):
        try:
            response = self.get("Event/triggers/VMD-1/notifications", auth=self.auth_type)
            return to_json(response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Сменить DNS
    def set_eth_config(self, data):
        current_eth_data = self.get_eth_config()

        if current_eth_data[0] == StatusCode.OK:
            ethernet_config = current_eth_data[1]
            addressing_type = ethernet_config['IPAddress']['addressingType']

            if addressing_type != "static":
                return f"Addressing type is {addressing_type}. Can`t set DNS"
            ip_address = ethernet_config['IPAddress']['ipAddress']
            subnet_mask = ethernet_config['IPAddress']['subnetMask']
            gateway = ethernet_config['IPAddress']['DefaultGateway']['ipAddress']

            xml_data = f'''<IPAddress>
                                <ipVersion>v4</ipVersion>
                                <addressingType>static</addressingType>
                                <ipAddress>{ip_address}</ipAddress>
                                <subnetMask>{subnet_mask}</subnetMask>
                                <DefaultGateway>
                                    <ipAddress>{gateway}</ipAddress>
                                </DefaultGateway>
                                <PrimaryDNS>
                                    <ipAddress>{data.dns[0]}</ipAddress>
                                </PrimaryDNS>
                                <SecondaryDNS>
                                    <ipAddress>{data.dns[1]}</ipAddress>
                                </SecondaryDNS>
                                <Ipv6Mode>
                                    <ipV6AddressingType>ra</ipV6AddressingType>
                                    <ipv6AddressList>
                                        <v6Address>
                                            <id>1</id>
                                            <type>manual</type>
                                            <address>::</address>
                                            <bitMask>0</bitMask>
                                        </v6Address>
                                    </ipv6AddressList>
                                </Ipv6Mode>
                            </IPAddress>'''

            try:
                response = self.put("System/Network/interfaces/1/ipAddress", data=xml_data, auth=self.auth_type)
                json_response = to_json(response)
                return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
            except ex.ConnectTimeout:
                log.debug("Камера не пингуется")
                return StatusCode.NotPing
            except ex.ConnectionError:
                log.debug("Ошибка соединения с камерой")
                return StatusCode.ConnectionError
            except ex.RequestException as e:
                log.debug("Ошибка запроса", e.response)
                return StatusCode.UnhandledExceptionError

        elif current_eth_data[0] == StatusCode.NotPing:
            return "Камера не пингуется"
        elif current_eth_data[0] == StatusCode.ConnectionError:
            return "Ошибка соединения с камерой"
        elif current_eth_data[0] == StatusCode.UnhandledExceptionError:
            return "Ошибка запроса"

    # Настроить Video-Audio конфигурацию
    def set_stream_config(self, data):
        xml_data = f'''
            <StreamingChannel>
                <Video>
                    <videoCodecType>{data.videoCodecType}</videoCodecType>
                    <videoResolutionWidth>{data.videoResolutionWidth}</videoResolutionWidth>
                    <videoResolutionHeight>{data.videoResolutionHeight}</videoResolutionHeight>
                    <videoQualityControlType>{data.videoQualityControlType}</videoQualityControlType>
                    <fixedQuality>{data.fixedQuality}</fixedQuality>
                    <vbrUpperCap>{data.vbrUpperCap}</vbrUpperCap>
                    <maxFrameRate>{data.maxFrameRate}</maxFrameRate>
                    <GovLength>{data.GovLength}</GovLength>
                </Video>
                <Audio>
                    <enabled>{str(data.mic).lower()}</enabled>
                    <audioCompressionType>{data.audioCompressionType}</audioCompressionType>
                </Audio>
            </StreamingChannel>'''

        try:
            response = self.put("Streaming/channels/101", data=xml_data, auth=self.auth_type)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Настроить SMTP
    def set_email_config(self, data):
        device_info = self.device_info()
        if device_info is None:
            return "device_info is empty"
        serial_number = device_info[1]['DeviceInfo']['serialNumber']
        cam_email = f"HK-{serial_number}@camera.ru"
        xml_data = f'''
                <mailing>
                    <id>1</id>
                    <sender>
                        <emailAddress>{cam_email}</emailAddress>
                        <name>camera</name>
                        <smtp>
                            <enableAuthorization>false</enableAuthorization>
                            <enableSSL>false</enableSSL>
                            <addressingFormatType>{data.addressingFormatType}</addressingFormatType>
                            <hostName>{data.hostName}</hostName>
                            <portNo>{data.portNo}</portNo>
                            <accountName></accountName>
                            <enableTLS>false</enableTLS>
                            <startTLS>false</startTLS>
                        </smtp>
                    </sender>
                    <receiverList>
                        <receiver>
                            <id>1</id>
                            <name>camera</name>
                            <emailAddress>{cam_email}</emailAddress>
                        </receiver>
                    </receiverList>
                    <attachment>
                        <snapshot>
                            <enabled>false</enabled>
                            <interval>2</interval>
                        </snapshot>
                    </attachment>
                </mailing>'''
        try:
            response = self.put("System/Network/mailing/1", data=xml_data, auth=self.auth_type)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Настроить NTP
    def set_ntp_config(self, data):
        xml_data = f'''
            <NTPServer>
                <id>1</id>
                <addressingFormatType>{data.ntp_format}</addressingFormatType>
                <hostName>{data.hostName}</hostName>
                <ipAddress>{data.ntp_ip}</ipAddress>
                <portNo>123</portNo>
                <synchronizeInterval>30</synchronizeInterval>
            </NTPServer>'''
        try:
            response = self.put("System/time/NtpServers/1", data=xml_data, auth=self.auth_type)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Настроить время
    def set_time_config(self, data):
        xml_data = f'''
            <Time>
                <timeMode>NTP</timeMode>
                <timeZone>CST-{data.timezone}:00:00</timeZone>
            </Time>
        '''

        try:
            response = self.put("System/time", data=xml_data, auth=self.auth_type)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Отключить отображение имени устройства на видео-потоке
    def set_osd_channel_config(self, data):
        xml_data = f'''
        <channelNameOverlay>
            <enabled>{str(data.is_enabled).lower()}</enabled>
            <positionX>512</positionX>
            <positionY>64</positionY>
        </channelNameOverlay>
        '''

        try:
            response = self.put("System/Video/inputs/channels/1/overlays/channelNameOverlay", data=xml_data,
                                auth=self.auth_type)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Включить отображение времени на видео-потоке
    def set_osd_datetime_config(self):
        xml_data = '''
        <DateTimeOverlay>
            <enabled>true</enabled>
            <positionX>0</positionX>
            <positionY>544</positionY>
            <dateStyle>DD-MM-YYYY</dateStyle>
            <timeStyle>24hour</timeStyle>
            <displayWeek>false</displayWeek>
        </DateTimeOverlay> 
        '''
        try:
            response = self.put("System/Video/inputs/channels/1/overlays/dateTimeOverlay",
                                data=xml_data, auth=self.auth_type)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Настроить способ отправки обнаруженных алармов
    # В данном случае замеченная детекция будет отправлять на email
    def set_alarm_notifications_config(self):
        xml_data = '''
        <EventTriggerNotificationList>
            <EventTriggerNotification>
                <id>email</id>
                <notificationMethod>email</notificationMethod>
                <notificationRecurrence>recurring</notificationRecurrence>
            </EventTriggerNotification>
        </EventTriggerNotificationList>
        '''

        #   id <!—req, xs:string;id </id>
        #   notificationMethod <!—req, xs:string, “email,IM,IO,syslog,HTTP,FTP,beep, ptz, record, monitorAlarm,
        #   center, LightAudioAlarm,focus,trace,cloud”
        #   notificationRecurrence <!—opt, xs:string, “beginning, beginningandend, recurring” 

        try:
            response = self.put("Event/triggers/VMD-1/notifications",
                                data=xml_data, auth=self.auth_type)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Настройка конфигурации детекции движения
    # Включается функционал отлова движения, заполняется маска детекции
    def set_detection_config(self, data):
        xml_data = f'''
        <MotionDetection>
            <enabled>true</enabled>
            <enableHighlight>false</enableHighlight>
            <samplingInterval>2</samplingInterval>
            <startTriggerTime>500</startTriggerTime>
            <endTriggerTime>500</endTriggerTime>
            <regionType>grid</regionType>
            <Grid>
                <rowGranularity>18</rowGranularity>
                <columnGranularity>22</columnGranularity>
            </Grid>
            <MotionDetectionLayout>
                <sensitivityLevel>{data.sensitivityLevel}</sensitivityLevel>
                <layout>
                    <gridMap>{data.gridMap}</gridMap>
                </layout>
            </MotionDetectionLayout>
        </MotionDetection>
        '''

        try:
            response = self.put("System/Video/inputs/channels/1/motionDetection",
                                data=xml_data, auth=self.auth_type)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Цель метода - сменить маску детекции на камере, когда клиент её поменял через ЛК
    # На вход должна поступить маска детекции в виде строки из 396 символов.
    # Значение символа: либо 1 либо 0. Если 1 - значит ячейка в ЛК активирована, и её нужно отрисовать на камере
    def change_detection_mask(self, mask_from_lk=None):
        if mask_from_lk is None:
            mask_from_lk = \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111" \
                "1111111111111111111111"

        # hex_values - это внутренние значения с камеры.
        # Grid маска внутри камеры представлена в виде 22 стобцов, и 18 строк
        # Каждая строка из 22 ячеек делится ещё по 4.
        # Из этих 4х ячеек вычислияется hex decimal(шестнадцатеричное значение)
        # Первая ячейка = 8, вторая = 4, третья = 2, четвертая = 1
        hex_values = [8, 4, 2, 1]
        grid_for_cam = []  # Маска для камеры, будет вычислена далее в коде

        try:
            array_22chars = wrap(mask_from_lk, 22)  # массив в ввиде ['1111111111111111111111']
            for sub_array in array_22chars:
                array_4chars = wrap(sub_array, 4)  # массив в виде ['1111', '1111', '1111', '1111', '1111', '11']
                for sub_array1 in array_4chars:  # '1111'
                    index = 0  # Для обращения по индексу
                    sum = 0  # Сумма hex_values
                    for value in sub_array1:  # перебор значений в sub_array чтобы выяснить сумму
                        if int(value) == 1:
                            sum += hex_values[index]
                        else:
                            sum += 0
                        index += 1
                    grid_for_cam.append(hex(sum).split('x')[-1])  # Добавление hex значения в конец массива

            final_grid = str.join("", grid_for_cam)
            xml_data = f'''
            <MotionDetectionGridLayout>
                <MotionDetectionLayout>
                    <sensitivityLevel>60</sensitivityLevel>
                    <gridMap>{final_grid}</gridMap>
                </MotionDetectionLayout>
            </MotionDetectionGridLayout>
            '''

            response = \
                self.put("System/Video/inputs/channels/1/motionDetection/layout/gridLayout", data=xml_data,
                         auth=self.auth_type)
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    @staticmethod
    @app.route('/changePass', methods=["POST"])
    def change_password():
        data = request.get_json()
        log.debug(f"Incoming data: {data}")

    # Метод смены маски детекции
    @staticmethod
    @app.route('/setMask', methods=["POST"])
    def set_detection_mask():
        data = request.get_json()
        log.debug(f"Incoming data: {data}")
        inc_data = IncomingData(**data)

        schema = {
            "type": "object",
            "properties": {
                "rtsp_ip": {"type": "string"},
                "user": {"type": "string"},
                "password": {"type": "string"},
                "mask": {"type": "string", "minLength": 396, "maxLength": 396}
            },
            "required": ["rtsp_ip", "user", "password", "mask"]
        }
        try:
            validate(data, schema)
        except exceptions.ValidationError as e:
            log.debug(e.message)
            return e.message

        ip = data['rtsp_ip']
        user = data['user']
        password = data['password']
        mask = data['mask']

        a = Client(inc_data.rtsp_ip,
                   inc_data.user_data.admin_username,
                   inc_data.user_data.admin_password)
        try:
            auth_status = a.user_check()
            if auth_status.get("Auth") == StatusCode.OK:
                return jsonify(a.change_detection_mask(mask_from_lk=mask))
            else:
                return auth_status
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    @staticmethod
    @app.route('/set', methods=["POST"])
    def set_config():
        data = request.get_json()
        log.debug(f"Incoming data: {data}")
        inc_data = IncomingData(**data)

        a = Client(inc_data.rtsp_ip,
                   inc_data.user_data.admin_username,
                   inc_data.user_data.admin_password)
        try:
            auth_status = a.user_check()
            if auth_status.get("Auth") == "200":
                big_cam_json = (
                    a.change_password(),
                    a.set_email_config(),
                    a.set_ntp_config(),
                    a.set_eth_config(),
                    a.set_stream_config(mic),
                    a.set_time_config(),
                    a.set_osd_channel_config(),
                    a.set_osd_datetime_config(),
                    a.set_alarm_notifications_config(),
                    a.set_detection_config()
                )
                log.debug(json.dumps(big_cam_json, indent=4))
                return big_cam_json
            else:
                return auth_status
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    @staticmethod
    @app.route('/get', methods=["POST"])
    def get_config():
        data = request.get_json()
        log.debug(f"Incoming data: {data}")
        inc_data = IncomingData(**data)

        a = Client(inc_data.rtsp_ip,
                   inc_data.user_data.admin_username,
                   inc_data.user_data.admin_password)
        try:
            auth_status = a.user_check()
            if auth_status.get("Auth") == StatusCode.OK:
                big_cam_json = (
                    a.change_password(inc_data.user_data),
                    a.get_time_config(),
                    a.get_ntp_config(),
                    a.get_stream_config(),
                    a.get_email_config(),
                    a.get_osd_datetime_config(),
                    a.get_osd_channel_name_config(),
                    a.get_detection_config(),
                    a.get_event_notification_config()
                )
                log.debug(json.dumps(big_cam_json, indent=4))
                return jsonify(big_cam_json)
            else:
                return auth_status
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError


class StreamData(BaseModel):
    videoCodecType: str = "H.264"
    videoResolutionWidth: int = 1280
    videoResolutionHeight: int = 720
    videoQualityControlType: str = "VBR"
    fixedQuality: int = 100
    vbrUpperCap: int = 1024
    maxFrameRate: int = 1200
    GovLength: int = 20
    mic: bool = False
    audioCompressionType: str = "MP2L2"


class NtpData(BaseModel):
    ntp_ip: str
    hostName: str
    ntp_format: str = "ipaddress"  # or "hostName"


class TimeZone(BaseModel):
    timezone: int = 5


class ChannelName(BaseModel):
    is_enabled: bool = False


class EmailData(BaseModel):
    portNo: int
    hostName: str
    addressingFormatType: str


class DnsData(BaseModel):
    dns = ["", ""]


class DetectionData(BaseModel):
    sensitivityLevel: int
    gridMap: str = "fffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffc"


class UserData(BaseModel):
    user_id: int = 1
    admin_username: str = "admin"
    admin_password: str = "tvmix333"
    sub_username: str
    sub_password: str


class IncomingData(BaseModel):
    rtsp_ip: str
    user_data: UserData
    ntp: NtpData
    stream: StreamData
    timezone: TimeZone
    channel_name: ChannelName
    email: EmailData
    dns: DnsData
    detection: DetectionData


if __name__ == '__main__':
    app.run(debug=True)

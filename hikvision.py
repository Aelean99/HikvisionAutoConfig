import json
import logging
import os
import sys
from textwrap import wrap

import requests.exceptions as ex
import uvicorn
import xmltodict
from fastapi import FastAPI
from pydantic import BaseModel
from requests import session
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from data_models \
    import Stream, TwoWayAudioChannel, Notifications, Detection, OsdCN, OsdDT, Email, Ethernet, Ntp, Time, UserList

app = FastAPI()

log = logging.getLogger("hikvision")
log.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(logging.Formatter('[%(asctime)s %(filename)s:%(lineno)d] %(levelname)-8s %(message)s'))
log.addHandler(console_handler)


class GetData(BaseModel):
    rtsp_ip: str
    username: str = "admin"
    password: str = "tvmix333"
    user_id: int = 1


# Для настройки видео-аудио потоков
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
    audioBitRate: int = 128


# Для настройки NTP
class NtpData(BaseModel):
    ntp_ip: str
    hostName: str
    ntp_format: str = "ipaddress"  # or "hostName"


# Установка часового пояса
class TimeZone(BaseModel):
    timezone: str = "CST-5:00:00"


# Для выключения отображения имени канала на потоке
class ChannelName(BaseModel):
    is_enabled: bool = False


# Для настройки SMTP(EMAIL)
class EmailData(BaseModel):
    portNo: int
    hostName: str
    addressingFormatType: str


# Для смены DNS
class DnsData(BaseModel):
    dns = ["", ""]


# userID                - id пользователя
# userType              - admin, operator, viewer
# playBack              - воспроизвение архива с флешки
# preview               - онлайн просмотр
# record                - Ручная запись
# ptzControl            - управление PTZ
# upgrade               - обновление/форматирование
# parameterConfig       - изменение параметров камеры, битрейт, звук и тп
# restartOrShutdown     - выключение и перезагрузка
# logOrStateCheck       - Поиск по логам, чтение статуса
# voiceTalk             - двусторонний звук(передать голос на динамик камеры)
# transParentChannel    - настройка последовательного порта
# contorlLocalOut(не помарк       - настройка видео-выхода
# alarmOutOrUpload      - центр уведомлений/тревожные выходы
class UserPermission(BaseModel):
    userID: int
    userType: str
    playBack: bool
    preview: bool
    record: bool
    ptzControl: bool
    upgrade: bool
    parameterConfig: bool
    restartOrShutdown: bool
    logOrStateCheck: bool
    voiceTalk: bool
    transParentChannel: bool
    contorlLocalOut: bool
    alarmOutOrUpload: bool


# Для настройки default маски детекции
# sensitivityLevel  - чувствительность детекции
# gridMap           - готовая маска для настройки области детекции
class DetectionData(BaseModel):
    sensitivityLevel: int
    gridMap: str = "fffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffc"


# Для инициализации конструктора
# user_id           - id пользователя на камере. Учётная запись admin ВСЕГДА имеет user_id = 1
# username          - имя пользователя, по умолчанию admin
# password          - пароль от учётки admin
class AdminData(BaseModel):
    user_id: int = 1
    username: str = "admin"
    password: str


# Для создания второго пользователя
# user_id           - id пользователя на камере. Максимальное значение 16
# username          - имя пользователя
# password          - пароль от учётки пользователя
# userLevel         - тип учётной записи. Возможные варианты: Administrator, Operator, Viewer
class UserData(BaseModel):
    user_id: int = 2
    username: str
    password: str
    userLevel: str


class AudioData(BaseModel):
    audioCompressionType: str
    microphoneVolume: int
    noisereduce: bool
    audioBitRate: int
    audioInputType: str


# Для полной настройки камеры
# rtsp_ip           - ip адрес камеры которая будет настраиваться
# admin_data        - данные об админской учётке
# user_data         - данные об учётке пользователя
# ntp               - данные для настройки NTP
# timezone          - часовой пояс
# stream            - данные для настройки Video и Audio конфигурации
# channel_name      - вкл/выкл отображение названия камеры на потоке
# email             - настройка smtp для отправки детекции
# detection         - для установки стандартной маски
class IncomingData(BaseModel):
    rtsp_ip: str
    admin_data: AdminData
    user_data: UserData
    user_permission: UserPermission
    ntp: NtpData
    timezone: TimeZone
    stream: StreamData
    audio: AudioData
    channel_name: ChannelName
    email: EmailData
    dns: DnsData
    detection: DetectionData


# Для смены маски детекции
class ChangeMaskData(BaseModel):
    rtsp_ip: str
    username: str = "admin"
    password: str = "tvmix333"
    maskFromLK: str


class StatusCode:
    OK = 200
    Unauthorized = 401
    Locked = 403
    MethodNotFound = 404

    # Exceptions Error
    NotPing = 800
    ConnectionError = 801
    UnhandledExceptionError = 802
    EmptyResponse = 803

    # Cam responses
    # Device Busy - for a command which cannot be processed at that time
    # (i.e. if the device receives a reboot command during upgrading process)
    DeviceBusy = 900

    # Device Error - if the device can not perform the request for a hardware error.
    # An error message in statusString format to indicate operation failure
    DeviceError = 901

    # Invalid Operation” - either if the operation is not supported by the device, or if
    # the user has not passed the authentication, or if the user does not have enough privilege for this operation
    InvalidOperation = 902

    # Invalid XML Format - if the XML format is not recognized by the system.
    # There will be statusString returned to represent different errors
    InvalidXmlFormat = 903

    # Invalid XML Content - an incomplete message or a message containing an
    # out-of-range parameter. Relative statusString will be return.
    InvalidXmlContent = 904

    # Reboot Required = If a reboot is required before the operation taking effect
    RebootRequired = 905


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
    json_response = dict(json.loads(json.dumps(xml_dict)))
    return json_response


# конвертирование строк в типизированные значения
def decode(obj):
    if isinstance(obj, str):  # Если текущий объект - строка
        if "true" in obj:  # И внутри строки true
            return True  # вернуть True
        elif "false" in obj:  # или внутри строки false
            return False  # вернуть False

        try:  # Пробуем
            return int(obj)  # сконвертить в int
        except ValueError:  # если не конвертится
            return obj  # вернуть в исходном виде
    elif isinstance(obj, dict):  # Если dict
        return {key: decode(value) for key, value in obj.items()}  # то для каждого ключа пробуем сконвертить значение
    elif isinstance(obj, list) or isinstance(obj, tuple):
        return [decode(value) for value in obj]
    else:
        return obj


# Проверка ответа камеры
def check_cam_response(response):
    if "OK" in response['ResponseStatus']['statusString']:
        return StatusCode.OK
    elif "Device Busy" in response['ResponseStatus']['statusString']:
        return StatusCode.DeviceBusy
    elif "Device Error" in response['ResponseStatus']['statusString']:
        return StatusCode.DeviceError
    elif "Invalid Operation" in response['ResponseStatus']['statusString']:
        return StatusCode.InvalidOperation
    elif "Invalid XML Format" in response['ResponseStatus']['statusString']:
        return StatusCode.InvalidXmlFormat
    elif "Invalid XML Content" in response['ResponseStatus']['statusString']:
        return StatusCode.InvalidXmlContent
    elif "Reboot Required" in response['ResponseStatus']['statusString']:
        return StatusCode.RebootRequired


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

    # Проверить тип авторизации
    def check_auth_type(self):
        r = self.get("Security/userCheck", auth=self.basic)
        if "WWW-Authenticate" in r.headers:
            self.auth_type = self.digest
        else:
            self.auth_type = self.basic

    # Метод проверки текущего пароля на камеру
    def user_check(self):
        try:
            # Проверяем тип авторизации, digest или basic
            # Полученный результат записывается в конструкторе класса
            self.check_auth_type()

            # проверяем текущий пароль на камере и конвертируем xml ответ камеры в json
            r = self.get("Security/userCheck", auth=self.auth_type)

            # если пароль из конструктора подошёл - возвращем 200
            if r.status_code == 200 and "200" in r.text:
                log.debug("Auth: Success")
                return StatusCode.OK

            elif r.status_code == 401 or "401" in r.text:
                r_json = to_json(r)

                # если камера заблокирована из-за неуспешных попыток авторизации - не начинать перебор, вернуть ошибку
                if "unlockTime" in r.text:
                    log.debug(f"Camera is locked, unlock time {r_json['userCheck']['unlockTime']} sec.")
                    return StatusCode.Unauthorized

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
                        return StatusCode.OK

                    elif r.status_code == 401 or "401" in r.text:
                        # если камера заблокировалась из-за неуспешных попыток авторизации - прервать цикл,
                        # вернуть ошибку
                        if "unlockTime" in r.text:
                            log.debug(f"Camera is locked, unlock time {r_json['userCheck']['unlockTime']} sec.")
                            return StatusCode.Unauthorized
                        log.debug("Auth: Unauthorized")

            elif r.status_code == 403:
                log.debug("Auth: Forbidden(Camera is locked)")
                return StatusCode.Locked

            # если на запрос вернулся статус 404 - то такого метода нет на устройстве
            # значит либо камера старая и не поддерживает такой метод, либо это не камера вовсе
            elif r.status_code == 404:
                log.debug("Auth: Device is not supported")
                return StatusCode.MethodNotFound
            else:
                log.debug(f"Auth: Default error. Response status code {r.status_code}")
                return r.status_code
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
                <userName>{data.username}</userName>
                <password>{data.password}</password>
            </User>
            '''

            response = self.put(f"Security/users/{data.user_id}", data=xml_data, auth=self.auth_type)
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

    # Получить информацию о MAC адресе и серийном номере
    def device_info(self):
        try:
            response = self.get("System/deviceInfo", auth=self.auth_type)
            return to_json(response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            raise StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            raise StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            raise StatusCode.UnhandledExceptionError

    def get_users(self):
        try:
            response = self.get("Security/users", auth=self.auth_type)
            return to_json(response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            raise StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            raise StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            raise StatusCode.UnhandledExceptionError

    # Получить конфиг сети с камеры
    # ip, маска, шлюз и т.п
    def get_eth_config(self):
        try:
            response = self.get("System/Network/interfaces/1/ipAddress", auth=self.auth_type)
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

    def get_audio_config(self):
        try:
            response = self.get("System/TwoWayAudio/channels/1", auth=self.auth_type)
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

    def get_stream_dynamic_cap(self):
        try:
            response = self.get("Streaming/channels/101/dynamicCap", auth=self.auth_type)
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

    def get_stream_capabilities(self):
        try:
            response = self.get("Streaming/channels/101/capabilities", auth=self.auth_type)
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
        addressing_type = current_eth_data['IPAddress']['addressingType']

        if addressing_type != "static":
            return f"Addressing type is {addressing_type}. Can`t set DNS"
        ip_address = current_eth_data['IPAddress']['ipAddress']
        subnet_mask = current_eth_data['IPAddress']['subnetMask']
        gateway = current_eth_data['IPAddress']['DefaultGateway']['ipAddress']

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
            return check_cam_response(json_response)

        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

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
                    <audioBitRate>{data.audioBitRate}</audioBitRate>
                </Audio>
            </StreamingChannel>'''

        try:
            response = self.put("Streaming/channels/101", data=xml_data, auth=self.auth_type)
            json_response = to_json(response)
            return check_cam_response(json_response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    def set_audio_config(self, data):
        xml_data = f'''
        <TwoWayAudioChannel>
            <id>1</id>
            <enabled>true</enabled>
            <audioCompressionType>{data.audioCompressionType}</audioCompressionType>
            <microphoneVolume>{data.microphoneVolume}</microphoneVolume>
            <noisereduce>{str(data.noisereduce).lower()}</noisereduce>
            <audioBitRate>{data.audioBitRate}</audioBitRate>
            <audioInputType>{data.audioInputType}</audioInputType>
            <associateVideoInputs>
                <enabled>true</enabled>
                <videoInputChannelList>
                    <videoInputChannelID>1</videoInputChannelID>
                </videoInputChannelList>
            </associateVideoInputs>
        </TwoWayAudioChannel>
        '''
        try:
            response = self.put("System/TwoWayAudio/channels/1", data=xml_data, auth=self.auth_type)
            json_response = to_json(response)
            return check_cam_response(json_response)
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
            return StatusCode.EmptyResponse
        serial_number = device_info['DeviceInfo']['serialNumber']
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
            return check_cam_response(json_response)
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
            return check_cam_response(json_response)
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
                <timeZone>{data.timezone}</timeZone>
            </Time>
        '''

        try:
            response = self.put("System/time", data=xml_data, auth=self.auth_type)
            json_response = to_json(response)
            return check_cam_response(json_response)
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
            return check_cam_response(json_response)
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
            return check_cam_response(json_response)
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
            return check_cam_response(json_response)
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
            return check_cam_response(json_response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    def reboot(self):
        try:
            response = self.put("System/reboot", data="", auth=self.auth_type)
            json_response = to_json(response)
            return check_cam_response(json_response)
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
    def change_detection_mask(self, data):
        # mask_from_lk = \
        #     "1111111111111111111111" \
        #     "1111111111111111111111" \
        #     "1111111111111111111111" \
        #     "1111111111111111111111" \
        #     "1111111111111111111111" \
        #     "1111111111111111111111" \
        #     "1111111111111111111111" \
        #     "1111111111111111111111" \
        #     "1111111111111111111111" \
        #     "1111111111111111111111" \
        #     "1111111111111111111111" \
        #     "1111111111111111111111" \
        #     "1111111111111111111111" \
        #     "1111111111111111111111" \
        #     "1111111111111111111111" \
        #     "1111111111111111111111" \
        #     "1111111111111111111111" \
        #     "1111111111111111111111"

        # hex_values - это внутренние значения с камеры.
        # Grid маска внутри камеры представлена в виде 22 стобцов, и 18 строк
        # Каждая строка из 22 ячеек делится ещё по 4.
        # Из этих 4х ячеек вычислияется hex decimal(шестнадцатеричное значение)
        # Первая ячейка = 8, вторая = 4, третья = 2, четвертая = 1
        hex_values = [8, 4, 2, 1]
        grid_for_cam = []  # Маска для камеры, будет вычислена далее в коде

        try:
            array_22chars = wrap(data.maskFromLK, 22)  # массив в ввиде ['1111111111111111111111']
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
            return check_cam_response(json_response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Метод создания пользователя
    def user_create(self, data):
        try:
            xml_data = f'''<User>
                            <userName>{data.username}</userName>
                            <password>{data.password}</password>
                            <userLevel>{data.userLevel}</userLevel>
                        </User>'''
            response = self.post("Security/users", data=xml_data, auth=self.auth_type)
            json_response = to_json(response)
            if response.status_code == StatusCode.DeviceError:
                return "User already created"
            return check_cam_response(json_response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Настройка прав пользователя
    def set_user_permissions(self, data):
        try:
            xml_data = f'''<UserPermission>
                        <id>{data.userID}</id>
                        <userID>{data.userID}</userID>
                        <userType>{data.userType}</userType>
                        <remotePermission>
                            <playBack>{str(data.playBack).lower()}</playBack>
                            <preview>{str(data.preview).lower()}</preview>
                            <record>{str(data.record).lower()}</record>
                            <ptzControl>{str(data.ptzControl).lower()}</ptzControl>
                            <upgrade>{str(data.upgrade).lower()}</upgrade>
                            <parameterConfig>{str(data.parameterConfig).lower()}</parameterConfig>
                            <restartOrShutdown>{str(data.restartOrShutdown).lower()}</restartOrShutdown>
                            <logOrStateCheck>{str(data.logOrStateCheck).lower()}</logOrStateCheck>
                            <voiceTalk>{str(data.voiceTalk).lower()}</voiceTalk>
                            <transParentChannel>{str(data.transParentChannel).lower()}</transParentChannel>
                            <contorlLocalOut>{str(data.contorlLocalOut).lower()}</contorlLocalOut>
                            <alarmOutOrUpload>{str(data.alarmOutOrUpload).lower()}</alarmOutOrUpload>
                        </remotePermission>
                    </UserPermission>'''

            response = self.put(f"Security/UserPermission/{data.userID}", data=xml_data, auth=self.auth_type)
            json_response = to_json(response)
            return check_cam_response(json_response)
        except ex.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing
        except ex.ConnectionError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except ex.RequestException as e:
            log.debug("Ошибка запроса", e.response)
            return StatusCode.UnhandledExceptionError

    # Метод смены маски детекции
    @staticmethod
    @app.post("/setMask")
    async def set_detection_mask(inc_data: ChangeMaskData):
        log.debug(f"Incoming data: {inc_data}")

        a = Client(inc_data.rtsp_ip,
                   inc_data.username,
                   inc_data.password)
        try:
            auth_status = a.user_check()
            if auth_status == StatusCode.OK:
                return a.change_detection_mask(inc_data)
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
    @app.post('/set')
    async def set_config(inc_data: IncomingData):
        log.debug(f"Incoming data: {inc_data}")

        a = Client(inc_data.rtsp_ip,
                   inc_data.admin_data.username,
                   inc_data.admin_data.password)
        try:
            auth_status = a.user_check()
            if auth_status == StatusCode.OK:
                big_cam_json = {
                    "password": a.change_password(inc_data.admin_data),
                    "user_create": a.user_create(inc_data.user_data),
                    "user_permission": a.set_user_permissions(inc_data.user_permission),
                    "email": a.set_email_config(inc_data.email),
                    "ntp": a.set_ntp_config(inc_data.ntp),
                    "dns": a.set_eth_config(inc_data.dns),
                    "stream": a.set_stream_config(inc_data.stream),
                    "audio": a.set_audio_config(inc_data.audio),
                    "time": a.set_time_config(inc_data.timezone),
                    "osd_channel": a.set_osd_channel_config(inc_data.channel_name),
                    "osd_datetime": a.set_osd_datetime_config(),
                    "alarm_notifications": a.set_alarm_notifications_config(),
                    "detection": a.set_detection_config(inc_data.detection)
                }
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

    # Метод получения всей необходимой конфигурации с камеры
    @staticmethod
    @app.post("/get")
    async def get_config(get_data: GetData):
        log.debug(f"Incoming data: {get_data}")

        a = Client(get_data.rtsp_ip,
                   get_data.username,
                   get_data.password)
        try:
            auth_status = a.user_check()
            if auth_status == StatusCode.OK:
                time = Time(**a.get_time_config())
                ntp = Ntp(**a.get_ntp_config())
                eth = Ethernet(**a.get_eth_config())
                email = Email(**a.get_email_config())
                osd_datetime = OsdDT(**a.get_osd_datetime_config())
                osd_channel_name = OsdCN(**a.get_osd_channel_name_config())
                detection = Detection(**a.get_detection_config())
                notifications = Notifications(**a.get_event_notification_config())
                stream = Stream(**a.get_stream_config())
                audio = TwoWayAudioChannel(**a.get_audio_config())
                users = UserList(**a.get_users())
                json_data = {
                    "change_password": check_cam_response(a.change_password(get_data)),
                    "time": time.Time.dict(),
                    "ntp": ntp.NTPServer.dict(),
                    "eth": eth.IPAddress.dict(),
                    "email": email.mailing.dict(),
                    "osd_datetime": osd_datetime.OsdDatetime.dict(),
                    "osd_channel_name": osd_channel_name.channelNameOverlay.dict(),
                    "detection": detection.MotionDetection.dict(),
                    "notifications": notifications.EventTriggerNotificationList.EventTriggerNotification.dict(),
                    "stream": stream.StreamingChannel.dict(),
                    "audio": audio.dict(),
                    "users": users.UserList.dict()
                }
                print(users)
                return json_data
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


if __name__ == '__main__':
    uvicorn.run(app, host="127.0.0.1", port=5000)

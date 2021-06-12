import json
import logging
import os
import sys
from textwrap import wrap

import httpx
import uvicorn
import xmltodict
from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from data_models import *

app = FastAPI()

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


async def to_json(response):
    xml_dict = xmltodict.parse(response.text)
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
        self.password = password
        self.auth = httpx.BasicAuth(user, password) or httpx.DigestAuth(user, password)
        self.request = httpx.AsyncClient(timeout=30)


    async def getAsync(self, uri):
        try:
            return await self.request.get(f"http://{self.ip_address}/ISAPI/{uri}", auth=self.auth)
        except httpx.ConnectError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except httpx.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing

    async def putAsync(self, uri, data):
        try:
            return await self.request.put(f"http://{self.ip_address}/ISAPI/{uri}", data=data, auth=self.auth)
        except httpx.ConnectError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except httpx.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing

    async def postAsync(self, uri, data):
        try:
            return await self.request.post(f"http://{self.ip_address}/ISAPI/{uri}", data=data, auth=self.auth)
        except httpx.ConnectError:
            log.debug("Ошибка соединения с камерой")
            return StatusCode.ConnectionError
        except httpx.ConnectTimeout:
            log.debug("Камера не пингуется")
            return StatusCode.NotPing

    async def try_auth(self):
        response = await self.request.get(f"http://{self.ip_address}/ISAPI/Security/userCheck",
                                          auth=httpx.BasicAuth(self.user, self.password))
        if response.status_code == 404:
            return 404
        if "WWW-Authenticate: Digest" in response.headers:
            self.auth = httpx.DigestAuth(self.user, self.password)
        else:
            self.auth = httpx.BasicAuth(self.user, self.password)

    # Метод проверки текущего пароля на камеру
    async def user_check(self):
        auth_status = await self.try_auth()
        # проверяем текущий пароль на камере и конвертируем xml ответ камеры в json
        r = await self.getAsync("Security/userCheck")

        # если пароль из конструктора подошёл - возвращем 200
        if r.status_code == 200 and "200" in r.text:
            log.debug("Auth: Success")
            return StatusCode.OK

        elif r.status_code == 401 or "401" in r.text:
            r_json = await to_json(r)

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
                # self.basic = BasicAuth(self.user, password)
                self.password = password

                # проверяем новый пароль и конвертим ответ в json
                r = await self.getAsync("Security/userCheck")
                r_json = await to_json(r)

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
        elif auth_status == 404 or r.status_code == 404:
            log.debug("Auth: Device is not supported")
            return StatusCode.MethodNotFound
        else:
            log.debug(f"Auth: Default error. Response status code {r.status_code}")
            return r.status_code

    # Метод смены пароля
    # user_id = 1 //админская учётка.
    # user_id = 2 и тд остальные создаваеые пользователи
    async def change_password(self, data):
        xml_data = f'''
        <User>
            <id>{data.user_id}</id>
            <userName>{data.username}</userName>
            <password>{data.password}</password>
        </User>
        '''

        response = await self.putAsync(f"Security/users/{data.user_id}", data=xml_data)
        return await to_json(response)

    # Получить информацию о MAC адресе и серийном номере
    async def device_info(self):
        response = await self.getAsync("System/deviceInfo")
        return await to_json(response)

    async def get_users(self):
        response = await self.getAsync("Security/users")
        return await to_json(response)

    # Получить конфиг сети с камеры
    # ip, маска, шлюз и т.п
    async def get_eth_config(self):
        response = await self.getAsync("System/Network/interfaces/1/ipAddress")
        return await to_json(response)

    async def get_user_permission(self):
        response = await self.getAsync(f"Security/UserPermission")
        return await to_json(response)

    async def get_audio_config(self):
        response = await self.getAsync("System/TwoWayAudio/channels/1")
        return await to_json(response)

    async def get_stream_dynamic_cap(self):
        response = await self.getAsync("Streaming/channels/101/dynamicCap")
        return await to_json(response)

    async def get_stream_capabilities(self):
        response = await self.getAsync("Streaming/channels/101/capabilities")
        return await to_json(response)

    # Получить настройки видео-аудио конфигурации
    async def get_stream_config(self):
        response = await self.getAsync("Streaming/channels/101")
        return await to_json(response)

    # Получить настройки времени
    async def get_time_config(self):
        response = await self.getAsync("System/time")
        return await to_json(response)

    # Получить NTP конфиг
    async def get_ntp_config(self):
        response = await self.getAsync("System/time/NtpServers/1")
        return await to_json(response)

    # Получить SMTP конфиг
    async def get_email_config(self):
        response = await self.getAsync("System/Network/mailing/1")
        return await to_json(response)

    # Получить конфиг детекции
    async def get_detection_config(self):
        response = await self.getAsync("System/Video/inputs/channels/1/motionDetection")
        return await to_json(response)

    # Получить список wi-fi сетей которые видит устройство
    async def get_wifi_list(self):
        response = await self.getAsync("System/Network/interfaces/2/wireless/accessPointList")
        return await to_json(response)

    # Получить конфиг OSD времени
    async def get_osd_datetime_config(self):
        response = await self.getAsync("System/Video/inputs/channels/1/overlays/dateTimeOverlay")
        return await to_json(response)

    # Получить конфиг OSD имени устройства
    async def get_osd_channel_name_config(self):
        response = await self.getAsync("System/Video/inputs/channels/1/overlays/channelNameOverlay")
        return await to_json(response)

    # Получить конфиг отправки детекции
    async def get_event_notification_config(self):
        response = await self.getAsync("Event/triggers/VMD-1/notifications")
        return await to_json(response)

    # Сменить DNS
    async def set_eth_config(self, data):
        current_eth_data = IPAddress(**await self.get_eth_config())

        if current_eth_data.IPAddress.addressingType != "static":
            return f"Addressing type is {current_eth_data.IPAddress.addressingType}. Can`t set DNS"
        ip_address = current_eth_data.IPAddress.ipAddress
        subnet_mask = current_eth_data.IPAddress.subnetMask
        gateway = current_eth_data.IPAddress.DefaultGateway.ipAddress
        dns1 = data.PrimaryDNS.ipAddress
        dns2 = data.SecondaryDNS.ipAddress

        xml_data = f'''<IPAddress>
                            <ipVersion>v4</ipVersion>
                            <addressingType>static</addressingType>
                            <ipAddress>{ip_address}</ipAddress>
                            <subnetMask>{subnet_mask}</subnetMask>
                            <DefaultGateway>
                                <ipAddress>{gateway}</ipAddress>
                            </DefaultGateway>
                            <PrimaryDNS>
                                <ipAddress>{dns1}</ipAddress>
                            </PrimaryDNS>
                            <SecondaryDNS>
                                <ipAddress>{dns2}</ipAddress>
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
        response = await self.putAsync("System/Network/interfaces/1/ipAddress", data=xml_data)
        json_response = await to_json(response)
        return check_cam_response(json_response)

    # Настроить Video-Audio конфигурацию
    async def set_stream_config(self, data):
        xml_data = f'''
            <StreamingChannel>
                <Video>
                    <videoCodecType>{data.Video.videoCodecType}</videoCodecType>
                    <videoResolutionWidth>{data.Video.videoResolutionWidth}</videoResolutionWidth>
                    <videoResolutionHeight>{data.Video.videoResolutionHeight}</videoResolutionHeight>
                    <videoQualityControlType>{data.Video.videoQualityControlType}</videoQualityControlType>
                    <fixedQuality>{data.Video.fixedQuality}</fixedQuality>
                    <vbrUpperCap>{data.Video.vbrUpperCap}</vbrUpperCap>
                    <maxFrameRate>{data.Video.maxFrameRate}</maxFrameRate>
                    <GovLength>{data.Video.GovLength}</GovLength>
                </Video>
                <Audio>
                    <enabled>{str(data.Audio.enabled).lower()}</enabled>
                </Audio>
            </StreamingChannel>'''
        response = await self.putAsync("Streaming/channels/101", data=xml_data)
        json_response = await to_json(response)
        return check_cam_response(json_response)

    async def set_audio_config(self, data):
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
        </TwoWayAudioChannel>'''
        response = await self.putAsync("System/TwoWayAudio/channels/1", data=xml_data)
        json_response = await to_json(response)
        return check_cam_response(json_response)

    # Настроить SMTP
    async def set_email_config(self, data):
        device_info = await self.device_info()
        if device_info is None:
            return StatusCode.EmptyResponse
        serial_number = device_info['DeviceInfo']['serialNumber']
        data.sender.emailAddress = f"HK-{serial_number}@camera.ru"
        xml_data = f'''
                <mailing>
                    <id>1</id>
                    <sender>
                        <name>{data.sender.name}</name>
                        <emailAddress>{data.sender.emailAddress}</emailAddress>
                        <smtp>
                            <enableAuthorization>{str(data.sender.smtp.enableAuthorization).lower()}</enableAuthorization>
                            <enableSSL>{str(data.sender.smtp.enableSSL).lower()}</enableSSL>
                            <addressingFormatType>{data.sender.smtp.addressingFormatType}</addressingFormatType>
                            <hostName>{data.sender.smtp.hostName}</hostName>
                            <portNo>{data.sender.smtp.portNo}</portNo>
                            <accountName>{data.sender.smtp.accountName}</accountName>
                            <password>{data.sender.smtp.password}</password>
                            <enableTLS>false</enableTLS>
                            <startTLS>false</startTLS>
                        </smtp>
                    </sender>
                    <receiverList>
                        <receiver>
                            <id>1</id>
                            <name>{data.sender.name}</name>
                            <emailAddress>{data.sender.emailAddress}</emailAddress>
                        </receiver>
                    </receiverList>
                    <attachment>
                        <snapshot>
                            <enabled>{str(data.attachment.snapshot.enabled).lower()}</enabled>
                            <interval>2</interval>
                        </snapshot>
                    </attachment>
                </mailing>'''
        response = await self.putAsync("System/Network/mailing/1", data=xml_data)
        json_response = await to_json(response)
        return check_cam_response(json_response)

    # Настроить NTP
    async def set_ntp_config(self, data):
        xml_data = f'''
            <NTPServer>
                <id>1</id>
                <addressingFormatType>{data.addressingFormatType}</addressingFormatType>
                <hostName>{data.hostName}</hostName>
                <ipAddress>{data.ipAddress}</ipAddress>
                <portNo>{data.portNo}</portNo>
                <synchronizeInterval>{data.synchronizeInterval}</synchronizeInterval>
            </NTPServer>'''
        response = await self.putAsync("System/time/NtpServers/1", data=xml_data)
        json_response = await to_json(response)
        return check_cam_response(json_response)

    # Настроить время
    async def set_time_config(self, data):
        xml_data = f'''
            <Time>
                <timeMode>{data.timeMode}</timeMode>
                <timeZone>{data.timeZone}</timeZone>
            </Time>'''
        response = await self.putAsync("System/time", data=xml_data)
        json_response = await to_json(response)
        return check_cam_response(json_response)

    # Отключить отображение имени устройства на видео-потоке
    async def set_osd_channel_config(self, data):
        xml_data = f'''
        <channelNameOverlay>
            <enabled>{str(data.enabled).lower()}</enabled>
            <positionX>512</positionX>
            <positionY>64</positionY>
        </channelNameOverlay>'''
        response = await self.putAsync("System/Video/inputs/channels/1/overlays/channelNameOverlay",
                                       data=xml_data)
        json_response = await to_json(response)
        return check_cam_response(json_response)

    # Включить отображение времени на видео-потоке
    async def set_osd_datetime_config(self, data):
        xml_data = f'''
        <DateTimeOverlay>
            <enabled>{str(data.enabled).lower()}</enabled>
            <positionX>0</positionX>
            <positionY>544</positionY>
            <dateStyle>{data.dateStyle}</dateStyle>
            <timeStyle>{data.timeStyle}</timeStyle>
            <displayWeek>{str(data.displayWeek).lower()}</displayWeek>
        </DateTimeOverlay> '''
        response = await self.putAsync("System/Video/inputs/channels/1/overlays/dateTimeOverlay",
                                       data=xml_data)
        json_response = await to_json(response)
        return check_cam_response(json_response)

    # Настроить способ отправки обнаруженных алармов
    # В данном случае замеченная детекция будет отправлять на email
    async def set_alarm_notifications_config(self, data):
        xml_data = f'''
        <EventTriggerNotificationList>
            <EventTriggerNotification>
                <id>{data.EventTriggerNotification.id}</id>
                <notificationMethod>{data.EventTriggerNotification.notificationMethod}</notificationMethod>
                <notificationRecurrence>{data.EventTriggerNotification.notificationRecurrence}</notificationRecurrence>
            </EventTriggerNotification>
        </EventTriggerNotificationList>
        '''

        #   id <!—req, xs:string;id </id>
        #   notificationMethod <!—req, xs:string, “email,IM,IO,syslog,HTTP,FTP,beep, ptz, record, monitorAlarm,
        #   center, LightAudioAlarm,focus,trace,cloud”
        #   notificationRecurrence <!—opt, xs:string, “beginning, beginningandend, recurring” 
        response = await self.putAsync("Event/triggers/VMD-1/notifications", data=xml_data)
        json_response = await to_json(response)
        return check_cam_response(json_response)

    # Настройка конфигурации детекции движения
    # Включается функционал отлова движения, заполняется маска детекции
    async def set_detection_config(self, data):
        xml_data = f'''
        <MotionDetection>
            <enabled>{str(data.enabled).lower()}</enabled>
            <enableHighlight>{str(data.enableHighlight).lower()}</enableHighlight>
            <samplingInterval>2</samplingInterval>
            <startTriggerTime>500</startTriggerTime>
            <endTriggerTime>500</endTriggerTime>
            <regionType>grid</regionType>
            <Grid>
                <rowGranularity>18</rowGranularity>
                <columnGranularity>22</columnGranularity>
            </Grid>
            <MotionDetectionLayout>
                <sensitivityLevel>{data.MotionDetectionLayout.sensitivityLevel}</sensitivityLevel>
                <layout>
                    <gridMap>{data.MotionDetectionLayout.layout.gridMap}</gridMap>
                </layout>
            </MotionDetectionLayout>
        </MotionDetection>'''

        response = await self.putAsync("System/Video/inputs/channels/1/motionDetection",
                                       data=xml_data)
        json_response = await to_json(response)
        return check_cam_response(json_response)

    async def reboot(self):
        response = await self.putAsync("System/reboot", data="")
        json_response = await to_json(response)
        return check_cam_response(json_response)

    async def _get_detection_mask(self):
        response = await self.getAsync("System/Video/inputs/channels/1/motionDetection/layout")
        json_response = await to_json(response)
        mdd = MotionDetectionLayoutData(**json_response)
        mask = [*mdd.MotionDetectionLayout.layout.gridMap]
        mask_for_lk = []
        for index, value in enumerate(mask, start=1):
            if index % 6 == 0:
                if value == "8" or value == "9":
                    mask_for_lk.append("10")
                elif value == "4" or value == "5":
                    mask_for_lk.append("01")
                elif value == "c" or value == "d":
                    mask_for_lk.append("11")
                elif value == "0" or value == "1":
                    mask_for_lk.append("00")
            else:
                if value == "0":
                    mask_for_lk.append("0000")
                elif value == "1":
                    mask_for_lk.append("0001" + bin(int(value, 16))[2:])
                elif value == "3":
                    mask_for_lk.append("0011" + bin(int(value, 16))[2:])
                elif value == "7":
                    mask_for_lk.append("0111" + bin(int(value, 16))[2:])
                elif value == "f":
                    mask_for_lk.append("1111")
        # assert len(str.join("", mask_for_lk)) == 396 or assert len(str.join("", mask_for_lk)) == 360
        return {"gridMap": str.join("", mask_for_lk)}

    # Цель метода - сменить маску детекции на камере, когда клиент её поменял через ЛК
    # На вход должна поступить маска детекции в виде строки из 396 символов.
    # Значение символа: либо 1 либо 0. Если 1 - значит ячейка в ЛК активирована, и её нужно отрисовать на камере
    async def _set_detection_mask(self, data):
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

        array_22chars = wrap(data.gridMap, 22)  # массив в ввиде ['1111111111111111111111']
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
        </MotionDetectionGridLayout>'''
        response = await self.putAsync("System/Video/inputs/channels/1/motionDetection/layout/gridLayout",
                                       data=xml_data)
        json_response = await to_json(response)
        return check_cam_response(json_response)

    # Метод создания пользователя
    async def user_create(self, data):
        xml_data = f'''<User>
                        <userName>{data.User.userName}</userName>
                        <password>{data.User.password}</password>
                        <userLevel>{data.User.userLevel}</userLevel>
                    </User>'''
        response = await self.postAsync("Security/users", data=xml_data)
        json_response = await to_json(response)
        if response.status_code == StatusCode.DeviceError:
            return "User already created"
        return check_cam_response(json_response)

    # Настройка прав пользователя
    async def set_user_permissions(self, data):
        user_id = data.UserPermission.id
        xml_data = f'''<UserPermission>
                    <id>{data.UserPermission.id}</id>
                    <userID>{data.UserPermission.userID}</userID>
                    <userType>{data.UserPermission.userType}</userType>
                    <remotePermission>
                        <playBack>{str(data.UserPermission.remotePermission.playBack).lower()}</playBack>
                        <preview>{str(data.UserPermission.remotePermission.preview).lower()}</preview>
                        <record>{str(data.UserPermission.remotePermission.record).lower()}</record>
                        <ptzControl>{str(data.UserPermission.remotePermission.ptzControl).lower()}</ptzControl>
                        <upgrade>{str(data.UserPermission.remotePermission.upgrade).lower()}</upgrade>
                        <parameterConfig>{str(data.UserPermission.remotePermission.parameterConfig).lower()}</parameterConfig>
                        <restartOrShutdown>{str(data.UserPermission.remotePermission.restartOrShutdown).lower()}</restartOrShutdown>
                        <logOrStateCheck>{str(data.UserPermission.remotePermission.logOrStateCheck).lower()}</logOrStateCheck>
                        <voiceTalk>{str(data.UserPermission.remotePermission.voiceTalk).lower()}</voiceTalk>
                        <transParentChannel>{str(data.UserPermission.remotePermission.transParentChannel).lower()}</transParentChannel>
                        <contorlLocalOut>{str(data.UserPermission.remotePermission.contorlLocalOut).lower()}</contorlLocalOut>
                        <alarmOutOrUpload>{str(data.UserPermission.remotePermission.alarmOutOrUpload).lower()}</alarmOutOrUpload>
                    </remotePermission>
                </UserPermission>'''

        response = await self.putAsync(f"Security/UserPermission/{user_id}", data=xml_data)
        json_response = await to_json(response)
        return check_cam_response(json_response)

    # Метод смены маски детекции
    @staticmethod
    @app.post("/getMask")
    async def get_detection_mask(inc_data: GetMaskData):
        log.debug(f"Incoming data: {inc_data}")

        a = Client(inc_data.rtsp_ip,
                   inc_data.username,
                   inc_data.password)
        auth_status = await a.user_check()
        if auth_status == StatusCode.OK:
            response = await a._get_detection_mask()
            await a.request.aclose()
            return response
        else:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=auth_status)

    # Метод смены маски детекции
    @staticmethod
    @app.post("/setMask")
    async def set_detection_mask(inc_data: SetMaskData):
        log.debug(f"Incoming data: {inc_data}")

        a = Client(inc_data.rtsp_ip,
                   inc_data.username,
                   inc_data.password)
        auth_status = await a.user_check()
        if auth_status == StatusCode.OK:
            response = await a._set_detection_mask(inc_data)
            await a.request.aclose()
            return response
        else:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=auth_status)

    @staticmethod
    @app.post('/set')
    async def set_config(inc_data: IncomingData):
        log.debug(f"Incoming data: {inc_data}")

        a = Client(inc_data.rtsp_ip,
                   inc_data.admin_data.username,
                   inc_data.admin_data.password)
        auth_status = await a.user_check()
        if auth_status == StatusCode.OK:
            response = {
                "change_password": check_cam_response(await a.change_password(inc_data.admin_data)),
                "Time": await a.set_time_config(inc_data.Time),
                "NTPServer": await a.set_ntp_config(inc_data.NTPServer),
                "IPAddress": await a.set_eth_config(inc_data.IPAddress),
                "mailing": await a.set_email_config(inc_data.mailing),
                "OsdDatetime": await a.set_osd_datetime_config(inc_data.OsdDatetime),
                "channelNameOverlay": await a.set_osd_channel_config(inc_data.channelNameOverlay),
                "MotionDetection": await a.set_detection_config(inc_data.MotionDetection),
                "EventTriggerNotificationList": await a.set_alarm_notifications_config(
                    inc_data.EventTriggerNotificationList),
                "StreamingChannel": await a.set_stream_config(inc_data.StreamingChannel),
                "TwoWayAudioChannel": await a.set_audio_config(inc_data.TwoWayAudioChannel),
                "UserList": await a.user_create(inc_data.UserList),
                "UserPermissionList": await a.set_user_permissions(inc_data.UserPermissionList)
            }
            await a.request.aclose()
            return response
        else:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=auth_status)

    # Метод получения всей необходимой конфигурации с камеры
    @staticmethod
    @app.post("/get")
    async def get_config(get_data: GetData):
        log.debug(f"Incoming data: {get_data}")

        a = Client(get_data.rtsp_ip,
                   get_data.username,
                   get_data.password)
        auth_status = await a.user_check()

        if auth_status == StatusCode.OK:
            try:
                users = UserList(**await a.get_users())
            except ValidationError:
                users = UserListL(**await a.get_users())
            try:
                user_permission = UserPermissionList(**await a.get_user_permission())
            except ValidationError:
                user_permission = UserPermissionListL(**await a.get_user_permission())

            serial = {"serial": DeviceInfo(**await a.device_info()).DeviceInfo.serialNumber}
            motion_detection = MotionDetection(**await a.get_detection_config())
            motion_detection.MotionDetection.MotionDetectionLayout.layout = await a._get_detection_mask()
            response = dict()

            methods_list = (
                Time(**await a.get_time_config()).dict(),
                NTPServer(**await a.get_ntp_config()).dict(),
                IPAddress(**await a.get_eth_config()).dict(),
                Mailing(**await a.get_email_config()).dict(),
                OsdDatetime(**await a.get_osd_datetime_config()).dict(),
                ChannelNameOverlay(**await a.get_osd_channel_name_config()).dict(),
                motion_detection.dict(),
                EventTriggerNotificationList(**await a.get_event_notification_config()).dict(),
                StreamingChannel(**await a.get_stream_config()).dict(),
                TwoWayAudioChannel(**await a.get_audio_config()).dict(),
                users.dict(),
                user_permission.dict(),
                serial
            )
            await a.request.aclose()
            for x in methods_list:
                response.update(x)
            return response
        else:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=auth_status)


if __name__ == '__main__':
    uvicorn.run(app, host="127.0.0.1", port=5000)

import json
import logging
import os
import sys
from textwrap import wrap

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
        self.auth_type = "basic/digest"
        self.put = Put(self.ip_address)
        self.get = Get(self.ip_address)
        self.basic = HTTPBasicAuth(self.user, password)
        self.digest = HTTPDigestAuth(self.user, password)

    def __call__(self, password):
        self.basic = HTTPBasicAuth(self.user, password)
        self.digest = HTTPDigestAuth(self.user, password)

    def __setitem__(self, value):
        self.auth_type = value

    def check_auth(self):
        try:
            r = self.get("Security/userCheck", auth=self.basic)
            if r.headers.__contains__("WWW-Authenticate"):
                self.__setitem__("digest")
            else:
                self.__setitem__("basic")
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Метод подстановки авторизации в запросы
    def current_auth(self):
        if self.auth_type == "basic":
            return self.basic
        else:
            return self.digest

    # Метод проверки текущего пароля на камеру
    def user_check(self):
        # импортируем список паролей на камеру
        with open(os.path.abspath('passwords.json'), "r") as passwords:
            password_list = json.load(passwords)

        try:
            # Проверяем тип авторизации, digest или basic
            # Полученный результат записывается в конструкторе класса
            self.check_auth()

            # проверяем текущий пароль на камере и конвертируем xml ответ камеры в json
            r = self.get("Security/userCheck", auth=self.current_auth())
            r_json = to_json(r)

            # если пароль из конструктора подошёл - возвращем 200
            if r.status_code == 200:
                log.debug("Auth: Success")
                return {"Auth": "200"}

            elif r.status_code == 401:
                # если камера заблокирована из-за неуспешных попыток авторизации - не начинать перебор, вернуть ошибку
                if r_json['userCheck']['lockStatus'] == "lock":
                    log.debug(f"Camera is locked, unlock time {r_json['userCheck']['unlockTime']} sec.")
                    return {"Auth": "200"}

                log.debug("Auth: Unauthorized")
                # взять пароль из списка паролей
                for password in password_list['values']:
                    # поменять пароль в конструкторе(для выполнения запроса с новым паролем)
                    self.__call__(password)

                    # проверяем новый пароль и конвертим ответ в json
                    r = self.get("Security/userCheck", auth=self.current_auth())
                    r_json = to_json(r)

                    if r.status_code == 200:
                        log.debug("Auth: Success")
                        return {"Auth": "200"}

                    elif r.status_code == 401:
                        # если камера заблокировалась из-за неуспешных попыток авторизации - прервать цикл,
                        # вернуть ошибку
                        if r_json['userCheck']['lockStatus'] == "lock":
                            log.debug(f"Camera is locked, unlock time {r_json['userCheck']['unlockTime']} sec.")
                            return {"Auth": "401"}
                        log.debug("Auth: Unauthorized")

            # если на запрос вернулся статус 404 - то такого метода нет на устройстве
            # значит либо камера старая и не поддерживает такой метод, либо это не камера вовсе
            elif r.status_code == 404:
                log.debug("Auth: Device is not supported")
                return {"Auth": "404"}
            else:
                log.debug(f"Auth: Default error. Response status code {r.status_code}")
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Метод смены пароля
    def change_password(self, password="tvmix333"):
        try:
            xml_data = f'''
            <User>
                <id>1</id>
                <userName>{self.user}</userName>
                <password>{password}</password>
            </User>
            '''

            r = self.put("Security/users/1", data=xml_data, auth=self.current_auth())
            return {"Auth": r.status_code}
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Получить информацию о MAC адресе и серийном номере
    def device_info(self):
        try:
            response = self.get("System/deviceInfo", auth=self.current_auth())
            return to_json(response)
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Получить конфиг сети с камеры
    # ip, маска, шлюз и т.п
    def get_eth_config(self):
        try:
            response = self.get("System/Network/interfaces/1/ipAddress", auth=self.current_auth())
            return to_json(response)
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Получить настройки видео-аудио конфигурации
    def get_stream_config(self):
        try:
            response = self.get("Streaming/channels/101", auth=self.current_auth())
            return to_json(response)
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Получить настройки времени
    def get_time_config(self):
        try:
            response = self.get("System/time", auth=self.current_auth())
            return to_json(response)
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Получить NTP конфиг
    def get_ntp_config(self):
        try:
            response = self.get("System/time/NtpServers/1", auth=self.current_auth())
            return to_json(response)
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Получить SMTP конфиг
    def get_email_config(self):
        try:
            response = self.get("System/Network/mailing/1", auth=self.current_auth())
            return to_json(response)
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Получить конфиг детекции
    def get_detection_config(self):
        try:
            response = self.get("System/Video/inputs/channels/1/motionDetection", auth=self.current_auth())
            return to_json(response)
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Получить список wi-fi сетей которые видит устройство
    def get_wifi_list(self):
        try:
            response = self.get("System/Network/interfaces/2/wireless/accessPointList", auth=self.current_auth())
            return to_json(response)
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Получить конфиг OSD времени
    def get_osd_datetime_config(self):
        try:
            response = self.get("System/Video/inputs/channels/1/overlays/dateTimeOverlay", auth=self.current_auth())
            return to_json(response)
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Получить конфиг OSD имени устройства
    def get_osd_channel_name_config(self):
        try:
            response = self.get("System/Video/inputs/channels/1/overlays/channelNameOverlay",
                                auth=self.current_auth())
            return to_json(response)
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Получить конфиг отправки детекции
    def get_event_notification_config(self):
        try:
            response = self.get("Event/triggers/VMD-1/notifications", auth=self.current_auth())
            return to_json(response)
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Сменить DNS
    def set_eth_config(self, dns=None):
        if dns is None:
            dns = ["217.24.176.230", "217.24.177.2"]

        current_eth_data = self.get_eth_config()
        if current_eth_data == 701:
            return 701
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
                        <ipAddress>{dns[0]}</ipAddress>
                    </PrimaryDNS>
                    <SecondaryDNS>
                        <ipAddress>{dns[1]}</ipAddress>
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
            response = self.put("System/Network/interfaces/1/ipAddress", data=xml_data, auth=self.current_auth())
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Настроить Video-Audio конфигурацию
    def set_stream_config(self, mic="false"):
        xml_data = f'''
            <StreamingChannel>
                <Video>
                    <videoCodecType>H.264</videoCodecType>
                    <videoResolutionWidth>1280</videoResolutionWidth>
                    <videoResolutionHeight>720</videoResolutionHeight>
                    <videoQualityControlType>VBR</videoQualityControlType>
                    <fixedQuality>100</fixedQuality>
                    <vbrUpperCap>1024</vbrUpperCap>
                    <maxFrameRate>1200</maxFrameRate>
                    <GovLength>20</GovLength>
                </Video>
                <Audio>
                    <enabled>{mic}</enabled>
                    <audioCompressionType>MP2L2</audioCompressionType>
                </Audio>
            </StreamingChannel>'''

        try:
            response = self.put("Streaming/channels/101", data=xml_data, auth=self.current_auth())
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Настроить SMTP
    def set_email_config(self):
        device_info = self.device_info()
        if device_info is None:
            return "device_info is empty"
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
                            <addressingFormatType>hostname</addressingFormatType>
                            <hostName>alarm.profintel.ru</hostName>
                            <portNo>15006</portNo>
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
            response = self.put("System/Network/mailing/1", data=xml_data, auth=self.current_auth())
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Настроить NTP
    def set_ntp_config(self):
        xml_data = '''
            <NTPServer>
                <id>1</id>
                <addressingFormatType>ipaddress</addressingFormatType>
                <ipAddress>217.24.176.232</ipAddress>
                <portNo>123</portNo>
                <synchronizeInterval>30</synchronizeInterval>
            </NTPServer>'''
        try:
            response = self.put("System/time/NtpServers/1", data=xml_data, auth=self.current_auth())
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Настроить время
    def set_time_config(self, timezone="5"):
        xml_data = f'''
            <Time>
                <timeMode>NTP</timeMode>
                <timeZone>CST-{timezone}:00:00</timeZone>
            </Time>
        '''

        try:
            response = self.put("System/time", data=xml_data, auth=self.current_auth())
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Отключить отображение имени устройства на видео-потоке
    def set_osd_channel_config(self):
        xml_data = '''
        <channelNameOverlay>
            <enabled>false</enabled>
            <positionX>512</positionX>
            <positionY>64</positionY>
        </channelNameOverlay>
        '''

        try:
            response = self.put("System/Video/inputs/channels/1/overlays/channelNameOverlay", data=xml_data,
                                auth=self.current_auth())
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

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
                                data=xml_data, auth=self.current_auth())
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

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

        try:
            response = self.put("Event/triggers/VMD-1/notifications",
                                data=xml_data, auth=self.current_auth())
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Настройка конфигурации детекции движения
    # Включается функционал отлова движения, заполняется маска детекции
    def set_detection_config(self):
        xml_data = '''
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
                <sensitivityLevel>60</sensitivityLevel>
                <layout>
                    <gridMap>fffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffcfffffc</gridMap>
                </layout>
            </MotionDetectionLayout>
        </MotionDetection>
        '''

        try:
            response = self.put("System/Video/inputs/channels/1/motionDetection",
                                data=xml_data, auth=self.current_auth())
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    # Цель метода - сменить маску детекции на камере, когда клиент её поменял через ЛК
    # На вход должна поступить маска детекции в виде строки из 396 символов.
    # Знчение символа: либо 1 либо 0. Если 1 - значит ячейка в ЛК активирована, и её нужно отрисовать на камере
    def set_detection_mask(self, mask_from_lk=None):
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
                    sum = 0  # Сумма hex_values, объявлена чтобы её можно было использовать в коде
                    for value in sub_array1:  # перебор значений в sub_array чтобы выяснить сумму
                        if int(value) == 1:
                            sum += hex_values[index]
                        else:
                            sum += 0
                        index += 1
                    grid_for_cam.append(hex(sum).split('x')[-1])  # Добавление hex значения в конец массива
                    sum = 0  # сбрасываем результат предыдущих вычислений

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
                         auth=self.current_auth())
            json_response = to_json(response)
            return json_response['ResponseStatus']['statusString'], json_response['ResponseStatus']['requestURL']
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            raise e("Нет соединения с камерой")

    @staticmethod
    @app.route('/set', methods=["POST"])
    def set_config():
        data = request.get_json()
        log.debug(data)
        ip = data['data']['rtsp_ip']
        user = data['data']['user']
        password = data['data']['password']

        a = Client(ip, user, password)
        try:
            auth_status = a.user_check()
            if auth_status.get("Auth") == "200":
                big_cam_json = (
                    a.change_password(),
                    a.set_email_config(),
                    a.set_ntp_config(),
                    a.set_eth_config(),
                    a.set_stream_config(),
                    a.set_time_config(),
                    a.set_osd_channel_config(),
                    a.set_osd_datetime_config(),
                    a.set_alarm_notifications_config(),
                    a.set_detection_config()
                )
                log.debug(json.dumps(big_cam_json, indent=4))
                return jsonify(big_cam_json)
            else:
                return auth_status
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            log.exception(e)
            raise e("Нет соединения с камерой")

    @staticmethod
    @app.route('/get', methods=["POST"])
    def get_config():
        data = request.get_json()
        log.debug(data)
        ip = data['data']['rtsp_ip']
        user = data['data']['user']
        password = data['data']['password']

        a = Client(ip, user, password)
        try:
            auth_status = a.user_check()
            if auth_status.get("Auth") == "200":
                big_cam_json = (
                    a.change_password(),
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
        except (ex.ConnectTimeout, ex.ConnectionError) as e:
            log.exception(e)
            raise e("Нет соединения с камерой")


if __name__ == '__main__':
    app.run(debug=False)

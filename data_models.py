from pydantic import BaseModel, validator
from typing import Optional, List


####################################
class TwoWayAudioChannelData(BaseModel):
    audioCompressionType: str
    audioInputType: str
    microphoneVolume: Optional[int]
    noisereduce: bool
    audioBitRate: Optional[int]


class TwoWayAudioChannel(BaseModel):
    TwoWayAudioChannel: TwoWayAudioChannelData


####################################
class Video(BaseModel):
    videoCodecType: str
    videoResolutionWidth: int
    videoResolutionHeight: int
    videoQualityControlType: str
    constantBitRate: int
    fixedQuality: int
    vbrUpperCap: int
    maxFrameRate: int
    GovLength: int


class Audio(BaseModel):
    enabled: bool


class StreamingChannelData(BaseModel):
    Video: Video
    Audio: Audio


class StreamingChannel(BaseModel):
    StreamingChannel: StreamingChannelData


####################################
class TimeData(BaseModel):
    timeMode: str
    timeZone: str


class Time(BaseModel):
    Time: TimeData


####################################
class NTPServerData(BaseModel):
    addressingFormatType: str
    ipAddress: str
    hostName: Optional[str]
    portNo: int
    synchronizeInterval: int


class NTPServer(BaseModel):
    NTPServer: NTPServerData


##################################
class PrimaryDNS(BaseModel):
    ipAddress: str


class SecondaryDNS(BaseModel):
    ipAddress: str


class DefaultGateway(BaseModel):
    ipAddress: str


class IPAddressData(BaseModel):
    addressingType: str
    ipAddress: str
    subnetMask: str
    DefaultGateway: DefaultGateway
    PrimaryDNS: PrimaryDNS
    SecondaryDNS: SecondaryDNS


class IPAddress(BaseModel):
    IPAddress: IPAddressData


##################################
class Smtp(BaseModel):
    addressingFormatType: str
    hostName: Optional[str]
    ipAddress: Optional[str]
    portNo: Optional[int]
    enableAuthorization: bool
    accountName: Optional[str]
    password: Optional[str]
    enableSSL: Optional[bool] = False


class Sender(BaseModel):
    name: Optional[str]
    emailAddress: Optional[str]
    smtp: Smtp


class Snapshot(BaseModel):
    enabled: bool


class Attachment(BaseModel):
    snapshot: Snapshot


class MailingData(BaseModel):
    sender: Sender
    attachment: Attachment


class Mailing(BaseModel):
    mailing: MailingData


###################################
class OsdDatetimeData(BaseModel):
    enabled: bool
    dateStyle: str
    timeStyle: str
    displayWeek: bool


class OsdDatetime(BaseModel):
    OsdDatetime: OsdDatetimeData


###################################
class ChannelNameOverlayData(BaseModel):
    enabled: bool


class ChannelNameOverlay(BaseModel):
    channelNameOverlay: ChannelNameOverlayData


###################################
class Layout(BaseModel):
    gridMap: str


class MotionDetectionLayout(BaseModel):
    sensitivityLevel: int
    layout: Layout


class MotionDetectionLayoutData(BaseModel):
    MotionDetectionLayout: MotionDetectionLayout


class MotionDetectionData(BaseModel):
    enabled: bool
    enableHighlight: bool
    MotionDetectionLayout: MotionDetectionLayout


class MotionDetection(BaseModel):
    MotionDetection: MotionDetectionData


###################################
class EventTriggerNotification(BaseModel):
    id: str
    notificationMethod: str
    notificationRecurrence: str


class EventTriggerNotificationListData(BaseModel):
    EventTriggerNotification: EventTriggerNotification


class EventTriggerNotificationList(BaseModel):
    EventTriggerNotificationList: EventTriggerNotificationListData


# Для создания второго пользователя
# user_id           - id пользователя на камере. Максимальное значение 16
# username          - имя пользователя
# password          - пароль от учётки пользователя
# userLevel         - тип учётной записи. Возможные варианты: Administrator, Operator, Viewer
############################################
class UserData(BaseModel):
    id: int
    userName: str
    password: Optional[str]
    userLevel: str


class UserListData(BaseModel):
    User: UserData


class UserListDataL(BaseModel):
    User: List[UserData]


class UserList(BaseModel):
    UserList: UserListData


class UserListL(BaseModel):
    UserList: UserListDataL


############################################
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
# contorlLocalOut       - настройка видео-выхода
# alarmOutOrUpload      - центр уведомлений/тревожные выходы
class RemotePermission(BaseModel):
    record: bool
    playBack: bool
    preview: bool
    ptzControl: bool
    upgrade: bool
    parameterConfig: bool
    restartOrShutdown: bool
    logOrStateCheck: bool
    voiceTalk: bool
    transParentChannel: bool
    contorlLocalOut: bool
    alarmOutOrUpload: bool


class UserPermission(BaseModel):
    id: int
    userID: int
    userType: str
    remotePermission: RemotePermission


class UserPermissionListData(BaseModel):
    UserPermission: UserPermission


class UserPermissionList(BaseModel):
    UserPermissionList: UserPermissionListData


class UserPermissionListDataL(BaseModel):
    UserPermission: List[UserPermission]


class UserPermissionListL(BaseModel):
    UserPermissionList: UserPermissionListDataL


##############################################
# Для инициализации конструктора
# user_id           - id пользователя на камере. Учётная запись admin ВСЕГДА имеет user_id = 1
# username          - имя пользователя, по умолчанию admin
# password          - пароль от учётки admin
class AdminData(BaseModel):
    user_id: int = 1
    username: str = "admin"
    password: str


class IncomingData(BaseModel):
    rtsp_ip: str
    admin_data: AdminData
    Time: TimeData
    NTPServer: NTPServerData
    IPAddress: IPAddressData
    mailing: MailingData
    OsdDatetime: OsdDatetimeData
    channelNameOverlay: ChannelNameOverlayData
    MotionDetection: MotionDetectionData
    EventTriggerNotificationList: EventTriggerNotificationListData
    StreamingChannel: StreamingChannelData
    TwoWayAudioChannel: TwoWayAudioChannelData
    UserList: UserListData
    UserPermissionList: UserPermissionListData


class GetData(BaseModel):
    rtsp_ip: str
    username: str
    password: str
    user_id: int


# Для смены маски детекции
class SetMaskData(BaseModel):
    rtsp_ip: str
    username: str
    password: str
    gridMap: str

    @validator("gridMap")
    def len_grid_map(cls, v):
        if len(v) < 396:
            raise ValueError("Value less than 396")
        elif len(v) > 396:
            raise ValueError("Value greater than 396")
        return v


class GetMaskData(BaseModel):
    rtsp_ip: str
    username: str
    password: str

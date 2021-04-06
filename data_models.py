from pydantic import BaseModel
from typing import Optional, List


####################################
class TwoWayAudioChannel(BaseModel):
    audioCompressionType: str
    audioInputType: str
    noisereduce: bool
    audioBitRate: Optional[int]


class TwoWayAudioChannel(BaseModel):
    TwoWayAudioChannel: TwoWayAudioChannel


####################################
class Video(BaseModel):
    videoCodecType: str
    videoResolutionWidth: int
    videoResolutionHeight: int
    videoQualityControlType: str
    constantBitRate: int
    vbrUpperCap: int
    maxFrameRate: int
    GovLength: int


class Audio(BaseModel):
    enabled: bool


class StreamingChannel(BaseModel):
    Video: Video
    Audio: Audio


class Stream(BaseModel):
    StreamingChannel: StreamingChannel


####################################
class TimeData(BaseModel):
    timeMode: str
    timeZone: str


class Time(BaseModel):
    Time: TimeData


####################################
class NTPServer(BaseModel):
    addressingFormatType: str
    ipAddress: str
    hostName: Optional[str]
    portNo: int
    synchronizeInterval: int


class Ntp(BaseModel):
    NTPServer: NTPServer


##################################
class PrimaryDNS(BaseModel):
    ipAddress: str


class SecondaryDNS(BaseModel):
    ipAddress: str


class EthData(BaseModel):
    addressingType: str
    PrimaryDNS: PrimaryDNS
    SecondaryDNS: SecondaryDNS


class Ethernet(BaseModel):
    IPAddress: EthData


##################################
class Smtp(BaseModel):
    addressingFormatType: str
    hostName: Optional[str]
    ipAddress: Optional[str]
    portNo: Optional[int]
    enableAuthorization: bool
    accountName: str


class Sender(BaseModel):
    name: str
    emailAddress: str
    smtp: Smtp


class Snapshot(BaseModel):
    enabled: bool


class Attachment(BaseModel):
    snapshot: Snapshot


class Mailing(BaseModel):
    sender: Sender
    attachment: Attachment


class Email(BaseModel):
    mailing: Mailing


###################################
class OsdDatetime(BaseModel):
    enabled: bool
    dateStyle: str
    timeStyle: str
    displayWeek: bool


class OsdDT(BaseModel):
    OsdDatetime: OsdDatetime


###################################
class ChannelNameOverlay(BaseModel):
    enabled: bool


class OsdCN(BaseModel):
    channelNameOverlay: ChannelNameOverlay


###################################
class Layout(BaseModel):
    gridMap: str


class MotionDetectionLayout(BaseModel):
    sensitivityLevel: int
    layout: Layout


class DetectionData(BaseModel):
    enabled: bool
    enableHighlight: bool
    MotionDetectionLayout: MotionDetectionLayout


class Detection(BaseModel):
    MotionDetection: DetectionData


###################################
class EventTriggerNotification(BaseModel):
    id: str
    notificationMethod: str
    notificationRecurrence: str


class EventTriggerNotificationList(BaseModel):
    EventTriggerNotification: EventTriggerNotification


class Notifications(BaseModel):
    EventTriggerNotificationList: EventTriggerNotificationList


############################################
class UserData(BaseModel):
    id: int
    userName: str
    userLevel: str


class User(BaseModel):
    User: List[UserData]


class UserList(BaseModel):
    UserList: User

############################################

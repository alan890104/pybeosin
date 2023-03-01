# coding: utf-8
import hashlib
import json
import os
import time
from typing import Dict, List, Any, TypeVar, Generic, Tuple
import requests
from dataclasses import dataclass
from collections import OrderedDict
from dacite import from_dict
import logging


LOGGER = logging.Logger(name="KYT", level=logging.DEBUG)
HANDLER = logging.StreamHandler()
HANDLER.setLevel(logging.DEBUG)
FORMAT = "%(asctime)s  %(name)s %(levelname)-5s %(message)s"
FORMATTER = logging.Formatter(fmt=FORMAT)
HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(HANDLER)


@dataclass(frozen=True)
class Tag:
    tagType: str
    tag: str


@dataclass(frozen=True)
class MaliceData:
    isMalice: bool
    address: str
    tags: List[Tag]


@dataclass(frozen=True)
class SanctionData:
    isSanction: bool
    address: str
    standard: str
    entity: str


@dataclass(frozen=True)
class AddrScore:
    pass


@dataclass(frozen=True)
class TxScore:
    pass


@dataclass(frozen=True)
class AddrDetail:
    address: str
    balance: float
    received: float
    sent: float
    inflow: int
    outflow: int
    firstTx: str
    firstTxTime: int
    firstTxAmount: float
    lastTx: str
    lastTxTime: int
    lastTxAmount: float


@dataclass(frozen=True)
class TxDetail:
    pass


T = TypeVar("T", MaliceData, SanctionData)


class BeosinKYT:
    def __init__(
        self,
        appSecret: str,
        appId: str,
        appRoot: str,
    ) -> None:
        assert appSecret
        assert appId
        assert appRoot
        self.appSecret = appSecret
        self.appId = appId
        self.appRoot = appRoot

    def createSign(self, params: Dict[str, str], key: str):
        sb = "appId={}&method={}&params={}address={}, platform={}{}&timestamp={}&url={}&key={}".format(
            params["appId"],
            params["method"],
            "{",
            params["params"]["address"],
            params["params"]["platform"],
            "}",
            params["timestamp"],
            params["url"],
            params["key"],
        )
        sign = hashlib.md5(sb.encode("utf-8")).hexdigest().upper()
        return sign

    def request(
        self,
        url: str,
        method: str,
        query: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """
        Make request and return (code, msg, data)
        """
        sortedMap = OrderedDict()
        sortedMap["appId"] = self.appId
        sortedMap["method"] = method
        sortedMap["params"] = query
        sortedMap["timestamp"] = str(int(time.time() * 1000))
        sortedMap["url"] = url
        sortedMap["key"] = self.appSecret
        sign = self.createSign(sortedMap, self.appSecret)
        headers = {
            "APPID": self.appId,
            "APP-SECRET": self.appSecret,
            "TIMESTAMP": sortedMap["timestamp"],
            "SIGN": sign,
        }
        response: dict = requests.request(
            method=method,
            url="{}{}".format(self.appRoot, url),
            params=query,
            headers=headers,
        ).json()
        LOGGER.info({"code": response.get("code"), "msg": response.get("msg")})
        return response

    def getMaliciousAddr(self, platform: str, address: str) -> MaliceData:
        query = {
            "platform": platform,
            "address": address,
        }
        resp = self.request(
            url="/api/v1/kyt/address/malice",
            method="GET",
            query=query,
        )
        return from_dict(
            data_class=MaliceData,
            data=resp.get("data"),
        )

    def getSanctionedAddr(self, platform: str, address: str) -> SanctionData:
        query = {
            "platform": platform,
            "address": address,
        }
        resp = self.request(
            url="/api/v1/kyt/address/sanction",
            method="GET",
            query=query,
        )
        return from_dict(
            data_class=SanctionData,
            data=resp.get("data"),
        )

    def getAddrScore(self, platform: str, address: str, currency: str) -> AddrScore:
        pass

    def getTxScore(self, platform: str, hash: str) -> TxScore:
        pass

    def getAddrDetail(self, platform: str, address: str, currency: str) -> AddrDetail:
        pass

    def getTxDetail(self, platform: str, hash: str) -> TxDetail:
        pass


if __name__ == "__main__":
    appId = os.getenv("APPID")
    appSecret = os.getenv("APPSECRET")
    appRoot = os.getenv("APPROOT")
    API = BeosinKYT(appId=appId, appSecret=appSecret, appRoot=appRoot)
    result = API.getMaliciousAddr(
        platform="eth",
        address="0xb763afd03e7c4e6fd91d3e88ac941cf7c07a3898",
    )
    print(result)
    result = API.getSanctionedAddr(
        platform="eth",
        address="0x3cbded43efdaf0fc77b9c55f6fc9988fcc9b757d",
    )
    print(result)

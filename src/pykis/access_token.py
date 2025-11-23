"""
pykis의 AccessToken 클래스를 담기 위한 모듈
"""

# Copyright 2022 Jueon Park
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from datetime import datetime, timedelta
from typing import NamedTuple, Optional, Dict, Any
import os
import hashlib
import diskcache as dc


class AccessToken:
    """
    인증용 토큰 정보를 담을 클래스
    """

    def __init__(self, cache_dir: Optional[str] = None, cache_expire: Optional[int] = 86400) -> None:
        self.value: Optional[str] = None
        self.valid_until: Optional[datetime] = None
        self._cache_dir = os.path.expanduser("~/.koreainvestment_cache") if cache_dir is None else cache_dir
        self._cache = dc.Cache(self._cache_dir, expire=cache_expire)  # 24시간 (초 단위)

    def create(self, resp: NamedTuple, key_info: Optional[Dict[str, Any]] = None) -> None:
        """
        Token을 생성한다.
        key_info: API 키 정보 (appkey, appsecret). 캐시 키 생성에 사용됨.
        """
        self.value: str = f"Bearer {str(resp.access_token)}"
        self.valid_until: datetime = self._valid_until(resp)
        
        # 캐시에 토큰 저장
        if key_info is not None:
            cache_key = self._get_cache_key(key_info)
            cache_data = {
                "value": self.value,
                "valid_until": self.valid_until.isoformat()
            }
            self._cache.set(cache_key, cache_data)
    
    def load_from_cache(self, key_info: Dict[str, Any]) -> bool:
        """
        캐시에서 토큰을 로드한다.
        key_info: API 키 정보 (appkey, appsecret)
        return: 캐시에서 토큰을 성공적으로 로드한 경우 True, 그렇지 않으면 False
        """
        cache_key = self._get_cache_key(key_info)
        cached_data = self._cache.get(cache_key)
        
        if cached_data is None:
            return False
        
        try:
            self.value = cached_data["value"]
            self.valid_until = datetime.fromisoformat(cached_data["valid_until"])
            
            # 캐시된 토큰이 여전히 유효한지 확인
            if self.is_valid():
                return True
            else:
                # 유효하지 않은 경우 캐시에서 제거
                self._cache.delete(cache_key)
                self.value = None
                self.valid_until = None
                return False
        except (KeyError, ValueError, TypeError):
            # 캐시 데이터가 손상된 경우
            self._cache.delete(cache_key)
            return False
    
    def _get_cache_key(self, key_info: Dict[str, Any]) -> str:
        """
        API 키 정보를 기반으로 캐시 키를 생성한다.
        """
        appkey = key_info.get("appkey", "")
        appsecret = key_info.get("appsecret", "")
        key_string = f"{appkey}:{appsecret}"
        return hashlib.sha256(key_string.encode()).hexdigest()

    def _valid_until(self, resp: NamedTuple) -> datetime:
        """
        현재 시각 기준으로 Token의 유효기한을 반환한다.
        """
        time_margin = 60
        duration = int(resp.expires_in) - time_margin
        return datetime.now() + timedelta(seconds=duration)

    def is_valid(self) -> bool:
        """
        Token이 유효한지 검사한다.
        """
        return self.value is not None and \
            self.valid_until is not None and \
            datetime.now() < self.valid_until

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

import os
import json
from datetime import datetime, timedelta
from typing import NamedTuple, Optional


class AccessToken:
    """
    인증용 토큰 정보를 담을 클래스
    """

    def __init__(self, key_info: json = {}, cache_file: str = "access_token_cache.json") -> None:
        self.value: Optional[str] = None
        self.valid_until: Optional[datetime] = None
        self.cache_file = cache_file

        self.key_info = key_info

        self.load_from_cache()

    def create(self, resp: NamedTuple) -> None:
        self.value = f"Bearer {str(resp.access_token)}"
        self.valid_until = self._valid_until(resp)
        self.save_to_cache()

    def _valid_until(self, resp: NamedTuple) -> datetime:
        time_margin = 60
        duration = int(resp.expires_in) - time_margin
        return datetime.now() + timedelta(seconds=duration)

    def is_valid(self) -> bool:
        return (
            self.value is not None and
            self.valid_until is not None and
            datetime.now() < self.valid_until
        )

    def save_to_cache(self) -> None:
        if self.value and self.valid_until:
            data = {}

            if os.path.exists(self.cache_file):
                with open(self.cache_file, "r") as f:
                    data = json.load(f)

            data[self.key_info.get("appkey")] = {
                "value": self.value,
                "valid_until": self.valid_until.isoformat()
            }

            with open(self.cache_file, "w") as f:
                json.dump(data, f)

    def load_from_cache(self) -> None:
        if os.path.exists(self.cache_file):
            with open(self.cache_file, "r") as f:
                data = json.load(f)
                data = data.get(self.key_info.get("appkey"))
                valid_until = datetime.fromisoformat(data["valid_until"])

                if datetime.now() < valid_until:
                    self.value = data["value"]
                    self.valid_until = valid_until
                else:
                    # 만료된 경우 캐시 초기화
                    self.value = None
                    self.valid_until = None

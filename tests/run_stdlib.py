"""无第三方依赖环境下的核心逻辑测试入口：stub 掉 FastAPI/Pydantic 等，
只加载 jcs / pathlang / security / engine 并用 unittest 运行。

正式环境请用 pytest（requirements.txt 安装后）：
    python -m unittest discover -s tests
"""
import importlib
import os
import sys
import types
import unittest

os.environ.setdefault("ALLOW_INSECURE_DEV_KEY", "1")


def _install_stubs():
    # ---- pydantic ----
    pydantic = types.ModuleType("pydantic")

    class _BaseModel:
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

        @classmethod
        def model_validate(cls, obj):
            if isinstance(cls, tuple):
                cls = cls[0]
            inst = cls.__new__(cls)
            if isinstance(obj, dict):
                inst.__dict__.update(obj)
            return inst

        def model_dump(self, mode=None):
            return dict(self.__dict__)

    class _FieldInfo:
        def __init__(self, default=None, **kw):
            self.default = default

    def Field(default=None, **kw):
        return default if not isinstance(default, type) else default

    def field_validator(*args, **kwargs):
        def deco(fn):
            fn.__validator__ = args
            return fn

        return deco

    pydantic.BaseModel = _BaseModel
    pydantic.Field = Field
    pydantic.field_validator = field_validator

    def _literal(cls, *args):
        return cls

    pydantic.Literal = _literal

    config = types.ModuleType("pydantic")
    pydantic.ConfigDict = dict
    sys.modules["pydantic"] = pydantic

    pydantic_settings = types.ModuleType("pydantic_settings")

    class _SettingsBase(_BaseModel):
        def __init__(self, **kw):
            pass

    pydantic_settings.BaseSettings = _SettingsBase
    pydantic_settings.SettingsConfigDict = lambda **kw: kw
    sys.modules["pydantic_settings"] = pydantic_settings

    # ---- fastapi / starlette （engine 链路上仅 errors.py 间接需要，测试不导入） ----
    # config.py 已可纯导入，无需 stub。

    # stub 版 BaseSettings 不读环境变量，直接打开开发密钥开关
    import app.config as _config

    _config.settings.allow_insecure_dev_key = True
    _config.settings.server_hmac_key = "test-key"


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    _install_stubs()

    # 显式加载纯逻辑模块，避免 import errors.py
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for mod in ("tests.test_jcs", "tests.test_pathlang", "tests.test_engine"):
        suite.addTests(loader.loadTestsFromName(mod))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)

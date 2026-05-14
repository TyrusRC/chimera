"""Device managers must be module singletons; multiple gets return the same instance."""
from chimera.device.manager import get_android_manager, get_ios_manager


def test_android_manager_is_singleton():
    a = get_android_manager()
    b = get_android_manager()
    assert a is b


def test_ios_manager_is_singleton():
    a = get_ios_manager()
    b = get_ios_manager()
    assert a is b

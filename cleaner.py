import os
import signal


def cleaner():
    os.system('iptables -F')
    os.system('iptables -X')
    os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
    print("Cleaning Finished Successfully")


signal.signal(signal.SIGTERM, cleaner)


def error_clean(func):
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
        except KeyboardInterrupt:
            cleaner()
            exit()

    return wrapper

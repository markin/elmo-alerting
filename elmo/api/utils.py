import re


def re_case(name):
    name = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    return name

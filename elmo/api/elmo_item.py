import re


class ElmoItem(object):
    def __init__(self, **entries):
        self.__dict__.update(entries)
        self.name = re.sub(r"([\s\n])", "_", self.name).lower()

    def __str__(self):
        return "\n".join([f"{key}: {value}" for key, value in self.__dict__.items()])

import re

abc = {"а":0, "б":1, "в":2, "г":3, "ґ":4, "д":5, "е":6, "є":7, "ж":8, "з":9, "и":10, "і":11, "ї":12, "й":13, "к":14,
       "л":15, "м":16, "н":17, "о":18, "п":19, "р":20, "с":21, "т":22, "у":23, "ф":24, "х":25, "ц":26, "ч":27, "ш":28,
       "щ":29, "ь":30, "ю":31, "я":32}


def encode(text, key):
    pattern = r"[^{}]".format("".join(list(abc.keys())))
    text = re.sub(pattern, "", text)
    enc = ''
    for i in range(len(text)):
        j = i % len(key)
        ch = abc[text[i]] + abc[key[j]]
        for k, value in abc.items():
            if ch % len(abc) == value:
                enc += k
    return enc

def decode(text, key):
    enc = ''
    for i in range(len(text)):
        j = i % len(key)
        ch = abc[text[i]] - abc[key[j]]
        for k, value in abc.items():
            if ch % len(abc) == value:
                enc += k
    return enc


if __name__ == '__main__':
    print(encode("весна красна колись настане", "зима"))
    print(decode("імґнзфгаьчмкчхцсечмсюиае", "зима"))

import numpy as np
from vigenere_cipher import *
import scipy.stats as sc

UKRAINIAN_LETTER_FREQUENCES = {'а': 0.074, 'б': 0.018, 'в': 0.054, 'г': 0.016, 'ґ': 0.001, 'д': 0.036, 'е': 0.017, 'є': 0.008, 'ж': 0.009, 'з': 0.024, 'и': 0.063,
                               'і': 0.059, 'ї': 0.006, 'й': 0.009, 'к': 0.036, 'л': 0.037, 'м': 0.032, 'н': 0.067, 'о': 0.097, 'п': 0.023, 'р': 0.049, 'с': 0.042,
                               'т': 0.057, 'у': 0.041, 'ф': 0.001, 'х': 0.012, 'ц': 0.006, 'ч': 0.019, 'ш': 0.012, 'щ': 0.001, 'ю': 0.004, 'я': 0.030, 'ь': 0.030}

abc = ''.join(list(UKRAINIAN_LETTER_FREQUENCES.keys()))

# def IOC(ciphertext):
#     f_i = 0
#     for i in abc.keys():
#         counter = 0
#         for j in ciphertext:
#             if i == j:
#                 counter += 1
#         f_i += counter*(counter-1)
#     IOC = f_i/(len(ciphertext)*(len(ciphertext)-1))
#     return IOC

def IOC(ciphertext):
    if len(ciphertext)<2:
        return 0
    n = len(ciphertext)
    ioc = 0
    for letter in UKRAINIAN_LETTER_FREQUENCES.keys():
        count = ciphertext.count(letter)
        ioc += count*(count-1)
    return ioc/(n*(n-1))

def key_batcher(len_key, ciphertext):
    classes = {i: [] for i in range(len_key)}
    for i, letter in enumerate(ciphertext):
        classes[i % len_key].append(letter)
    return classes


def key_len_guesser(ciphertext, max_key_len=33, ukr_ioc=0.049877):
    glob_ioc = []
    for key in range(2, max_key_len):
        classes = key_batcher(key, ciphertext)
        ioc = 0
        for batch in classes.values():
            if len(batch) > 1:
                ioc += IOC(batch)
            else:
                key -= 1
        glob_ioc.append(abs(ioc/key - ukr_ioc))
    #print(glob_ioc)
    return np.argmin(glob_ioc)+2


def get_hist(ct):
    hist = [0]*len(abc)
    for letter, dist in UKRAINIAN_LETTER_FREQUENCES.items():
        hist[abc.find(letter)] = ct.count(letter)
    return hist


def analyze_encrypted_text(text):
    len_key = key_len_guesser(text)
    classes = key_batcher(len_key, text)
    proposed = ""
    for batch in classes.values():
        chi2 = {}
        freqs = dict.fromkeys(UKRAINIAN_LETTER_FREQUENCES.keys(), 0)
        for letter in UKRAINIAN_LETTER_FREQUENCES.keys():
            freq = get_hist(decode(''.join(batch), letter))
            #freqs.update({abc[i]: loc_freq[uniques.index(abc[i])] for i in range(len(loc_freq))})
            stats, pval = sc.chisquare(freq,
                                       list(UKRAINIAN_LETTER_FREQUENCES.values()))
            chi2[letter] = stats
        proposed += min(chi2, key=chi2.get)
    return proposed


def error(plaintext, ciphertext):
    return 1 - (np.char.array(list(plaintext)) == np.char.array(list(decode(ciphertext, analyze_encrypted_text(ciphertext))))).mean()


if __name__ == '__main__':
    with open("black_soviet_encrypted (2).txt", 'r') as file:
        text1 = file.read()
        #pattern = r"[^{}]".format("".join(list(abc.keys())))
        #text1 = re.sub(pattern, "", text1)
    #text = encode(text1, "зима")
    #print(IOC(text1))
    #print(key_len_guesser(text))
    key = analyze_encrypted_text(text1[:2000])
    print(key)
    #print(error(text1, text))
    print(decode(text1, key))

import re
from collections import Counter


def syllable_count(word):
    word = word.lower()
    count = 0
    vowels = "aeiouy"
    if word[0] in vowels:
        count += 1
    for index in range(1, len(word)):
        if word[index] in vowels and word[index - 1] not in vowels:
            count += 1
    if word.endswith("e"):
        count -= 1
    if count == 0:
        count += 1
    return count


def analyze_text(text):
    words = re.sub('[^A-Za-z0-9]+', ' ', text).split()
    alphabet = re.sub('[^A-Za-z0-9]+', '', text.lower())
    syllables = 0
    for word in words:
        syllables += syllable_count(word)
    return {"length": len(text),
            "sentences_amount": len(text.split(".")),
            "words_amount": len(words),
            # "words_freq": Counter(words),
            # "alphabet_freq": Counter(alphabet),
            "alphabet": len(Counter(alphabet)),
            "syllables": syllables,
            "complexity": 206.835 - (1.015 * len(words) / len(text.split('.'))) - 84.6 * (syllables / len(words))}


def normalize_text_data(data):
    new_data = {x: data[x] for x in data if x not in "_id"}
    return {
        **new_data,
        "id": data["_id"]["$oid"]
    }

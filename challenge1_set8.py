#!/usr/bin/env python3
import requests
from functions import chunks

r = requests.get("https://cryptopals.com/static/challenge-data/8.txt")

scores = []

for i, line in enumerate(r.iter_lines()):
    chunked = chunks(line, 32)
    count = {}
    for chunk in chunked:
        if chunk not in count:
            count[chunk] = 0
        count[chunk] += 1

    score = max(count.values())
    scores.append((score, i + 1, line))

scores.sort(key=lambda x: x[0], reverse=True)

# repeats, line number, line text
print(scores[:3])

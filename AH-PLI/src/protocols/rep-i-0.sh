#!/bin/bash

tmp_file="test.txt"
for file in *.c;
do
    awk '{gsub(/i=0/, "i = 0"); print}' "$file" > "$tmp_file"
    mv "$tmp_file" "$file"
done
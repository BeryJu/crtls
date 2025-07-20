#!/bin/sh
# https://carlosbecker.com/posts/golang-completions-cobra/
set -e
rm -rf completions
mkdir -p completions
for sh in bash zsh fish; do
    go run . completion "$sh" > "completions/crtls.$sh"
done

#!/bin/bash
# KLTN benign — profile "web" (kltn-user). A normal customer/staff browsing OWASP Juice Shop over HTTP.
# Legitimate application flows only: landing, search, product/reviews, valid login, basket. No injection,
# no fuzzing, no auth brute force — this is the benign baseline of traffic to the exposed web app.
set -u
URL="${KLTN_WEB_URL:-http://127.0.0.1}"
J="$HOME/.webjar"; UA="Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
C(){ curl -fsS --max-time 12 -A "$UA" -c "$J" -b "$J" "$@" >/dev/null 2>&1 || true; }
terms=(apple juice banana lemon cherry eggfruit melon "owasp" carrot); q=${terms[$RANDOM % ${#terms[@]}]}
C "$URL/"                                   # landing SPA
C "$URL/main.js"; C "$URL/styles.css"       # static assets
C "$URL/rest/admin/application-configuration"
C "$URL/api/Products"                        # product catalogue
C "$URL/rest/products/search?q=$q"           # search (normal term)
pid=$(( (RANDOM % 9) + 1 ))
C "$URL/api/Products/$pid"                    # view one product
C "$URL/rest/products/$pid/reviews"          # its reviews
# Occasionally register + log in a throwaway customer and view the (empty) basket — valid auth, no brute force.
if [ $((RANDOM % 3)) -eq 0 ]; then
  em="shopper$RANDOM@juice.lab"; pw="Benign_$RANDOM!"
  C -H 'Content-Type: application/json' -X POST "$URL/api/Users" \
     --data "{\"email\":\"$em\",\"password\":\"$pw\",\"passwordRepeat\":\"$pw\",\"securityQuestion\":{\"id\":1},\"securityAnswer\":\"lab\"}"
  tok=$(curl -fsS --max-time 12 -A "$UA" -H 'Content-Type: application/json' -X POST "$URL/rest/user/login" \
        --data "{\"email\":\"$em\",\"password\":\"$pw\"}" 2>/dev/null | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
  [ -n "$tok" ] && curl -fsS --max-time 12 -A "$UA" -H "Authorization: Bearer $tok" "$URL/rest/basket/1" >/dev/null 2>&1 || true
fi

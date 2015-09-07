from jose import jwt

claims = {
    'test': 1
}

test = {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "e52f68a6c1d04d1451c8437c319ed1eb2425f3a2",
   "n": "ufmhFfZJ8D9TZIGqlWfpVlA9VftAdEWop71G4xnoPC6Rk7RIOHG5P59tVqdA_uINgOzqWd4DZDiyajwZU-SoxwGUjfrijBsge-Ul_HTwVM0kwAorizSm97--rderM3b9KzkatJqizmIG7Dm7A06USMWGlSeTKs_RYDFGM7QZWncQVvtCYu_XJfuc0DCa1PyAFzwmBrEliv0tZEogWUien0HQ95Y-EJrxb-CgKt7fd3gfI0wAJtg-h7QyZWX4UH8ae3VnfeUZp6dg7SLswfNxc2W7UdTgwOaokkxzRNq5qmzIT6Cz-vMjl_Mf6VaLr7e4Y357vwUzqh9ool-DDlEjVw",
   "e": "AQAB"
  }

token = jwt.encode(claims, test, algorithm='RS256')

print token

import json, random, string, sys

random.seed(1)
n = int(sys.argv[1])
alnum = string.ascii_letters + string.digits


def tok(k):
    return "".join(random.choice(alnum) for _ in range(k))


def secret(k):
    return tok(k - 1) + random.choice(string.digits)


plain = [
    lambda: f'10.0.{random.randint(0,255)}.{random.randint(0,255)} - - "GET /api/v1/items/{random.randint(1,99999)} HTTP/1.1" 200 {random.randint(100,9999)} "-" "Mozilla/5.0"',
    lambda: f'level=info ts=2026-10-06T12:00:00Z caller=reconciler.go:{random.randint(1,999)} msg="reconciled" namespace=tenant-x name=app-{tok(6)} duration={random.random():.3f}s',
    lambda: f'I1006 12:00:00.000000       1 controller.go:{random.randint(1,999)}] Successfully synced key="tenant-x/{tok(8)}"',
]
keyword = [
    lambda: f'level=info msg="token refreshed" user={tok(8)} expires_in=3600',
    lambda: f'level=debug msg="using auth header" scheme=Bearer key_id={tok(6)}',
    lambda: f'level=info msg="loaded secret" name=db-credentials namespace=tenant-x',
]
leak = [
    lambda: f'connecting with api_key={secret(24)}',
    lambda: 'remote s3 secrets:{key:"secret-key" value:"' + secret(28) + '"}',
    lambda: 'remote s3 secrets:{key:\\"secret-key\\" value:\\"' + secret(28) + '\\"}',
]
for i in range(n):
    r = random.random()
    pool = leak if r < 0.05 else keyword if r < 0.30 else plain
    print(json.dumps({"log": random.choice(pool)(), "stream": "stdout"}))

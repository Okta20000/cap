from hcaptcha.keyfetcher import KeyFetcher

kf = KeyFetcher()
build = kf.live_build_hash()
print(f"build hash: {build}")

keys = kf.fetch(build)
print(f"hsj.payload_encrypt_key: {keys['hsj']['payload_encrypt_key']}")
print(f"hsw.encrypt_key:         {keys['hsw']['encrypt_key']}")
print(f"hsw.n_key:               {keys['hsw']['n_key']}")
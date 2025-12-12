import re
import requests
import pathlib

urls = [
    "https://cdn.public.zooplus.net/media/my-account-frame/account-overview-app/latest/main.min.js",
    "https://cdn.public.zooplus.net/media/my-account-frame/account-overview-app/latest/722.min.js",
    "https://cdn.public.zooplus.net/media/my-account-frame/account-overview-app/latest/315.min.js",
    "https://cdn.public.zooplus.net/media/my-account-frame/account-overview-app/latest/272.min.js",
    "https://cdn.public.zooplus.net/media/my-account-frame/account-overview-app/latest/982.min.js",
    "https://cdn.public.zooplus.net/media/my-account-frame/account-overview-app/latest/365.min.js",
    "https://cdn.public.zooplus.net/media/my-account-frame/account-overview-app/latest/176.min.js",
    "https://cdn.public.zooplus.net/media/my-account-frame/account-overview-app/latest/835.min.js",
]


def main() -> None:
    out = pathlib.Path("Zooplus/tmp_js")
    out.mkdir(parents=True, exist_ok=True)
    for url in urls:
        try:
            txt = requests.get(url, timeout=10).text
        except Exception as e:  # noqa: BLE001
            print(url, "ERROR", e)
            continue
        name = url.rsplit("/", 1)[-1]
        (out / name).write_text(txt, encoding="utf-8", errors="ignore")
        print(f"\n-- {name}")
        for m in re.finditer(r'client_id":"([^"]+)', txt):
            print("client_id:", m.group(1))
        for m in re.finditer(r"/protected/api[^\"\\s]+", txt):
            val = m.group(0)
            if any(k in val for k in ["loyalty", "order", "invoice", "bonus", "membership"]):
                print("protected api:", val)
        for m in re.finditer(r"/myaccount/api[^\"\\s]+", txt):
            print("myaccount api:", m.group(0))


if __name__ == "__main__":
    main()


"""Download the AIT Alert Data Set (Zenodo record 8263181, CC BY 4.0), verify it and unpack it to data/ait/."""
import hashlib, urllib.request, zipfile
from pathlib import Path

D = Path(__file__).resolve().parents[1] / 'data'
FILES = {  # name: (url, md5)
    'ait_ads.zip': ('https://zenodo.org/api/records/8263181/files/ait_ads.zip/content', '43db6b1f0996e0024befd617706c50e9'),
    'labels.csv': ('https://zenodo.org/api/records/8263181/files/labels.csv/content', '60ff33796c77fd2136c4d1a4bc841bd9'),
}


def md5(p):
    h = hashlib.md5()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def main():
    D.mkdir(exist_ok=True)
    for name, (url, digest) in FILES.items():
        p = D / name
        if not p.exists() or md5(p) != digest:
            print('downloading', name)
            urllib.request.urlretrieve(url, p)
        assert md5(p) == digest, f'checksum mismatch for {name}'
        print('ok', name)
    with zipfile.ZipFile(D / 'ait_ads.zip') as z:
        z.extractall(D / 'ait')
    print('unpacked to', D / 'ait')


if __name__ == '__main__':
    main()

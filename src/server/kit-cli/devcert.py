"""기기 인증서(P6) — 사내 기기 인증서 CA · 발급(PKCS#12) · 폐기(CRL).

  kit device-cert issue <이름>    → /data/mtls/issued/<이름>.p12 와 비밀번호(이 화면에서만) — MDM·관리자가 그 PC 에 설치
  kit device-cert revoke <이름>   → CRL 에 넣고 nginx 다시 읽기 — 그 PC 는 바로 포털·Git 화면이 막힘
  kit device-cert list
"""
import datetime
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

D = Path(os.environ.get("KIT_DATA", "/data")) / "mtls"
CA_KEY, CA_PEM, CRL, DB = D / "ca.key", D / "ca.pem", D / "crl.pem", D / "issued.json"
now = lambda: datetime.datetime.now(datetime.timezone.utc)


def load_ca():
    return (serialization.load_pem_private_key(CA_KEY.read_bytes(), None), x509.load_pem_x509_certificate(CA_PEM.read_bytes()))


def db():
    return json.loads(DB.read_text()) if DB.exists() else {}


def write_crl():
    key, ca = load_ca()
    b = x509.CertificateRevocationListBuilder().issuer_name(ca.subject).last_update(now()).next_update(now() + datetime.timedelta(days=3650))
    for e in db().values():
        if e.get("revoked_at"):
            b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(int(e["serial"])).revocation_date(
                datetime.datetime.fromtimestamp(e["revoked_at"], datetime.timezone.utc)).build())
    CRL.write_bytes(b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))


def init():
    D.mkdir(parents=True, exist_ok=True)
    os.chmod(D, 0o700)
    if not CA_KEY.exists():
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MCP Dev Kit device CA")])
        ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now()).not_valid_after(now() + datetime.timedelta(days=3650))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
              .sign(key, hashes.SHA256()))
        CA_KEY.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        os.chmod(CA_KEY, 0o600)
        CA_PEM.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    if not CRL.exists():
        write_crl()


def issue(name, days=365):
    init()
    if name in db() and not db()[name].get("revoked_at"):
        sys.exit(f"{name} 은 이미 발급돼 있습니다 — 다시 발급하려면 먼저 revoke")
    ca_key, ca = load_ca()
    key = ec.generate_private_key(ec.SECP256R1())
    serial = x509.random_serial_number()
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(serial).not_valid_before(now()).not_valid_after(now() + datetime.timedelta(days=days))
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pw = secrets.token_urlsafe(12)
    out = D / "issued" / f"{name}.p12"
    out.parent.mkdir(exist_ok=True)
    out.write_bytes(pkcs12.serialize_key_and_certificates(name.encode(), key, cert, [ca],
                                                          serialization.BestAvailableEncryption(pw.encode())))
    os.chmod(out, 0o600)
    d = db()
    d[name] = {"serial": str(serial), "issued_at": now().timestamp(), "until": (now() + datetime.timedelta(days=days)).timestamp()}
    DB.write_text(json.dumps(d, indent=1))
    print(f"발급: {out}\n비밀번호(이 화면에서만): {pw}\n윈도우: certutil -f -p <비밀번호> -importpfx My {name}.p12 (사용자 인증서) · 브라우저가 이 인증서를 고르게 됩니다")


def revoke(name):
    d = db()
    if name not in d:
        sys.exit(f"{name} 은 발급 기록이 없습니다")
    d[name]["revoked_at"] = now().timestamp()
    DB.write_text(json.dumps(d, indent=1))
    write_crl()
    subprocess.run(["nginx", "-c", "/dev/shm/kit/nginx.conf", "-s", "reload"], check=False)
    print(f"폐기: {name} — 다음 접속부터 막힙니다")


if __name__ == "__main__":
    cmd, rest = (sys.argv[1] if len(sys.argv) > 1 else ""), sys.argv[2:]
    if cmd == "init":
        init()
    elif cmd == "issue" and rest:
        issue(rest[0])
    elif cmd == "revoke" and rest:
        revoke(rest[0])
    elif cmd == "list":
        for n, e in sorted(db().items()):
            print(n, "폐기됨" if e.get("revoked_at") else "유효", datetime.datetime.fromtimestamp(e["until"]).date())
    else:
        print(__doc__)

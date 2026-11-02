"""검사용 격리 이미지가 호스트 docker 에 없으면 키트 이미지에 든 tar 를 불러온다."""
import os
import subprocess

IMAGE = os.environ["KIT_SANDBOX_IMAGE"]
TAR = "/opt/kit/images/sandbox-python.tar"


def ensure():
    if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode == 0:
        return "있음"
    if not os.path.exists(TAR):
        raise RuntimeError(f"{IMAGE} 가 없고 {TAR} 도 없습니다")
    subprocess.run(["docker", "load", "-i", TAR], check=True, capture_output=True)
    return "불러옴"

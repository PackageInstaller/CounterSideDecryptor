from __future__ import annotations
import hashlib
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Iterator, Tuple


def derive_keystream(file_path: str) -> bytes:
    name = os.path.splitext(os.path.basename(file_path))[0].lower()
    md5_hex = hashlib.md5(name.encode("utf-8")).hexdigest()
    mask1 = int(md5_hex[0:16], 16)
    mask2 = int(md5_hex[16:32], 16)
    mask3 = int(md5_hex[0:8] + md5_hex[16:24], 16)
    mask4 = int(md5_hex[8:16] + md5_hex[24:32], 16)
    return (
        mask1.to_bytes(8, "little")
        + mask2.to_bytes(8, "little")
        + mask3.to_bytes(8, "little")
        + mask4.to_bytes(8, "little")
    )


def crypto_xor(data: bytearray, size: int, keystream: bytes) -> None:
    if size <= 0:
        return

    aligned = (size // 8) * 8

    if aligned:
        head = bytes(data[:aligned])
        ks = keystream * (aligned // 32 + 1)
        ks = ks[:aligned]
        xored = (int.from_bytes(head, "big") ^ int.from_bytes(ks, "big")).to_bytes(
            aligned, "big"
        )
        data[:aligned] = xored

    if aligned < size:
        chunk_idx = (aligned // 8) % (32 // 8)
        buggy_byte = keystream[chunk_idx * 8]
        for i in range(aligned, size):
            data[i] ^= buggy_byte


def decrypt(path: str) -> Tuple[str, str]:
    with open(path, "r+b") as f:
        head = bytearray(f.read(212))
        if not head:
            return ("empty", path)

        if bytes(head[:8]) == b"UnityFS\0":
            return ("skipped", path)

        crypto_xor(head, len(head), derive_keystream(path))

        if bytes(head[:8]) != b"UnityFS\0":
            return ("error:magic", path)

        f.seek(0)
        f.write(head)
    return ("ok", path)


def iter_asset_files(root: str) -> Iterator[str]:
    stack = [root]
    while stack:
        current = stack.pop()
        it = os.scandir(current)
        for entry in it:
            if entry.is_dir(follow_symlinks=False):
                stack.append(entry.path)
            elif entry.is_file(follow_symlinks=False) and entry.name.endswith(
                (".asset", ".vkor", ".vjpn", ".twn", ".gbtwn")
            ):
                yield entry.path


def run(root: str, workers: int) -> int:
    files = list(iter_asset_files(root))
    total = len(files)
    print(f"找到{total}个加密文件")
    if not total:
        return 0

    ok = skipped = empty = err = 0
    err_samples: list[Tuple[str, str]] = []

    workers = max(1, workers)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for status, path in pool.map(decrypt, files, chunksize=64):
            if status == "ok":
                ok += 1
            elif status == "skipped":
                skipped += 1
            elif status == "empty":
                empty += 1
            else:
                err += 1
                if len(err_samples) < 8:
                    err_samples.append((status, path))

    print(f"ok={ok} skipped={skipped} empty={empty} error={err} ")
    for s, p in err_samples:
        print(f"错误{s}:{p}")

    return 0 if err == 0 else 1


if __name__ == "__main__":
    sys.exit(run("Assetbundles", 64))

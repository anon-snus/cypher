import asyncio
import os
import sys
from pathlib import Path

from cypher import cypher

if getattr(sys, 'frozen', False):
    ROOT_DIR = Path(sys.executable).parent.absolute()
else:
    ROOT_DIR = Path(__file__).parent.parent.absolute()

ADDRESSES_PATH = os.path.join(ROOT_DIR, 'cypher/wallets.txt')
CYPHERED_PATH = os.path.join(ROOT_DIR, 'cypher/encrypted.txt')


async def get_wallet_addresses(path: str) -> list[str]:
    wallet_addresses = []
    with open(path) as f:
        for wallet_address in f:
            wallet_addresses.append(wallet_address.strip())
    return wallet_addresses


async def main():
    action = int(
        input('choose action: \n1) generate attributes\n2) encrypt keys\n3) decrypt keys\n'))

    if action == 1:
        await cypher.generate_attributes()
    elif action == 2:
        key = input('Введите первый пароль: ')

        wallets = await get_wallet_addresses(path=ADDRESSES_PATH)
        cupher = cypher(key=key)
        print(cupher.key[:1])
        keys = []
        for i in wallets:
            cyphered = await cupher.triple_encrypt(data=i)
            keys.append(cyphered.hex())
        with open('encrypted.txt', 'w') as f:
            for i in keys:
                f.write(f'{i}\n')
    elif action == 3:
        key = input('Введите пароль: ')
        wallets = await get_wallet_addresses(path=CYPHERED_PATH)
        cupher = cypher(key=key)
        keys = []
        for i in wallets:
            encrypted_data = bytes.fromhex(i)
            decrypted = await cupher.triple_decrypt(encrypted_data=encrypted_data)
            keys.append(decrypted)
        with open('decrypted.txt', 'w') as f:
            for i in keys:
                f.write(f'{i}\n')


if __name__ == '__main__':
    asyncio.run(main())
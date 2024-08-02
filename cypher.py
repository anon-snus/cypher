from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import hashlib

import keys


class cypher():
	def __init__(self, key: str):
		self.key = key

	async def rearrange_pairs(self, s: str) -> str:
		if len(s) % 2 != 0:
			s += ' '
		pairs = [s[i:i + 2] for i in range(0, len(s), 2)]
		result = []
		to_move = []
		n = int(self.key[:1])
		for index, pair in enumerate(pairs):
			if (index + 1) % n == 0:
				to_move.append(pair)
			else:
				result.append(pair)
		result.extend(to_move)
		return ''.join(result)

	async def restore_original_string(self, s: str) -> str:
		if len(s) % 2 != 0:
			s = s[:-1]
		pairs = [s[i:i + 2] for i in range(0, len(s), 2)]
		n = int(self.key[:1])
		total_pairs = len(pairs)
		moved_pairs_indices = [(i + 1) % n == 0 for i in range(total_pairs)]
		original_pairs = [None] * total_pairs
		num_moved_pairs = sum(moved_pairs_indices)
		non_moved_pairs_count = total_pairs - num_moved_pairs
		moved_pairs_start_index = non_moved_pairs_count
		current_moved_index = moved_pairs_start_index
		current_original_index = 0
		for i, is_moved in enumerate(moved_pairs_indices):
			if is_moved:
				original_pairs[i] = pairs[current_moved_index]
				current_moved_index += 1
			else:
				original_pairs[i] = pairs[current_original_index]
				current_original_index += 1
		return ''.join(original_pairs)
	@staticmethod
	async def generate_attributes():
		# Генерация трех случайных солей для ключей
		salt1 = os.urandom(16)
		salt2 = os.urandom(16)
		salt3 = os.urandom(16)
		print(salt1, salt2, salt3)

		# Хэширование солей в одну строку
		hashed_salts, combined_salts = await cypher.hash_salts(salt1=salt1, salt2=salt2, salt3=salt3)

		# Вектор инициализации для шифрования
		iv = os.urandom(16)

		with open('keys.py', 'w') as f:
			f.write(f'combined_salts = "{combined_salts}"\n')
			f.write(f'iv = {iv}\n')
			f.write(f'hashed_salts = "{hashed_salts}"')

		return hashed_salts, combined_salts, iv

	async def generate_key(self, password: str, salt: bytes) -> bytes:
		"""
		Генерирует ключ шифрования с использованием PBKDF2HMAC и SHA-256.

		:param password: Пароль в виде строки.
		:param salt: Соль в байтовом формате.
		:return: Ключ в байтовом формате.
		"""
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
		key = kdf.derive(password.encode())
		return key

	@staticmethod
	async def hash_salts(salt1: bytes, salt2: bytes, salt3: bytes) -> str:
		"""
		Объединяет и хэширует три соли в одну строку с использованием SHA-256.

		:param salt1: Первая соль.
		:param salt2: Вторая соль.
		:param salt3: Третья соль.
		:return: Хэшированная строка всех трех солей.
		"""
		combined_salts = salt1 + salt2 + salt3
		hashed_salts = hashlib.sha256(combined_salts).hexdigest()
		return hashed_salts, combined_salts.hex()


	async def split_salts(self, combined_salts: str, salt_lengths: tuple[int, int, int]) -> tuple[bytes, bytes, bytes]:
		"""
		Извлекает три соли из хэшированной строки, используя известные длины солей.

		:param combined_salts: Хэшированная строка всех трех солей.
		:param salt_lengths: Кортеж с длинами каждой соли.
		:return: Кортеж, содержащий три отдельные соли.
		"""
		salt1_length, salt2_length, salt3_length = salt_lengths
		# Преобразуем обратно в байты
		combined_salts = bytes.fromhex(combined_salts)

		salt1 = combined_salts[:salt1_length]
		salt2 = combined_salts[salt1_length:salt1_length + salt2_length]
		salt3 = combined_salts[salt1_length + salt2_length:salt1_length + salt2_length + salt3_length]

		return salt1, salt2, salt3


	async def triple_encrypt(self, data: str) -> tuple[bytes, str, str, bytes]:
		"""
		Тройное шифрование данных с использованием трех различных паролей и хэширования солей.

		:param data: Данные в виде строки.
		:param password1: Первый пароль для шифрования.
		:param password2: Второй пароль для шифрования.
		:param password3: Третий пароль для шифрования.
		:return: зашифрованные данные
		"""
		password= self.key
		combined_salts = keys.combined_salts
		iv = keys.iv
		data=await self.rearrange_pairs(data)
		print(data)
		salt1, salt2, salt3 = await self.split_salts(combined_salts, (16,16,16))

		# Генерация ключей для шифрования
		key1 = await self.generate_key(password, salt1)
		key2 = await self.generate_key(password, salt2)
		key3 = await self.generate_key(password, salt3)
		print(data)

		# Первый уровень шифрования
		cipher1 = Cipher(algorithms.AES(key1), modes.CFB(iv), backend=default_backend())
		encryptor1 = cipher1.encryptor()
		encrypted_data1 = encryptor1.update(data.encode()) + encryptor1.finalize()


		# Второй уровень шифрования
		cipher2 = Cipher(algorithms.AES(key2), modes.CFB(iv), backend=default_backend())
		encryptor2 = cipher2.encryptor()
		encrypted_data2 = encryptor2.update(encrypted_data1) + encryptor2.finalize()


		# Третий уровень шифрования
		cipher3 = Cipher(algorithms.AES(key3), modes.CFB(iv), backend=default_backend())
		encryptor3 = cipher3.encryptor()
		encrypted_data3 = encryptor3.update(encrypted_data2) + encryptor3.finalize()


		return encrypted_data3


	async def triple_decrypt(self, encrypted_data: bytes) -> str:
		"""
		Тройное дешифрование данных с использованием трех различных паролей и хэшированных солей.

		:param encrypted_data: Зашифрованные данные в байтовом формате.
		:param password1: Первый пароль для дешифрования.
		:param password2: Второй пароль для дешифрования.
		:param password3: Третий пароль для дешифрования.
		:param combined_salts: Хэшированная строка всех трех солей.
		:param iv: Вектор инициализации.
		:param salt_lengths: Кортеж с длинами каждой соли.
		:return: Дешифрованные данные в виде строки.
		"""
		combined_salts = keys.combined_salts
		iv = keys.iv
		password = self.key

		# Восстановление трех солей из хэшированной строки
		salt1, salt2, salt3 = await self.split_salts(combined_salts, (16,16,16))




		# Генерация ключей для дешифрования
		key1 = await self.generate_key(password, salt1)
		key2 = await self.generate_key(password, salt2)
		key3 = await self.generate_key(password, salt3)

		# Первый уровень дешифрования (обратный порядок)
		cipher3 = Cipher(algorithms.AES(key3), modes.CFB(iv), backend=default_backend())
		decryptor3 = cipher3.decryptor()
		decrypted_data2 = decryptor3.update(encrypted_data) + decryptor3.finalize()

		# Второй уровень дешифрования
		cipher2 = Cipher(algorithms.AES(key2), modes.CFB(iv), backend=default_backend())
		decryptor2 = cipher2.decryptor()
		decrypted_data1 = decryptor2.update(decrypted_data2) + decryptor2.finalize()

		# Третий уровень дешифрования
		cipher1 = Cipher(algorithms.AES(key1), modes.CFB(iv), backend=default_backend())
		decryptor1 = cipher1.decryptor()
		decrypted_data = decryptor1.update(decrypted_data1) + decryptor1.finalize()
		decrypted_data = await self.restore_original_string(decrypted_data.decode())
		return decrypted_data

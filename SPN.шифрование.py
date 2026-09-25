import random
import tkinter as tk
from tkinter import messagebox, scrolledtext

# 1. S-box из AES

AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

INV_AES_SBOX = [0] * 256
for idx, val in enumerate(AES_SBOX):
    INV_AES_SBOX[val] = idx

# P-box 
PBOX = [(i % 8) * 8 + (i // 8) for i in range(64)]
INV_PBOX = [0] * 64
for idx, val in enumerate(PBOX):
    INV_PBOX[val] = idx

BLOCK_SIZE = 8       # байт = 64 бита — размер одного блока
DEFAULT_ROUNDS = 4   # сколько раундов по умолчанию

# 2. Перевод между форматами

def bytes_to_bits(data: bytes) -> str:
    return ''.join(f'{byte:08b}' for byte in data)

def bits_to_bytes(bits: str) -> bytes:
    byte_list = []
    for i in range(0, len(bits), 8):
        byte_list.append(int(bits[i:i+8], 2))
    return bytes(byte_list)

def apply_pbox(bits: str, pbox: list[int]) -> str:
    out = ['0'] * len(bits)
    for i, src in enumerate(pbox):
        out[i] = bits[src]
    return ''.join(out)

def substitute_bytes(data: bytes, sbox: list[int]) -> bytes:
    """Заменяет каждый байт целиком через таблицу (AES S-box работает так)."""
    return bytes(sbox[b] for b in data)

def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(b1, b2))

def generate_random_key_hex() -> str:
    return f"{random.getrandbits(64):016X}"

def generate_random_iv_bytes() -> bytes:
    return random.getrandbits(64).to_bytes(8, 'big')

# 3. Генерация раундовых ключей

def rotate_left_bytes(data: bytes, n_bits: int) -> bytes:
    """Циклический сдвиг 8-байтового значения влево на n_bits."""
    val = int.from_bytes(data, 'big')
    n_bits %= 64
    rotated = ((val << n_bits) | (val >> (64 - n_bits))) & ((1 << 64) - 1)
    return rotated.to_bytes(8, 'big')

def generate_round_keys(master_key: bytes, rounds: int) -> list[bytes]:
    """Возвращает список из (rounds + 1) ключей по 8 байт каждый:
    keys[0]  — ключ "отбеливания" (XOR перед первым раундом)
    keys[1..rounds] — ключ для каждого раунда."""
    keys = [master_key]
    current = master_key
    for i in range(1, rounds + 1):
        rotated = rotate_left_bytes(current, 11)
        round_constant = bytes([(i * 0x9E) & 0xFF]) + b'\x00' * 7
        mixed = xor_bytes(rotated, round_constant)
        mixed = bytes([AES_SBOX[mixed[0]]]) + mixed[1:]
        keys.append(mixed)
        current = mixed
    return keys

# 4. Шифрование блока 

def encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    rounds = len(round_keys) - 1
    state = xor_bytes(block, round_keys[0])

    for r in range(1, rounds + 1):
        state = substitute_bytes(state, AES_SBOX)
        if r != rounds:
            perm_bits = apply_pbox(bytes_to_bits(state), PBOX)
            state = bits_to_bytes(perm_bits)
        state = xor_bytes(state, round_keys[r])

    return state

def encrypt_block_trace(block: bytes, round_keys: list[bytes]) -> list[str]:
    """То же самое, что encrypt_block, но возвращает лог состояния блока
    после каждого шага — чтобы наглядно видеть, что именно происходит
    на каждом раунде и чем последний раунд отличается от остальных."""
    rounds = len(round_keys) - 1
    state = xor_bytes(block, round_keys[0])
    log = [f"После отбеливания (XOR c K0): {state.hex().upper()}"]

    for r in range(1, rounds + 1):
        state = substitute_bytes(state, AES_SBOX)
        log.append(f"Раунд {r}: после S-box:            {state.hex().upper()}")
        if r != rounds:
            perm_bits = apply_pbox(bytes_to_bits(state), PBOX)
            state = bits_to_bytes(perm_bits)
            log.append(f"Раунд {r}: после P-box:            {state.hex().upper()}")
        else:
            log.append(f"Раунд {r}: P-box ПРОПУЩЕН (финальный раунд)")
        state = xor_bytes(state, round_keys[r])
        log.append(f"Раунд {r}: после XOR c K{r}:          {state.hex().upper()}")

    return log

def decrypt_block(cipher_block: bytes, round_keys: list[bytes]) -> bytes:
    rounds = len(round_keys) - 1
    state = cipher_block

    for r in range(rounds, 0, -1):
        state = xor_bytes(state, round_keys[r])
        if r != rounds:
            perm_bits = apply_pbox(bytes_to_bits(state), INV_PBOX)
            state = bits_to_bytes(perm_bits)
        state = substitute_bytes(state, INV_AES_SBOX)

    state = xor_bytes(state, round_keys[0])
    return state

# 5. Padding по ISO/IEC 7816-4

def iso7816_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Добавляет один байт-маркер 0x80, затем нули до конца блока.
    Если данные уже кратны block_size — всё равно добавляется целый
    лишний блок (маркер + нули), иначе конец данных будет неоднозначен."""
    pad_len = block_size - (len(data) % block_size)
    return data + b'\x80' + b'\x00' * (pad_len - 1)

def iso7816_unpad(data: bytes) -> bytes:
    """Ищем маркер 0x80 с конца, пропуская нулевые байты."""
    idx = len(data) - 1
    while idx >= 0 and data[idx] == 0x00:
        idx -= 1
    if idx < 0 or data[idx] != 0x80:
        raise ValueError("Некорректный padding — возможно, неверный ключ или число раундов")
    # маркер не должен быть дальше, чем на BLOCK_SIZE байт от конца
    if len(data) - idx > BLOCK_SIZE:
        raise ValueError("Некорректный padding — возможно, неверный ключ или число раундов")
    return data[:idx]


def encrypt_data_cbc(plaintext: bytes, key_hex: str, rounds: int) -> bytes:
    """Режим CBC: каждый блок сцепляется с предыдущим шифроблоком (нужен IV)."""
    master_key = bytes.fromhex(key_hex)
    round_keys = generate_round_keys(master_key, rounds)
    padded = iso7816_pad(plaintext, BLOCK_SIZE)

    iv = generate_random_iv_bytes()
    prev_block = iv
    out_blocks = [iv]

    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        mixed = xor_bytes(block, prev_block)
        cipher_block = encrypt_block(mixed, round_keys)
        out_blocks.append(cipher_block)
        prev_block = cipher_block

    return b''.join(out_blocks)


def decrypt_data_cbc(data: bytes, key_hex: str, rounds: int) -> bytes:
    if len(data) < BLOCK_SIZE or (len(data) - BLOCK_SIZE) % BLOCK_SIZE != 0:
        raise ValueError("Некорректная длина шифротекста")

    master_key = bytes.fromhex(key_hex)
    round_keys = generate_round_keys(master_key, rounds)

    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]

    prev_block = iv
    plain_chunks = []

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        cipher_block = ciphertext[i:i + BLOCK_SIZE]
        mixed = decrypt_block(cipher_block, round_keys)
        plain_block = xor_bytes(mixed, prev_block)
        plain_chunks.append(plain_block)
        prev_block = cipher_block

    padded_plain = b''.join(plain_chunks)
    return iso7816_unpad(padded_plain)


def encrypt_data_ecb(plaintext: bytes, key_hex: str, rounds: int) -> bytes:
    """Режим ECB: каждый блок шифруется НЕЗАВИСИМО, без сцепления и без IV.
    Одинаковые блоки открытого текста дают одинаковые блоки шифротекста —
    это и есть слабость ECB, которую CBC устраняет."""
    master_key = bytes.fromhex(key_hex)
    round_keys = generate_round_keys(master_key, rounds)
    padded = iso7816_pad(plaintext, BLOCK_SIZE)

    out_blocks = []
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        cipher_block = encrypt_block(block, round_keys)   # без XOR с чем-либо ещё
        out_blocks.append(cipher_block)

    return b''.join(out_blocks)


def decrypt_data_ecb(data: bytes, key_hex: str, rounds: int) -> bytes:
    if len(data) == 0 or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Некорректная длина шифротекста")

    master_key = bytes.fromhex(key_hex)
    round_keys = generate_round_keys(master_key, rounds)

    plain_chunks = []
    for i in range(0, len(data), BLOCK_SIZE):
        cipher_block = data[i:i + BLOCK_SIZE]
        plain_block = decrypt_block(cipher_block, round_keys)   # без XOR с чем-либо ещё
        plain_chunks.append(plain_block)

    padded_plain = b''.join(plain_chunks)
    return iso7816_unpad(padded_plain)


def encrypt_data(plaintext: bytes, key_hex: str, rounds: int, mode: str = "CBC") -> bytes:
    if mode == "ECB":
        return encrypt_data_ecb(plaintext, key_hex, rounds)
    return encrypt_data_cbc(plaintext, key_hex, rounds)


def decrypt_data(data: bytes, key_hex: str, rounds: int, mode: str = "CBC") -> bytes:
    if mode == "ECB":
        return decrypt_data_ecb(data, key_hex, rounds)
    return decrypt_data_cbc(data, key_hex, rounds)

# 6. Графический интерфейс (GUI)

def get_rounds() -> int:
    try:
        rounds = int(spin_rounds.get())
    except ValueError:
        rounds = DEFAULT_ROUNDS
    return max(1, min(rounds, 16))

def on_encrypt():
    text = text_input.get("1.0", tk.END).rstrip("\n")
    key_hex = entry_key.get().strip()
    rounds = get_rounds()
    mode = mode_var.get()

    if len(key_hex) != 16:
        messagebox.showerror("Ошибка", "Ключ должен состоять из 16 hex-символов (64 бита)!")
        return

    try:
        plain_bytes = text.encode('utf-8')
        cipher_bytes = encrypt_data(plain_bytes, key_hex, rounds, mode)
        cipher_hex = cipher_bytes.hex().upper()

        text_result.delete("1.0", tk.END)
        text_result.insert("1.0", cipher_hex)
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось зашифровать: {e}")

def on_decrypt():
    cipher_hex = text_input.get("1.0", tk.END).strip()
    key_hex = entry_key.get().strip()
    rounds = get_rounds()
    mode = mode_var.get()

    if len(key_hex) != 16:
        messagebox.showerror("Ошибка", "Ключ должен состоять из 16 hex-символов (64 бита)!")
        return

    try:
        cipher_bytes = bytes.fromhex(cipher_hex)
        plain_bytes = decrypt_data(cipher_bytes, key_hex, rounds, mode)
        plain_text = plain_bytes.decode('utf-8')

        text_result.delete("1.0", tk.END)
        text_result.insert("1.0", plain_text)
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось расшифровать: {e}")

def generate_key_action():
    new_key = generate_random_key_hex()
    entry_key.delete(0, tk.END)
    entry_key.insert(0, new_key)

def show_round_keys_action():
    key_hex = entry_key.get().strip()
    rounds = get_rounds()
    if len(key_hex) != 16:
        messagebox.showerror("Ошибка", "Ключ должен состоять из 16 hex-символов (64 бита)!")
        return
    master_key = bytes.fromhex(key_hex)
    round_keys = generate_round_keys(master_key, rounds)

    lines = [f"K0 (отбеливание): {round_keys[0].hex().upper()}"]
    for i, k in enumerate(round_keys[1:], start=1):
        lines.append(f"K{i} (раунд {i}):   {k.hex().upper()}")
    messagebox.showinfo("Раундовые ключи", "\n".join(lines))

def show_trace_action():
    """Показывает пошаговое состояние ПЕРВОГО 8-байтового блока текста
    на каждом раунде — чтобы наглядно видеть, что S-box и XOR с ключом
    идут на каждом раунде, а P-box пропускается только на последнем."""
    text = text_input.get("1.0", tk.END).rstrip("\n")
    key_hex = entry_key.get().strip()
    rounds = get_rounds()

    if len(key_hex) != 16:
        messagebox.showerror("Ошибка", "Ключ должен состоять из 16 hex-символов (64 бита)!")
        return
    if not text:
        messagebox.showerror("Ошибка", "Введите текст в верхнее поле!")
        return

    data = text.encode('utf-8')
    padded = iso7816_pad(data, BLOCK_SIZE)
    first_block = padded[:BLOCK_SIZE]  # берём только первый блок для наглядности

    master_key = bytes.fromhex(key_hex)
    round_keys = generate_round_keys(master_key, rounds)

    log = [f"Режим: {mode_var.get()}", f"Первый блок (после padding): {first_block.hex().upper()}", ""]
    log.extend(encrypt_block_trace(first_block, round_keys))

    messagebox.showinfo("Трассировка раундов (первый блок)", "\n".join(log))

def copy_result_action():
    result = text_result.get("1.0", tk.END).rstrip("\n")
    if not result:
        return
    root.clipboard_clear()
    root.clipboard_append(result)
    root.update()

def use_result_as_input_action():
    result = text_result.get("1.0", tk.END).rstrip("\n")
    text_input.delete("1.0", tk.END)
    text_input.insert("1.0", result)


def build_gui():
    global root, text_input, entry_key, spin_rounds, text_result, mode_var

    root = tk.Tk()
    root.title("SP-Сеть Шифрование (AES S-box, N раундов, ECB/CBC, ISO7816-4)")
    root.geometry("560x680")

    label_text = tk.Label(root, text="Входной текст (для шифрования) или Hex-шифротекст (для расшифровки):")
    label_text.pack(pady=(10, 2))
    text_input = scrolledtext.ScrolledText(root, width=64, height=7)
    text_input.insert("1.0", "Пример текста любой длины с несколькими раундами шифрования.")
    text_input.pack(padx=10)

    label_key = tk.Label(root, text="Ключ (HEX 16 символов / 64 бита):")
    label_key.pack(pady=(10, 2))

    frame_key = tk.Frame(root)
    frame_key.pack()

    entry_key = tk.Entry(frame_key, width=30)
    entry_key.insert(0, generate_random_key_hex())
    entry_key.pack(side=tk.LEFT, padx=(0, 5))

    btn_gen_key = tk.Button(frame_key, text="Сгенерировать", command=generate_key_action)
    btn_gen_key.pack(side=tk.LEFT, padx=(0, 15))

    tk.Label(frame_key, text="Раундов:").pack(side=tk.LEFT)
    spin_rounds = tk.Spinbox(frame_key, from_=1, to=16, width=4)
    spin_rounds.delete(0, tk.END)
    spin_rounds.insert(0, str(DEFAULT_ROUNDS))
    spin_rounds.pack(side=tk.LEFT, padx=(5, 0))

    frame_mode = tk.Frame(root)
    frame_mode.pack(pady=(8, 0))
    tk.Label(frame_mode, text="Режим:").pack(side=tk.LEFT, padx=(0, 5))
    mode_var = tk.StringVar(value="CBC")
    tk.Radiobutton(frame_mode, text="CBC (со сцеплением, безопаснее)", variable=mode_var, value="CBC").pack(side=tk.LEFT)
    tk.Radiobutton(frame_mode, text="ECB (каждый блок отдельно, слабее)", variable=mode_var, value="ECB").pack(side=tk.LEFT)

    btn_show_keys = tk.Button(root, text="Показать раундовые ключи", command=show_round_keys_action)
    btn_show_keys.pack(pady=(8, 0))

    btn_show_trace = tk.Button(root, text="Показать процесс по раундам (1-й блок)", command=show_trace_action)
    btn_show_trace.pack(pady=(4, 0))

    frame_buttons = tk.Frame(root)
    frame_buttons.pack(pady=15)

    btn_encrypt = tk.Button(frame_buttons, text="Зашифровать", width=15, bg="#4CAF50", fg="white", command=on_encrypt)
    btn_encrypt.pack(side=tk.LEFT, padx=5)

    btn_decrypt = tk.Button(frame_buttons, text="Расшифровать", width=15, bg="#2196F3", fg="white", command=on_decrypt)
    btn_decrypt.pack(side=tk.LEFT, padx=5)

    label_result = tk.Label(root, text="Результат:")
    label_result.pack(pady=(5, 2))
    text_result = scrolledtext.ScrolledText(root, width=64, height=7, font=("Consolas", 10))
    text_result.pack(padx=10)

    frame_result_buttons = tk.Frame(root)
    frame_result_buttons.pack(pady=10)

    btn_copy = tk.Button(frame_result_buttons, text="Копировать результат", command=copy_result_action)
    btn_copy.pack(side=tk.LEFT, padx=5)

    btn_use_as_input = tk.Button(frame_result_buttons, text="Перенести результат в поле ввода", command=use_result_as_input_action)
    btn_use_as_input.pack(side=tk.LEFT, padx=5)

    root.mainloop()


if __name__ == "__main__":
    build_gui()

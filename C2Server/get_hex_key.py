with open("cur_key.txt", "rb") as f:
    data = f.read()
    print(''.join(f'\\x{b:02x}' for b in data))

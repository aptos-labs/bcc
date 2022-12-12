from os import listdir
from os.path import isfile, join

class Node:
	def __init__(self, name, start, end):
		self.name = name
		self.start = start
		self.end = end
		self.rb_left = None
		self.rb_right = None

	def lookup(self, ip):
		node =self

		while (node):
			if ip < node.start:
				node = node.rb_left
			elif ip >= node.end:
				node = node.rb_right
			else:
				return node.name
		return None

def ser(node, f):
	if node == None:
		f.write("-\n")
		return;
	f.write(f"{node.name},{hex(node.start)},{hex(node.end)}\n")
	ser(node.rb_left, f)
	ser(node.rb_right, f)

def des(f):
	line  = f.readline()
	line = line.rstrip('\n')

	if line == '-':
		return None

	ln = line.split(',')
	node = Node(ln[0], int(ln[-2],16), int(ln[-1],16))
	node.rb_left = des(f)
	node.rb_right = des(f)

	return node

def deserialize_sym_file(filename):
	f = open(filename, "r")
	return des(f)

def serialize_sym_file(root, filename):
	f = open(filename, "w")
	ser(root, f)

SYMBOLS = {}

def get_sym_files():
	files = [f for f in listdir('/tmp/') if isfile(join('/tmp/', f)) and f.startswith('symbols_')]

	for f in files:
		name = join('/tmp/', f)
		key = f.split('_', 1)[1]
		SYMBOLS[key] = deserialize_sym_file(name)

def resolve(module, ip):
	if not SYMBOLS:
		get_sym_files()
	if module in SYMBOLS:
		return SYMBOLS[module].lookup(ip)
	return None

if __name__ == '__main__':
	n = deserialize_sym_file("/tmp/symbols_ld-2.31.so")
	serialize_sym_file(n, "/tmp/cmp.txt")
	print(n.lookup(0x10000))
	print(n.lookup(0x1534f))

	#get_sym_files()
	print(resolve("ld-2.31.so", 0x9176))

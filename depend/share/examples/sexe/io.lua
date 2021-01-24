
-- Some example I/O functions in SEXE

require 'io'


-- Opens a file in append mode
file = io.open("/test/sexe_io", "w")

io.output(file);

-- appends a word test to the first line of the file
io.write("-- Automatically Generated #1\n")
file:write("-- Automatically Generated #2\n")

-- closes the open file
io.close(file)


-- Opens a file in read
file = io.open("/test/sexe_io", "r")

-- sets the default input file as test.lua
io.input(file)

-- prints the first line of the file
print("[io.write] ");
println(io.read())
print("[file.read] ");
println(file:read());

-- closes the open file
io.close(file)



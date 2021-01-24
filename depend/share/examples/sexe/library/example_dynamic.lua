
-- Example dynamic SEXE library loading.
--
-- sxc -o testlib.sx testlib.lua
-- sxc -o example_dynamic.sx example_dynamic.lua
-- You can now run "sx example_dynamic.sx" providing "testlib.sx" and "example_dynamic.sx" are available. The "testlib.sx" can safely be replaced with a new version without updating the "example_dynamic.sx" binary.

require 'testlib'

test()


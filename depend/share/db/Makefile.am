

SHDB=$(top_builddir)/src/share-util/static/shdb
SHRM=$(top_builddir)/src/share-util/static/shrm
SHZ=$(top_builddir)/src/share-util/static/shz

GEO_ARCHIVE=$(top_srcdir)/db/libshare/geo.shz
#JSON_ZIPCODE=$(top_srcdir)/db/libshare/geo/zipcode.json
#JSON_COMMON=$(top_srcdir)/db/libshare/geo/common.json
#JSON_CITY=$(top_srcdir)/db/libshare/geo/city.json
#JSON_NETWORK=$(top_srcdir)/db/libshare/geo/network.json
JSON_ZIPCODE=$(builddir)/zipcode.json
JSON_COMMON=$(builddir)/common.json
JSON_CITY=$(builddir)/city.json
JSON_NETWORK=$(builddir)/network.json

install-exec-hook: $(GEO_ARCHIVE)
	@echo "Installing geodetic databases.."
	$(SHZ) -x $(GEO_ARCHIVE)
	$(SHRM) "/sys/db/libshare/geo"
	$(SHDB) geo --import $(JSON_ZIPCODE)
	$(SHDB) geo --import $(JSON_CITY)
	$(SHDB) geo --import $(JSON_COMMON)
	$(SHDB) geo --import $(JSON_NETWORK)


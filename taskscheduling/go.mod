module Findyou.TaskScheduling

go 1.22.2

require (
	github.com/pkg/errors v0.9.1
	github.com/projectdiscovery/gologger v1.1.23
	github.com/redis/go-redis/v9 v9.5.1
	golang.org/x/net v0.25.0
	gopkg.in/yaml.v3 v3.0.1
	gorm.io/driver/mysql v1.5.6
	gorm.io/gorm v1.25.10
)

require (
	github.com/360EntSecGroup-Skylar/excelize v1.4.1 // indirect
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dsnet/compress v0.0.2-0.20210315054119-f66993602bf5 // indirect
	github.com/go-sql-driver/mysql v1.7.0 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/logrusorgru/aurora v2.0.3+incompatible // indirect
	github.com/mholt/archiver/v3 v3.5.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/nwaples/rardecode v1.1.3 // indirect
	github.com/pierrec/lz4/v4 v4.1.2 // indirect
	github.com/projectdiscovery/utils v0.2.8 // indirect
	github.com/richardlehane/mscfb v1.0.4 // indirect
	github.com/richardlehane/msoleps v1.0.3 // indirect
	github.com/ulikunitz/xz v0.5.11 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	github.com/xuri/efp v0.0.0-20231025114914-d1ff6096ae53 // indirect
	github.com/xuri/nfp v0.0.0-20230919160717-d98342af3f05 // indirect
	golang.org/x/crypto v0.23.0 // indirect
	golang.org/x/text v0.15.0 // indirect
	gopkg.in/djherbis/times.v1 v1.3.0 // indirect
)

replace (
	github.com/360EntSecGroup-Skylar/excelize v1.4.1 => ./lib/excelize-2.8.1
	github.com/projectdiscovery/gologger v1.1.12 => ./lib/gologger
)
